package playbook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// autoTimeout bounds the work done for one incident when it opens.
const autoTimeout = 4 * time.Minute

// maxPreparing is how many incidents are prepared at the same moment.
const maxPreparing = 2

// IncidentStore is the part of the agent store the service uses.
type IncidentStore interface {
	PutIncidentBinding(store.IncidentBinding) (bool, error)
	GetIncidentBinding(incidentID string) (store.IncidentBinding, error)
	ExecutionsForIncident(incidentID string) ([]store.RemediationExecution, error)
}

// Proposer is remediation.Manager.Propose: the one place a playbook becomes
// something the user can approve.
type Proposer interface {
	Propose(ctx context.Context, executionID, incidentID string, rb runbook.Runbook) (store.RemediationExecution, error)
}

// Service builds a playbook for an incident and proposes it for approval.
//
// How it learns about incidents: the relay answers each firing event with the
// id of the incident it opened. The client hands that pair to IncidentOpened,
// which remembers the monitor behind the incident (so an app that only knows
// the incident id can still ask for a playbook), proposes the catalog
// playbook if one fits, and for a critical incident that has none asks the
// playbook service once. Incidents the relay opens itself (web checks,
// missed heartbeats) never pass through here; for those the app sends the
// monitor kind and target with its request.
type Service struct {
	Store       IncidentStore
	Remediation Proposer
	Generator   *Generator
	// Collect gathers the redacted evidence for an incident.
	Collect func(ctx context.Context, t diagnose.Target) diagnose.Bundle
	// Inventory lists the names on this server and its OS.
	Inventory func(ctx context.Context) (Inventory, OSInfo)
	// DiskMounts maps each disk step to the mount that holds the folder it
	// frees space in. Optional; without it no disk step is offered.
	DiskMounts func(ctx context.Context) map[steps.ID]string
	// ServerID is the relay's id for this server, or empty before enrollment.
	ServerID func() string
	// MonitoringOn reports whether this agent is enrolled with the relay.
	MonitoringOn func() bool
	// Ctx bounds background work; cancelled on shutdown.
	Ctx  context.Context
	Logf func(format string, args ...any)

	mu        sync.Mutex
	preparing map[string]bool
	slots     chan struct{}
	slotsOnce sync.Once
}

// Request identifies the incident a playbook is wanted for. Only IncidentID is
// required; the rest fills in what the agent has no record of.
type Request struct {
	IncidentID  string
	MonitorKind string
	Target      string
	Severity    string
}

func (s *Service) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Service) slot() chan struct{} {
	s.slotsOnce.Do(func() { s.slots = make(chan struct{}, maxPreparing) })
	return s.slots
}

// IncidentOpened is called when the relay reports the incident a firing
// monitor event opened or joined. It returns at once; the work runs in the
// background.
func (s *Service) IncidentOpened(ev watchtower.MonitorEvent, incidentID string) {
	b := store.IncidentBinding{
		IncidentID: incidentID, MonitorKind: ev.MonitorKind, Target: ev.Target,
		Severity: ev.Severity, Summary: ev.Summary, EventID: ev.EventID,
	}
	created, err := s.Store.PutIncidentBinding(b)
	if err != nil {
		s.logf("playbook: remember incident %s: %v", incidentID, err)
		return
	}
	if !created {
		return
	}
	go func() {
		ctx := s.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithTimeout(ctx, autoTimeout)
		defer cancel()
		select {
		case s.slot() <- struct{}{}:
			defer func() { <-s.slot() }()
		case <-ctx.Done():
			return
		}
		if _, err := s.prepare(ctx, b, false); err != nil {
			var pe *Error
			if errors.As(err, &pe) {
				s.logf("playbook: no automatic playbook for incident %s: %s (%s)", incidentID, pe.Status, pe.Message)
				return
			}
			s.logf("playbook: prepare incident %s: %v", incidentID, err)
		}
	}()
}

// Generate prepares a playbook because the user asked for one and returns the
// id of the execution that holds it. A playbook that is already waiting for
// approval or running is returned as it is: asking twice never costs a second
// request to the playbook service.
func (s *Service) Generate(ctx context.Context, req Request) (string, error) {
	if s.MonitoringOn != nil && !s.MonitoringOn() {
		return "", &Error{Status: StatusUnavailable, Message: MsgTurnOnMonitoring}
	}
	b, err := s.Store.GetIncidentBinding(req.IncidentID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
		if req.MonitorKind == "" {
			return "", &Error{Status: StatusUnavailable, Message: "This server has no details about that incident yet. Open it again in a minute."}
		}
		b = store.IncidentBinding{IncidentID: req.IncidentID, MonitorKind: req.MonitorKind, Target: req.Target, Severity: req.Severity}
	}
	return s.prepare(ctx, b, true)
}

// prepare proposes a playbook for the incident and returns its execution id.
func (s *Service) prepare(ctx context.Context, b store.IncidentBinding, userRequested bool) (string, error) {
	if !s.begin(b.IncidentID) {
		return "", &Error{Status: StatusUnavailable, Message: "A playbook is already being prepared for this incident."}
	}
	defer s.end(b.IncidentID)

	if id, ok, err := s.activeExecution(b.IncidentID); err != nil {
		return "", err
	} else if ok {
		return id, nil
	}

	bundle := s.Collect(ctx, diagnose.Target{IncidentID: b.IncidentID, MonitorKind: b.MonitorKind, Target: b.Target, Summary: b.Summary})
	inv, osInfo := s.Inventory(ctx)
	facts := Facts{Inventory: inv, Bundle: bundle, OS: osInfo, Target: b.Target}
	facts.Signatures = diagnose.Match(bundle)
	if s.DiskMounts != nil {
		facts.DiskMounts = s.DiskMounts(ctx)
	}

	if pb, ok := FromBundle(facts); ok {
		if err := Check(ctx, &pb, inv, s.Generator.Validator); err == nil {
			return s.propose(ctx, b.IncidentID, pb)
		} else {
			s.logf("playbook: catalog playbook for incident %s failed its check: %v", b.IncidentID, err)
		}
	}
	if !userRequested && b.Severity != "critical" {
		return "", &Error{Status: StatusNoPlaybook, Message: "No catalog playbook fits and the incident is not critical."}
	}
	pb, err := s.Generator.Generate(ctx, Incident{
		ID: b.IncidentID, Kind: b.MonitorKind, Target: b.Target, Severity: orSeverity(b.Severity), UserRequested: userRequested,
	}, facts)
	if err != nil {
		return "", err
	}
	return s.propose(ctx, b.IncidentID, pb)
}

func orSeverity(s string) string {
	switch s {
	case "critical", "warning", "info":
		return s
	}
	return "warning"
}

// activeExecution finds a primary execution of the incident that the user has
// not declined.
func (s *Service) activeExecution(incidentID string) (string, bool, error) {
	list, err := s.Store.ExecutionsForIncident(incidentID)
	if err != nil {
		return "", false, err
	}
	for _, e := range list {
		if e.Status != store.RemediationDeclined {
			return e.ID, true, nil
		}
	}
	return "", false, nil
}

func (s *Service) propose(ctx context.Context, incidentID string, pb Playbook) (string, error) {
	execID, err := newID("exe")
	if err != nil {
		return "", err
	}
	rbID, err := newID("rb")
	if err != nil {
		return "", err
	}
	serverID := ""
	if s.ServerID != nil {
		serverID = s.ServerID()
	}
	if _, err := s.Remediation.Propose(ctx, execID, incidentID, ToRunbook(pb, rbID, incidentID, serverID)); err != nil {
		return "", fmt.Errorf("propose playbook: %w", err)
	}
	return execID, nil
}

func (s *Service) begin(incidentID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preparing == nil {
		s.preparing = map[string]bool{}
	}
	if s.preparing[incidentID] {
		return false
	}
	s.preparing[incidentID] = true
	return true
}

func (s *Service) end(incidentID string) {
	s.mu.Lock()
	delete(s.preparing, incidentID)
	s.mu.Unlock()
}

func newID(prefix string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
