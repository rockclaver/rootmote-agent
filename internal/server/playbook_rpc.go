package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/inventory"
	"github.com/rockclaver/rootmote-agent/internal/playbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// generateTimeout bounds one incident.playbook.generate call. The playbook
// service may wait on a slow model.
const generateTimeout = 4 * time.Minute

// newPlaybookService builds the playbook service from the configured parts,
// or returns nil when there is no remediation manager or store to propose
// into.
func (s *Server) newPlaybookService() *playbook.Service {
	if s.cfg.Remediation == nil || s.cfg.Store == nil {
		return nil
	}
	redactor := s.cfg.DiagnoseRedactor
	if redactor == nil {
		redactor, _ = redact.New(nil)
	}
	gen := &playbook.Generator{Redactor: redactor}
	if h, err := os.Hostname(); err == nil {
		gen.Hostnames = []string{h}
	}
	if s.cfg.Watchtower != nil {
		gen.Client = s.cfg.Watchtower
	}
	if s.cfg.Steps != nil {
		gen.Validator = s.cfg.Steps
	}
	svc := &playbook.Service{
		Store:       s.cfg.Store,
		Remediation: s.cfg.Remediation,
		Generator:   gen,
		Collect: func(ctx context.Context, t diagnose.Target) diagnose.Bundle {
			b := s.buildDiagnosePipeline().Collect(ctx, t)
			s.setDiagnoseBundle(t.IncidentID, b)
			return b
		},
		Inventory:  s.playbookInventory,
		DiskMounts: s.diskStepMounts,
		ServerID: func() string {
			if s.cfg.Watchtower == nil {
				return ""
			}
			if creds := s.cfg.Watchtower.Creds(); creds != nil {
				return creds.ServerID
			}
			return ""
		},
		MonitoringOn: func() bool { return s.cfg.Watchtower != nil && s.cfg.Watchtower.Creds() != nil },
		Logf:         log.Printf,
	}
	return svc
}

// StartPlaybooks sets the context that bounds background playbook work. Call
// it with the agent's lifetime context before the monitor engine starts.
func (s *Server) StartPlaybooks(ctx context.Context) {
	if s.playbooks != nil {
		s.playbooks.Ctx = ctx
	}
}

// IncidentOpened tells the agent which relay incident a firing monitor event
// opened. It is the watchtower.Client.IncidentOpened callback.
func (s *Server) IncidentOpened(ev watchtower.MonitorEvent, incidentID string) {
	if s.playbooks != nil {
		s.playbooks.IncidentOpened(ev, incidentID)
	}
}

// playbookInventory lists the names on this server that a playbook step may
// target, and its operating system.
func (s *Server) playbookInventory(ctx context.Context) (playbook.Inventory, playbook.OSInfo) {
	report := s.cachedInventory(ctx)
	var inv playbook.Inventory
	for _, u := range report.SystemdUnits {
		if steps.CheckUnitAllowed(u.Name) == nil {
			inv.Units = append(inv.Units, u.Name)
		}
	}
	for _, c := range report.Docker.Containers {
		inv.Containers = append(inv.Containers, c.Name)
		if c.ComposeProject != "" && c.ComposeService != "" {
			inv.ComposeServices = append(inv.ComposeServices, playbook.ComposePair{Project: c.ComposeProject, Service: c.ComposeService})
		}
	}
	for _, a := range report.PM2Apps {
		inv.PM2Apps = append(inv.PM2Apps, playbook.PM2App{User: a.User, App: a.App})
	}
	for _, p := range report.SupervisorPrograms {
		inv.SupervisorPrograms = append(inv.SupervisorPrograms, p.Name)
	}
	for _, c := range report.Certs {
		inv.Certs = append(inv.Certs, c.Name)
	}
	ports := map[int]bool{}
	for _, p := range report.ListeningPorts {
		if !ports[p.Port] {
			ports[p.Port] = true
			inv.Ports = append(inv.Ports, p.Port)
		}
	}
	sort.Ints(inv.Ports)
	inv.URLs = s.candidateURLs(report.PublicDomains, report.ReverseProxies)

	osInfo := playbook.OSInfo{Version: report.OS.Version}
	if name := strings.Fields(strings.ToLower(report.OS.Name)); len(name) > 0 {
		osInfo.Distro = name[0]
	}
	return inv, osInfo
}

// candidateURLs lists web addresses on this host that check.http may request:
// the domains its web servers serve, plus the addresses of the user's web
// monitors. Only addresses the allowlist accepts are returned.
func (s *Server) candidateURLs(domains []string, proxies []inventory.ReverseProxyInfo) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		if s.cfg.URLs != nil && !s.cfg.URLs.Allowed(u) {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	hosts := append([]string{}, domains...)
	for _, p := range proxies {
		hosts = append(hosts, p.Domains...)
	}
	for _, h := range hosts {
		if h == "" || strings.ContainsAny(h, "*/ ") {
			continue
		}
		add("https://" + h + "/")
		add("http://" + h + "/")
	}
	if s.cfg.URLs != nil {
		for _, t := range s.cfg.URLs.MonitorURLs() {
			add(t)
		}
	}
	sort.Strings(out)
	return out
}

// handlePlaybookGenerate serves incident.playbook.generate: build a playbook
// for the incident (a catalog one if it fits, else ask the playbook service)
// and return the id of the execution that holds it. It replies with the
// error codes consent_required, limit_reached, no_playbook (with findings)
// or unavailable, each with a plain-English message.
func (s *Server) handlePlaybookGenerate(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		IncidentID  string `json:"incidentId"`
		MonitorKind string `json:"monitorKind"`
		Target      string `json:"target"`
		Severity    string `json:"severity"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.IncidentID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "incidentId required")
		return
	}
	if s.playbooks == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", playbook.MsgTurnOnMonitoring)
		return
	}
	// Generation can take minutes; never hold up the connection's read loop.
	go func() {
		gctx, cancel := context.WithTimeout(ctx, generateTimeout)
		defer cancel()
		execID, err := s.playbooks.Generate(gctx, playbook.Request{
			IncidentID: in.IncidentID, MonitorKind: in.MonitorKind, Target: in.Target, Severity: in.Severity,
		})
		if err != nil {
			s.writePlaybookErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "incident.playbook.generate", map[string]any{"executionId": execID})
	}()
}

// writePlaybookErr maps a playbook error to its RPC error code.
func (s *Server) writePlaybookErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	var pe *playbook.Error
	if !errors.As(err, &pe) {
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
		return
	}
	body := map[string]any{"error": pe.Message}
	if pe.Status == playbook.StatusNoPlaybook {
		findings := pe.Findings
		if findings == nil {
			findings = []playbook.Finding{}
		}
		body["findings"] = findings
	}
	s.writeErrorBody(writeMu, id, pe.Status, body)
}

// writeErrorBody sends an error frame whose payload has more than a message.
func (s *Server) writeErrorBody(writeMu *connWriter, id, kind string, body map[string]any) {
	raw, _ := json.Marshal(body)
	out, _ := json.Marshal(Frame{ID: id, Kind: "error." + kind, Payload: raw})
	writeMu.enqueue(out)
}

// diskStepMounts finds, for each disk step, the mount that holds the folder
// the step frees space in. A step whose folder or mount cannot be found is
// left out.
func (s *Server) diskStepMounts(ctx context.Context) map[steps.ID]string {
	out := map[steps.ID]string{}
	if s.cfg.Steps == nil {
		return out
	}
	for _, id := range []steps.ID{steps.JournalVacuumID, steps.DockerPruneID, steps.AptCleanID} {
		dir, err := steps.DiskStepPath(ctx, s.cfg.Steps.Env, id)
		if err != nil {
			continue
		}
		if mount, err := steps.MountPointOf(dir); err == nil {
			out[id] = mount
		}
	}
	return out
}
