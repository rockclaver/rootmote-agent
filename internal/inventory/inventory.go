// Package inventory owns the Fleet Inventory capability snapshot used by the
// AI Action Plane target resolver. It reports what this agent can observe or
// operate through existing typed modules; it does not execute remediation.
package inventory

import (
	"context"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/cliauth"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

const (
	ReasonNotConfigured    = "not_configured"
	ReasonNotAuthenticated = "not_authenticated"
	ReasonBaseDomainUnset  = "base_domain_unset"
	ReasonUnknown          = "unknown"
)

// Capability is the common wire shape for one inventory capability.
type Capability struct {
	Available          bool   `json:"available"`
	Configured         bool   `json:"configured"`
	Version            string `json:"version,omitempty"`
	APIVersion         string `json:"api_version,omitempty"`
	Method             string `json:"method,omitempty"`
	Account            string `json:"account,omitempty"`
	Count              int    `json:"count,omitempty"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
	UnavailableMessage string `json:"unavailable_message,omitempty"`
}

// Snapshot is a point-in-time view of the typed capabilities available on this
// server. Later resolver work can combine this with aliases/resources.
type Snapshot struct {
	CapturedAt        time.Time             `json:"captured_at"`
	Docker            Capability            `json:"docker"`
	Systemd           Capability            `json:"systemd"`
	ProcessInspection Capability            `json:"process_inspection"`
	Previews          Capability            `json:"previews"`
	Push              Capability            `json:"push"`
	AIClis            map[string]Capability `json:"ai_clis"`
}

type dockerStatus interface {
	Status(context.Context) docker.Status
}

type systemdStatus interface {
	Status(context.Context) systemd.Status
}

type processLister interface {
	List(context.Context, string, int) ([]process.Process, error)
}

type previewConfig interface {
	BaseDomain() (string, error)
}

type pushDeviceLister interface {
	ListPushDevices() ([]store.PushDevice, error)
}

type authStatus interface {
	Status(context.Context, string) (cliauth.Status, error)
}

// Config wires the snapshot probes. Nil probes are reported as not configured.
type Config struct {
	Docker         dockerStatus
	Systemd        systemdStatus
	Processes      processLister
	Previews       previewConfig
	PushDevices    pushDeviceLister
	PushConfigured func() bool
	Auth           authStatus
	Now            func() time.Time
}

// Manager builds fleet inventory snapshots from existing agent modules.
type Manager struct {
	cfg Config
}

// New constructs a Manager.
func New(cfg Config) *Manager {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{cfg: cfg}
}

// SnapshotCapabilities returns the current capability inventory.
func (m *Manager) SnapshotCapabilities(ctx context.Context) Snapshot {
	return Snapshot{
		CapturedAt:        m.cfg.Now(),
		Docker:            m.docker(ctx),
		Systemd:           m.systemd(ctx),
		ProcessInspection: m.processes(ctx),
		Previews:          m.previews(),
		Push:              m.push(),
		AIClis: map[string]Capability{
			cliauth.KindClaude: m.aiCLI(ctx, cliauth.KindClaude),
			cliauth.KindCodex:  m.aiCLI(ctx, cliauth.KindCodex),
		},
	}
}

func (m *Manager) docker(ctx context.Context) Capability {
	if m.cfg.Docker == nil {
		return unavailable(ReasonNotConfigured, "docker subsystem not configured")
	}
	st := m.cfg.Docker.Status(ctx)
	return Capability{
		Available:          st.Available,
		Configured:         true,
		Version:            st.Version,
		APIVersion:         st.APIVersion,
		UnavailableReason:  st.UnavailableReason,
		UnavailableMessage: st.UnavailableMessage,
	}
}

func (m *Manager) systemd(ctx context.Context) Capability {
	if m.cfg.Systemd == nil {
		return unavailable(ReasonNotConfigured, "systemd subsystem not configured")
	}
	st := m.cfg.Systemd.Status(ctx)
	return Capability{
		Available:          st.Available,
		Configured:         true,
		UnavailableReason:  st.UnavailableReason,
		UnavailableMessage: st.UnavailableMessage,
	}
}

func (m *Manager) processes(ctx context.Context) Capability {
	if m.cfg.Processes == nil {
		return unavailable(ReasonNotConfigured, "process inspection not configured")
	}
	procs, err := m.cfg.Processes.List(ctx, process.SortCPU, 1)
	if err != nil {
		return Capability{
			Available:          false,
			Configured:         true,
			UnavailableReason:  ReasonUnknown,
			UnavailableMessage: err.Error(),
		}
	}
	return Capability{Available: true, Configured: true, Count: len(procs)}
}

func (m *Manager) previews() Capability {
	if m.cfg.Previews == nil {
		return unavailable(ReasonNotConfigured, "preview subsystem not configured")
	}
	base, err := m.cfg.Previews.BaseDomain()
	if err != nil {
		return Capability{
			Available:          false,
			Configured:         true,
			UnavailableReason:  ReasonUnknown,
			UnavailableMessage: err.Error(),
		}
	}
	if base == "" {
		return Capability{
			Available:          false,
			Configured:         false,
			UnavailableReason:  ReasonBaseDomainUnset,
			UnavailableMessage: "preview base domain not configured",
		}
	}
	return Capability{Available: true, Configured: true}
}

func (m *Manager) push() Capability {
	if m.cfg.PushConfigured == nil || !m.cfg.PushConfigured() || m.cfg.PushDevices == nil {
		return unavailable(ReasonNotConfigured, "push delivery not configured")
	}
	devices, err := m.cfg.PushDevices.ListPushDevices()
	if err != nil {
		return Capability{
			Available:          false,
			Configured:         true,
			UnavailableReason:  ReasonUnknown,
			UnavailableMessage: err.Error(),
		}
	}
	return Capability{Available: true, Configured: true, Count: len(devices)}
}

func (m *Manager) aiCLI(ctx context.Context, kind string) Capability {
	if m.cfg.Auth == nil {
		return unavailable(ReasonNotConfigured, kind+" auth subsystem not configured")
	}
	st, err := m.cfg.Auth.Status(ctx, kind)
	if err != nil {
		return Capability{
			Available:          false,
			Configured:         true,
			UnavailableReason:  ReasonUnknown,
			UnavailableMessage: err.Error(),
		}
	}
	c := Capability{
		Available:  st.LoggedIn,
		Configured: true,
		Version:    st.Version,
		Method:     st.Method,
		Account:    st.Account,
	}
	if !st.LoggedIn {
		c.UnavailableReason = ReasonNotAuthenticated
		c.UnavailableMessage = kind + " CLI is not authenticated"
	}
	return c
}

func unavailable(reason, message string) Capability {
	return Capability{
		Available:          false,
		Configured:         false,
		UnavailableReason:  reason,
		UnavailableMessage: message,
	}
}
