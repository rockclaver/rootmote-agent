package inventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/cliauth"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

func TestSnapshotCapabilitiesReportsExistingAgentModules(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := New(Config{
		Docker:         fakeDockerStatus{st: docker.Status{Available: true, Version: "26.0.0", APIVersion: "1.45"}},
		Systemd:        fakeSystemdStatus{st: systemd.Status{Available: true}},
		Processes:      fakeProcessLister{procs: []process.Process{{PID: 10}}},
		Previews:       fakePreviewConfig{base: "previews.example.com"},
		PushDevices:    fakePushDeviceLister{devices: []store.PushDevice{{Token: "tok"}}},
		PushConfigured: func() bool { return true },
		Auth: fakeAuthStatus{statuses: map[string]cliauth.Status{
			cliauth.KindClaude: {Kind: cliauth.KindClaude, LoggedIn: true, Method: cliauth.MethodSubscription, Account: "dev@example.com", Version: "1.2.3"},
			cliauth.KindCodex:  {Kind: cliauth.KindCodex, LoggedIn: true, Method: cliauth.MethodAPIKey, Version: "0.4.0"},
		}},
		Now: func() time.Time { return now },
	})

	snap := m.SnapshotCapabilities(context.Background())
	if !snap.CapturedAt.Equal(now) {
		t.Fatalf("captured_at = %v", snap.CapturedAt)
	}
	if !snap.Docker.Available || snap.Docker.Version != "26.0.0" || snap.Docker.APIVersion != "1.45" {
		t.Fatalf("docker capability mismatch: %+v", snap.Docker)
	}
	if !snap.Systemd.Available {
		t.Fatalf("systemd unavailable: %+v", snap.Systemd)
	}
	if !snap.ProcessInspection.Available || snap.ProcessInspection.Count != 1 {
		t.Fatalf("process capability mismatch: %+v", snap.ProcessInspection)
	}
	if !snap.Previews.Available || !snap.Previews.Configured {
		t.Fatalf("preview capability mismatch: %+v", snap.Previews)
	}
	if !snap.Push.Available || snap.Push.Count != 1 {
		t.Fatalf("push capability mismatch: %+v", snap.Push)
	}
	if !snap.AIClis[cliauth.KindClaude].Available || snap.AIClis[cliauth.KindClaude].Account != "dev@example.com" {
		t.Fatalf("claude capability mismatch: %+v", snap.AIClis[cliauth.KindClaude])
	}
	if !snap.AIClis[cliauth.KindCodex].Available || snap.AIClis[cliauth.KindCodex].Method != cliauth.MethodAPIKey {
		t.Fatalf("codex capability mismatch: %+v", snap.AIClis[cliauth.KindCodex])
	}
}

func TestSnapshotCapabilitiesReportsUnavailableReasons(t *testing.T) {
	m := New(Config{
		Docker:         fakeDockerStatus{st: docker.Status{Available: false, UnavailableReason: docker.ReasonDaemonDown, UnavailableMessage: "daemon down"}},
		Systemd:        fakeSystemdStatus{st: systemd.Status{Available: false, UnavailableReason: systemd.ReasonNotSystemd, UnavailableMessage: "not systemd"}},
		Processes:      fakeProcessLister{err: errors.New("procfs missing")},
		Previews:       fakePreviewConfig{},
		PushConfigured: func() bool { return false },
		Auth: fakeAuthStatus{statuses: map[string]cliauth.Status{
			cliauth.KindClaude: {Kind: cliauth.KindClaude, LoggedIn: false, Method: cliauth.MethodNone},
		}},
	})

	snap := m.SnapshotCapabilities(context.Background())
	if snap.Docker.UnavailableReason != docker.ReasonDaemonDown {
		t.Fatalf("docker reason = %q", snap.Docker.UnavailableReason)
	}
	if snap.Systemd.UnavailableReason != systemd.ReasonNotSystemd {
		t.Fatalf("systemd reason = %q", snap.Systemd.UnavailableReason)
	}
	if snap.ProcessInspection.UnavailableReason != ReasonUnknown || snap.ProcessInspection.UnavailableMessage != "procfs missing" {
		t.Fatalf("process reason mismatch: %+v", snap.ProcessInspection)
	}
	if snap.Previews.UnavailableReason != ReasonBaseDomainUnset || snap.Previews.Configured {
		t.Fatalf("preview reason mismatch: %+v", snap.Previews)
	}
	if snap.Push.UnavailableReason != ReasonNotConfigured {
		t.Fatalf("push reason = %q", snap.Push.UnavailableReason)
	}
	if snap.AIClis[cliauth.KindClaude].UnavailableReason != ReasonNotAuthenticated {
		t.Fatalf("claude reason mismatch: %+v", snap.AIClis[cliauth.KindClaude])
	}
	if snap.AIClis[cliauth.KindCodex].UnavailableReason != ReasonUnknown {
		t.Fatalf("codex reason mismatch: %+v", snap.AIClis[cliauth.KindCodex])
	}
}

type fakeDockerStatus struct{ st docker.Status }

func (f fakeDockerStatus) Status(context.Context) docker.Status { return f.st }

type fakeSystemdStatus struct{ st systemd.Status }

func (f fakeSystemdStatus) Status(context.Context) systemd.Status { return f.st }

type fakeProcessLister struct {
	procs []process.Process
	err   error
}

func (f fakeProcessLister) List(context.Context, string, int) ([]process.Process, error) {
	return f.procs, f.err
}

type fakePreviewConfig struct {
	base string
	err  error
}

func (f fakePreviewConfig) BaseDomain() (string, error) { return f.base, f.err }

type fakePushDeviceLister struct {
	devices []store.PushDevice
	err     error
}

func (f fakePushDeviceLister) ListPushDevices() ([]store.PushDevice, error) {
	return f.devices, f.err
}

type fakeAuthStatus struct {
	statuses map[string]cliauth.Status
	err      error
}

func (f fakeAuthStatus) Status(_ context.Context, kind string) (cliauth.Status, error) {
	if f.err != nil {
		return cliauth.Status{Kind: kind}, f.err
	}
	if st, ok := f.statuses[kind]; ok {
		return st, nil
	}
	return cliauth.Status{Kind: kind}, errors.New("missing status")
}
