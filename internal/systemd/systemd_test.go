package systemd

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// fakeClient records calls and returns canned data. The Manager is tested
// purely through this fake — no real systemd is exercised.
type fakeClient struct {
	available error
	units     []Unit
	details   map[string]UnitDetail
	listErr   error
	getErr    error
	actionErr error

	actions []actionCall
}

type actionCall struct {
	name   string
	action Action
}

func (f *fakeClient) Available(_ context.Context) error { return f.available }
func (f *fakeClient) List(_ context.Context) ([]Unit, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]Unit(nil), f.units...), nil
}
func (f *fakeClient) Get(_ context.Context, name string) (UnitDetail, error) {
	if f.getErr != nil {
		return UnitDetail{}, f.getErr
	}
	d, ok := f.details[name]
	if !ok {
		return UnitDetail{}, errors.New("not found")
	}
	return d, nil
}
func (f *fakeClient) Action(_ context.Context, name string, action Action) error {
	f.actions = append(f.actions, actionCall{name: name, action: action})
	return f.actionErr
}

func newManager(t *testing.T, client Client) *Manager {
	t.Helper()
	m, err := New(Config{Client: client})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// AC: list/get/action degrade to a typed unavailable reason on non-systemd
// hosts.
func TestStatus_NotSystemd(t *testing.T) {
	m := newManager(t, &fakeClient{available: ErrNotSystemd})
	st := m.Status(context.Background())
	if st.Available || st.UnavailableReason != ReasonNotSystemd {
		t.Fatalf("unexpected status %+v", st)
	}
}

func TestStatus_PermissionDenied(t *testing.T) {
	m := newManager(t, &fakeClient{available: errors.New("dbus: permission denied")})
	st := m.Status(context.Background())
	if st.Available || st.UnavailableReason != ReasonPermissionDenied {
		t.Fatalf("unexpected status %+v", st)
	}
}

// AC: List returns units with state + enabled-on-boot.
func TestList_MapsStateAndProtectedFlag(t *testing.T) {
	fc := &fakeClient{units: []Unit{
		{Name: "nginx.service", LoadState: "loaded", ActiveState: "active", SubState: "running", EnabledOnBoot: "enabled", Description: "nginx"},
		{Name: "sshd.service", LoadState: "loaded", ActiveState: "active", SubState: "running", EnabledOnBoot: "enabled", Description: "OpenSSH"},
	}}
	m := newManager(t, fc)
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 units, got %d", len(got))
	}
	if got[0].Protected {
		t.Fatalf("nginx should not be protected")
	}
	if !got[1].Protected || got[1].ProtectReason == "" {
		t.Fatalf("sshd should be protected with reason: %+v", got[1])
	}
	if got[0].ActiveState != "active" || got[0].EnabledOnBoot != "enabled" {
		t.Fatalf("state not preserved: %+v", got[0])
	}
}

// AC: Get returns single-unit detail.
func TestGet_ReturnsDecoratedDetail(t *testing.T) {
	fc := &fakeClient{details: map[string]UnitDetail{
		"sshd.service": {
			Unit: Unit{Name: "sshd.service", Description: "OpenSSH", ActiveState: "active", SubState: "running", LoadState: "loaded", EnabledOnBoot: "enabled"},
		},
	}}
	m := newManager(t, fc)
	d, err := m.Get(context.Background(), "sshd.service")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !d.Protected || d.ProtectReason == "" {
		t.Fatalf("expected protected: %+v", d)
	}
	if d.ActiveState != "active" {
		t.Fatalf("active state lost: %+v", d)
	}
}

// AC: every lifecycle verb reaches the client.
func TestAction_EachVerbReachesClient(t *testing.T) {
	fc := &fakeClient{}
	m := newManager(t, fc)
	for _, a := range []Action{ActionStart, ActionStop, ActionRestart, ActionEnable, ActionDisable} {
		fc.actions = nil
		if err := m.Action(context.Background(), "nginx.service", a); err != nil {
			t.Fatalf("Action(%s): %v", a, err)
		}
		want := []actionCall{{name: "nginx.service", action: a}}
		if !reflect.DeepEqual(fc.actions, want) {
			t.Fatalf("Action(%s) recorded %v, want %v", a, fc.actions, want)
		}
	}
}

func TestAction_RejectsUnknownVerb(t *testing.T) {
	fc := &fakeClient{}
	m := newManager(t, fc)
	if err := m.Action(context.Background(), "nginx.service", Action("delete")); !errors.Is(err, ErrUnsupportedAction) {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.actions) != 0 {
		t.Fatalf("client called on unsupported verb: %v", fc.actions)
	}
}

// AC: protected-unit guard rejects stop/disable BEFORE any client call.
func TestAction_ProtectedGuardRejectsStopDisableBeforeClient(t *testing.T) {
	cases := []struct {
		name string
		unit string
	}{
		{"sshd", "sshd.service"},
		{"ssh", "ssh.service"},
		{"agent", "claver-agent.service"},
		{"caddy", "caddy.service"},
		{"init", "init.scope"},
	}
	for _, c := range cases {
		t.Run(c.name+"_stop", func(t *testing.T) {
			fc := &fakeClient{}
			m := newManager(t, fc)
			err := m.Action(context.Background(), c.unit, ActionStop)
			var pe *ProtectedUnitError
			if !errors.As(err, &pe) || !errors.Is(err, ErrProtectedUnit) {
				t.Fatalf("expected ProtectedUnitError, got %v", err)
			}
			if pe.Unit != c.unit || pe.Action != ActionStop {
				t.Fatalf("wrong error fields: %+v", pe)
			}
			if len(fc.actions) != 0 {
				t.Fatalf("client called despite guard: %v", fc.actions)
			}
		})
		t.Run(c.name+"_disable", func(t *testing.T) {
			fc := &fakeClient{}
			m := newManager(t, fc)
			err := m.Action(context.Background(), c.unit, ActionDisable)
			if !errors.Is(err, ErrProtectedUnit) {
				t.Fatalf("expected ErrProtectedUnit, got %v", err)
			}
			if len(fc.actions) != 0 {
				t.Fatalf("client called despite guard")
			}
		})
	}
}

// Protected units allow non-destructive verbs (start/restart/enable).
func TestAction_ProtectedAllowsStartRestartEnable(t *testing.T) {
	fc := &fakeClient{}
	m := newManager(t, fc)
	for _, a := range []Action{ActionStart, ActionRestart, ActionEnable} {
		if err := m.Action(context.Background(), "sshd.service", a); err != nil {
			t.Fatalf("Action(%s) on sshd: %v", a, err)
		}
	}
	if len(fc.actions) != 3 {
		t.Fatalf("expected 3 client calls, got %v", fc.actions)
	}
}

func TestProtectedUnits_LookupWithoutSuffix(t *testing.T) {
	m := newManager(t, &fakeClient{})
	if !m.IsProtected("sshd") {
		t.Fatalf("expected sshd to be protected (no suffix)")
	}
	if !m.IsProtected("sshd.service") {
		t.Fatalf("expected sshd.service to be protected")
	}
	if m.IsProtected("nginx.service") {
		t.Fatalf("expected nginx not protected")
	}
}

func TestNew_RejectsNilClient(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatalf("expected error for nil client")
	}
}
