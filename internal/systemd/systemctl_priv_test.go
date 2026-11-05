package systemd

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

type recordingPriv struct {
	calls [][]string
	err   error
}

func (r *recordingPriv) Call(_ context.Context, action string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{action}, args...))
	return nil, r.err
}

// An unprivileged agent must send start/stop/restart/reload through the
// privilege helper instead of running systemctl itself (it has no rights).
func TestSystemctlClientAction_UsesPrivilegeHelperWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: systemctl is called directly")
	}
	for _, a := range []Action{ActionStart, ActionStop, ActionRestart, ActionReload} {
		p := &recordingPriv{}
		c := &SystemctlClient{Priv: p}
		if err := c.Action(context.Background(), "nginx.service", a); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if want := [][]string{{"service." + string(a), "nginx.service"}}; !reflect.DeepEqual(p.calls, want) {
			t.Fatalf("%s: calls %v, want %v", a, p.calls, want)
		}
	}
	// A refusal from the helper is returned to the caller untouched.
	refused := errors.New("sshd is a protected system service")
	c := &SystemctlClient{Priv: &recordingPriv{err: refused}}
	if err := c.Action(context.Background(), "sshd.service", ActionRestart); !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the helper's refusal", err)
	}
}
