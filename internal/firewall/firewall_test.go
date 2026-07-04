package firewall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fakeBackend is a recordable in-memory Backend used to drive Manager
// tests against both ufw and firewalld semantics without touching the
// host.
type fakeBackend struct {
	kind        BackendKind
	available   error
	rules       []Rule
	rulesErr    error
	addCalls    []Rule
	addErr      error
	removeCalls []Rule
	removeErr   error
}

func (f *fakeBackend) Kind() BackendKind                 { return f.kind }
func (f *fakeBackend) Available(_ context.Context) error { return f.available }
func (f *fakeBackend) Rules(_ context.Context) ([]Rule, error) {
	if f.rulesErr != nil {
		return nil, f.rulesErr
	}
	return append([]Rule(nil), f.rules...), nil
}
func (f *fakeBackend) Add(_ context.Context, r Rule) error {
	f.addCalls = append(f.addCalls, r)
	if f.addErr != nil {
		return f.addErr
	}
	f.rules = append(f.rules, r)
	return nil
}
func (f *fakeBackend) Remove(_ context.Context, r Rule) error {
	f.removeCalls = append(f.removeCalls, r)
	if f.removeErr != nil {
		return f.removeErr
	}
	out := f.rules[:0]
	for _, existing := range f.rules {
		if existing == r {
			continue
		}
		out = append(out, existing)
	}
	f.rules = out
	return nil
}

type fakeSockets struct {
	sockets []Socket
	err     error
}

func (f fakeSockets) Listening(_ context.Context) ([]Socket, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]Socket(nil), f.sockets...), nil
}

type fixedSSH struct{ ports []int }

func (f fixedSSH) SSHPorts(_ context.Context) []int { return append([]int(nil), f.ports...) }

func newManagerT(t *testing.T, cfg Config) *Manager {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// AC: status returns sockets, current rules, and detects backend ufw.
func TestStatus_DetectsUFWBackend_AC1(t *testing.T) {
	ufw := &fakeBackend{kind: BackendUFW, rules: []Rule{
		{Action: ActionAllow, Protocol: ProtoTCP, Port: 22},
	}}
	m := newManagerT(t, Config{
		Backends: []Backend{ufw, &fakeBackend{kind: BackendFirewalld, available: errors.New("absent")}},
		Sockets:  fakeSockets{sockets: []Socket{{Protocol: ProtoTCP, Address: "0.0.0.0", Port: 22, Process: "sshd", PID: 100}}},
		SSH:      fixedSSH{ports: []int{22}},
	})

	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Backend != BackendUFW || !st.Available {
		t.Fatalf("backend = %s available=%v", st.Backend, st.Available)
	}
	if len(st.Rules) != 1 || st.Rules[0].Port != 22 {
		t.Fatalf("rules = %+v", st.Rules)
	}
	if len(st.Sockets) != 1 || st.Sockets[0].Process != "sshd" {
		t.Fatalf("sockets = %+v", st.Sockets)
	}
	if !reflect.DeepEqual(st.SSHPorts, []int{22}) {
		t.Fatalf("ssh_ports = %v", st.SSHPorts)
	}
}

// AC: status detects firewalld when ufw is absent.
func TestStatus_DetectsFirewalldBackend_AC1(t *testing.T) {
	fw := &fakeBackend{kind: BackendFirewalld, rules: []Rule{{Action: ActionAllow, Protocol: ProtoTCP, Port: 22}}}
	m := newManagerT(t, Config{
		Backends: []Backend{
			&fakeBackend{kind: BackendUFW, available: errors.New("ufw absent")},
			fw,
		},
		Sockets: fakeSockets{},
		SSH:     fixedSSH{ports: []int{22}},
	})
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Backend != BackendFirewalld || !st.Available {
		t.Fatalf("backend = %s available=%v", st.Backend, st.Available)
	}
}

// AC: a host with neither backend falls back to a read-only listening-
// sockets view with a typed reason; no edit actions are offered.
func TestStatus_ReadOnlyFallback_AC2(t *testing.T) {
	m := newManagerT(t, Config{
		Backends: []Backend{
			&fakeBackend{kind: BackendUFW, available: errors.New("ufw absent")},
			&fakeBackend{kind: BackendFirewalld, available: errors.New("firewalld absent")},
		},
		Sockets: fakeSockets{sockets: []Socket{{Protocol: ProtoTCP, Address: "0.0.0.0", Port: 22, Process: "sshd"}}},
		SSH:     fixedSSH{ports: []int{22}},
	})
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Available {
		t.Fatal("expected unavailable")
	}
	if st.Backend != BackendNone || st.UnavailableReason != "no_backend" {
		t.Fatalf("backend=%s reason=%s", st.Backend, st.UnavailableReason)
	}
	if len(st.Sockets) != 1 {
		t.Fatalf("sockets should still be reported, got %+v", st.Sockets)
	}
	if len(st.Rules) != 0 {
		t.Fatalf("rules should be empty, got %+v", st.Rules)
	}
	// AC: no edit actions are offered. RuleAdd/RuleRemove must fail
	// with ErrReadOnly so the server can refuse to expose them.
	if err := m.RuleAdd(context.Background(), Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 80}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("RuleAdd on read-only should be ErrReadOnly, got %v", err)
	}
	if err := m.RuleRemove(context.Background(), Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 80}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("RuleRemove on read-only should be ErrReadOnly, got %v", err)
	}
}

// AC: rule_add / rule_remove mutate against the detected backend.
func TestRuleAddRemove_RoutesToDetectedBackend_AC3(t *testing.T) {
	for _, kind := range []BackendKind{BackendUFW, BackendFirewalld} {
		t.Run(string(kind), func(t *testing.T) {
			b := &fakeBackend{kind: kind}
			m := newManagerT(t, Config{
				Backends: []Backend{b},
				Sockets:  fakeSockets{},
				SSH:      fixedSSH{ports: []int{22}},
			})
			rule := Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 80}
			if err := m.RuleAdd(context.Background(), rule); err != nil {
				t.Fatalf("RuleAdd: %v", err)
			}
			if len(b.addCalls) != 1 || b.addCalls[0] != rule {
				t.Fatalf("add not routed: %+v", b.addCalls)
			}
			if err := m.RuleRemove(context.Background(), rule); err != nil {
				t.Fatalf("RuleRemove: %v", err)
			}
			if len(b.removeCalls) != 1 || b.removeCalls[0] != rule {
				t.Fatalf("remove not routed: %+v", b.removeCalls)
			}
		})
	}
}

// AC: anti-lockout guard refuses adding a deny rule covering the active
// SSH port, with a typed error, BEFORE any backend call.
func TestAntiLockout_RefusesDenyOnSSHPort_AC4(t *testing.T) {
	b := &fakeBackend{kind: BackendUFW}
	m := newManagerT(t, Config{
		Backends: []Backend{b},
		Sockets:  fakeSockets{},
		SSH:      fixedSSH{ports: []int{2222}}, // non-default port — proves resolution comes from sockets
	})
	err := m.RuleAdd(context.Background(), Rule{Action: ActionDeny, Protocol: ProtoTCP, Port: 2222})
	if !errors.Is(err, ErrAntiLockout) {
		t.Fatalf("expected ErrAntiLockout, got %v", err)
	}
	var ale *AntiLockoutError
	if !errors.As(err, &ale) {
		t.Fatalf("error should be AntiLockoutError, got %T", err)
	}
	if !reflect.DeepEqual(ale.SSHPorts, []int{2222}) || ale.Rule.Port != 2222 {
		t.Fatalf("typed payload wrong: %+v", ale)
	}
	if len(b.addCalls) != 0 {
		t.Fatalf("backend Add called before guard: %+v", b.addCalls)
	}
}

// AC: anti-lockout guard refuses REMOVING the allow rule covering the
// active SSH port.
func TestAntiLockout_RefusesRemovingSSHAllowRule_AC4(t *testing.T) {
	b := &fakeBackend{kind: BackendUFW, rules: []Rule{{Action: ActionAllow, Protocol: ProtoTCP, Port: 22}}}
	m := newManagerT(t, Config{
		Backends: []Backend{b},
		Sockets:  fakeSockets{},
		SSH:      fixedSSH{ports: []int{22}},
	})
	err := m.RuleRemove(context.Background(), Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 22})
	if !errors.Is(err, ErrAntiLockout) {
		t.Fatalf("expected ErrAntiLockout, got %v", err)
	}
	if len(b.removeCalls) != 0 {
		t.Fatalf("backend Remove called before guard: %+v", b.removeCalls)
	}
}

// AC: anti-lockout allows non-SSH edits.
func TestAntiLockout_AllowsNonSSHEdits_AC4(t *testing.T) {
	b := &fakeBackend{kind: BackendUFW}
	m := newManagerT(t, Config{
		Backends: []Backend{b},
		Sockets:  fakeSockets{},
		SSH:      fixedSSH{ports: []int{22}},
	})
	if err := m.RuleAdd(context.Background(), Rule{Action: ActionDeny, Protocol: ProtoTCP, Port: 9999}); err != nil {
		t.Fatalf("non-SSH deny add should be allowed: %v", err)
	}
}

// AC: IsSSHRule reports true for active SSH ports.
func TestIsSSHRule(t *testing.T) {
	m := newManagerT(t, Config{
		Backends: []Backend{&fakeBackend{kind: BackendUFW}},
		Sockets:  fakeSockets{},
		SSH:      fixedSSH{ports: []int{22, 2222}},
	})
	if !m.IsSSHRule(context.Background(), Rule{Port: 22}) {
		t.Fatal("port 22 should be sshd")
	}
	if !m.IsSSHRule(context.Background(), Rule{Port: 2222}) {
		t.Fatal("port 2222 should be sshd")
	}
	if m.IsSSHRule(context.Background(), Rule{Port: 80}) {
		t.Fatal("port 80 should not be sshd")
	}
}

// AC: backend detection prefers ufw over firewalld when both are
// reachable (deterministic order from Config.Backends).
func TestDetect_PrefersFirstAvailable(t *testing.T) {
	ufw := &fakeBackend{kind: BackendUFW}
	fw := &fakeBackend{kind: BackendFirewalld}
	m := newManagerT(t, Config{
		Backends: []Backend{ufw, fw},
		Sockets:  fakeSockets{},
		SSH:      fixedSSH{ports: []int{22}},
	})
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Backend != BackendUFW {
		t.Fatalf("expected ufw preferred, got %s", st.Backend)
	}
}

// AC: SSHFromSockets resolves ports from sshd-owned listening sockets,
// not user input.
func TestSSHFromSockets_ResolvesFromLiveSockets(t *testing.T) {
	reader := fakeSockets{sockets: []Socket{
		{Protocol: ProtoTCP, Port: 22, Process: "sshd"},
		{Protocol: ProtoTCP, Port: 2222, Process: "sshd"},
		{Protocol: ProtoTCP, Port: 80, Process: "nginx"},
	}}
	got := SSHFromSockets{Reader: reader}.SSHPorts(context.Background())
	want := []int{22, 2222}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SSHPorts = %v, want %v", got, want)
	}
}

func TestSSHFromSockets_FallsBackTo22(t *testing.T) {
	got := SSHFromSockets{Reader: fakeSockets{}}.SSHPorts(context.Background())
	if !reflect.DeepEqual(got, []int{22}) {
		t.Fatalf("fallback got %v", got)
	}
}

// AC: validation rejects unknown actions / out-of-range ports before any
// backend call.
func TestValidate_RejectsBadInput(t *testing.T) {
	b := &fakeBackend{kind: BackendUFW}
	m := newManagerT(t, Config{
		Backends: []Backend{b},
		Sockets:  fakeSockets{},
		SSH:      fixedSSH{ports: []int{22}},
	})
	if err := m.RuleAdd(context.Background(), Rule{Action: "drop", Protocol: ProtoTCP, Port: 80}); !errors.Is(err, ErrUnsupportedAction) {
		t.Fatalf("bad action: %v", err)
	}
	if err := m.RuleAdd(context.Background(), Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 70000}); err == nil {
		t.Fatal("port out of range should fail")
	}
	if len(b.addCalls) != 0 {
		t.Fatalf("backend should not be called: %+v", b.addCalls)
	}
}

// Parser smoke tests — exercising real ufw + ss formats without needing
// the binaries.
func TestParseUFWRules(t *testing.T) {
	raw := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     DENY IN     Anywhere
[ 3] 53                         ALLOW IN    Anywhere
`
	got := parseUFWRules(raw)
	want := []Rule{
		{Action: ActionAllow, Protocol: ProtoTCP, Port: 22},
		{Action: ActionDeny, Protocol: ProtoTCP, Port: 80},
		{Action: ActionAllow, Protocol: ProtoAny, Port: 53},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseUFWRules = %+v\nwant %+v", got, want)
	}
}

// Review comment #3329218455: in the packaged install the agent runs as
// `rootmote`, so ufw / firewall-cmd must be invoked through a privileged
// path. When Sudo=true the backends must prepend `sudo -n`.
func TestBackends_SudoWraps_RealCommand(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("running"), nil
	}
	lookup := func(string) (string, error) { return "/usr/bin/x", nil }

	u := &UFWBackend{Run: run, LookBin: lookup, Sudo: true}
	if err := u.Available(context.Background()); err != nil {
		t.Fatalf("ufw available: %v", err)
	}
	if err := u.Add(context.Background(), Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 80}); err != nil {
		t.Fatalf("ufw add: %v", err)
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "sudo -n ufw ") {
			t.Fatalf("ufw call not wrapped with sudo -n: %q", c)
		}
	}

	calls = nil
	f := &FirewalldBackend{Run: run, LookBin: lookup, Sudo: true}
	if err := f.Available(context.Background()); err != nil {
		t.Fatalf("firewalld available: %v", err)
	}
	if err := f.Add(context.Background(), Rule{Action: ActionAllow, Protocol: ProtoTCP, Port: 80}); err != nil {
		t.Fatalf("firewalld add: %v", err)
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "sudo -n firewall-cmd ") {
			t.Fatalf("firewalld call not wrapped with sudo -n: %q", c)
		}
	}
}

func TestParseSS(t *testing.T) {
	raw := `tcp   LISTEN 0      128         0.0.0.0:22          0.0.0.0:*    users:(("sshd",pid=421,fd=3))
tcp   LISTEN 0      128         127.0.0.1:7676      0.0.0.0:*    users:(("rootmote-agent",pid=999,fd=7))
udp   UNCONN 0      0           0.0.0.0:53          0.0.0.0:*    users:(("dnsmasq",pid=300,fd=4))
`
	got := parseSS(raw)
	if len(got) != 3 {
		t.Fatalf("len = %d: %+v", len(got), got)
	}
	if got[0].Process != "sshd" || got[0].PID != 421 || got[0].Port != 22 || got[0].Protocol != ProtoTCP {
		t.Fatalf("first socket: %+v", got[0])
	}
	if got[2].Protocol != ProtoUDP || got[2].Port != 53 {
		t.Fatalf("udp socket: %+v", got[2])
	}
}

func TestParseLsofDarwinSockets(t *testing.T) {
	raw := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd        421   root    3u  IPv4 0x123456789abcdef0      0t0  TCP *:22 (LISTEN)
rootmote-ag   999 rootmote    7u  IPv4 0x123456789abcdef1      0t0  TCP 127.0.0.1:7676 (LISTEN)
`
	got := parseLsof(raw, ProtoTCP)
	if len(got) != 2 {
		t.Fatalf("len=%d got=%+v", len(got), got)
	}
	if got[0].Process != "sshd" || got[0].PID != 421 || got[0].Port != 22 || got[0].Address != "*" {
		t.Fatalf("first socket: %+v", got[0])
	}
	if got[1].Process != "rootmote-ag" || got[1].Port != 7676 || got[1].Address != "127.0.0.1" {
		t.Fatalf("second socket: %+v", got[1])
	}
}

func TestParseNetstatDarwinSockets(t *testing.T) {
	raw := `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options
tcp4       0      0  127.0.0.1.7676         *.*                    LISTEN                 0            0  131072  131072     rootmote-agent:99680  00100 00000006
tcp4       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072          launchd:1      00180 00000006
tcp4       0      0  127.0.0.1.64795        1.1.1.1.443            ESTABLISHED            0          171  132104  132104          Safari:100     00102 00000008
`
	got := parseNetstatDarwin(raw)
	if len(got) != 2 {
		t.Fatalf("len=%d got=%+v", len(got), got)
	}
	if got[0].Process != "rootmote-agent" || got[0].PID != 99680 || got[0].Address != "127.0.0.1" || got[0].Port != 7676 {
		t.Fatalf("first socket: %+v", got[0])
	}
	if got[1].Process != "launchd" || got[1].PID != 1 || got[1].Address != "*" || got[1].Port != 22 {
		t.Fatalf("second socket: %+v", got[1])
	}
}
