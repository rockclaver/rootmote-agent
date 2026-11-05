package steps

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/firewall"
)

type fakeProc struct {
	comm  string
	ppid  int
	start uint64
	alive bool
}

type fakeFW struct {
	rules   []firewall.Rule
	added   []firewall.Rule
	removed []firewall.Rule
}

func (f *fakeFW) Kind() firewall.BackendKind                     { return firewall.BackendUFW }
func (f *fakeFW) Available(context.Context) error                { return nil }
func (f *fakeFW) Rules(context.Context) ([]firewall.Rule, error) { return f.rules, nil }
func (f *fakeFW) Add(_ context.Context, r firewall.Rule) error {
	f.added = append(f.added, r)
	return nil
}
func (f *fakeFW) Remove(_ context.Context, r firewall.Rule) error {
	f.removed = append(f.removed, r)
	return nil
}

type fixedSSH []int

func (s fixedSSH) SSHPorts(context.Context) []int { return s }

type noSockets struct{}

func (noSockets) Listening(context.Context) ([]firewall.Socket, error) { return nil, nil }

type fakeHost struct {
	fsys    fstest.MapFS
	runs    [][]string
	runFn   func(name string, args []string) ([]byte, error)
	paths   map[string]bool
	users   map[string]UserInfo
	uids    map[string]int
	procs   map[int]*fakeProc
	self    int
	signals []int
	chdirs  []string
	fw      *fakeFW
	sshPort []int
	hostNS  bool
	reexec  [][]string
	reCode  int
	now     time.Time
	onSig   func(pid int, sig syscall.Signal)
}

func newHost() *fakeHost {
	return &fakeHost{
		fsys:    fstest.MapFS{"etc/supervisor/supervisord.conf": &fstest.MapFile{Data: []byte("[supervisord]\n")}},
		paths:   map[string]bool{"nginx": true, "certbot": true, "apt-get": true, "supervisorctl": true},
		users:   map[string]UserInfo{},
		uids:    map[string]int{"/etc/supervisor/supervisord.conf": 0},
		procs:   map[int]*fakeProc{},
		self:    500,
		fw:      &fakeFW{},
		sshPort: []int{22},
		hostNS:  true,
		now:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func (h *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.runs = append(h.runs, append([]string{name}, args...))
	if h.runFn != nil {
		return h.runFn(name, args)
	}
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		unit := args[len(args)-1]
		if !hasUnitSuffix(unit) {
			unit += ".service"
		}
		return []byte("Id=" + unit + "\nLoadState=loaded\n"), nil
	}
	return nil, nil
}
func (h *fakeHost) ran(prefix ...string) bool {
	for _, r := range h.runs {
		if len(r) >= len(prefix) && strings.Join(r[:len(prefix)], " ") == strings.Join(prefix, " ") {
			return true
		}
	}
	return false
}
func (h *fakeHost) LookPath(n string) (string, error) {
	if h.paths[n] {
		return "/usr/bin/" + n, nil
	}
	return "", errors.New("not found")
}
func rel(p string) string                             { return strings.TrimPrefix(p, "/") }
func (h *fakeHost) ReadFile(p string) ([]byte, error) { return h.fsys.ReadFile(rel(p)) }
func (h *fakeHost) ReadTail(p string, max int64) ([]byte, error) {
	fi, err := h.fsys.Stat(rel(p))
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := h.fsys.ReadFile(rel(p))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		data = data[int64(len(data))-max:]
	}
	return data, nil
}
func (h *fakeHost) ReadDir(p string) ([]fs.DirEntry, error) {
	return h.fsys.ReadDir(rel(p))
}
func (h *fakeHost) Stat(p string) (fs.FileInfo, error)  { return h.fsys.Stat(rel(p)) }
func (h *fakeHost) Lstat(p string) (fs.FileInfo, error) { return h.fsys.Stat(rel(p)) }
func (h *fakeHost) FileUID(p string) (int, error) {
	if u, ok := h.uids[p]; ok {
		return u, nil
	}
	return 0, os.ErrNotExist
}
func (h *fakeHost) LookupUser(n string) (UserInfo, error) {
	if u, ok := h.users[n]; ok {
		return u, nil
	}
	return UserInfo{}, errors.New("no such user")
}
func (h *fakeHost) Self() int { return h.self }
func (h *fakeHost) PIDs() []int {
	var out []int
	for p := range h.procs {
		out = append(out, p)
	}
	return out
}
func (h *fakeHost) ParentPID(pid int) int {
	if p, ok := h.procs[pid]; ok {
		return p.ppid
	}
	return 0
}
func (h *fakeHost) Comm(pid int) string {
	if p, ok := h.procs[pid]; ok {
		return p.comm
	}
	return ""
}
func (h *fakeHost) StartTime(pid int) (uint64, bool) {
	if p, ok := h.procs[pid]; ok && p.alive {
		return p.start, true
	}
	return 0, false
}
func (h *fakeHost) OpenProcess(pid int) (Process, error) {
	if p, ok := h.procs[pid]; ok && p.alive {
		return &fakeProcHandle{h: h, pid: pid}, nil
	}
	return nil, errors.New("no such process")
}

type fakeProcHandle struct {
	h   *fakeHost
	pid int
}

func (p *fakeProcHandle) Signal(sig syscall.Signal) error {
	p.h.signals = append(p.h.signals, int(sig))
	if p.h.onSig != nil {
		p.h.onSig(p.pid, sig)
	}
	return nil
}
func (p *fakeProcHandle) Close() error { return nil }
func (h *fakeHost) Chdir(dir string) error {
	h.chdirs = append(h.chdirs, dir)
	return nil
}

func hasUnitSuffix(u string) bool {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(u, s) {
			return true
		}
	}
	return false
}
func (h *fakeHost) Sleep(context.Context, time.Duration) {}
func (h *fakeHost) Now() time.Time                       { return h.now }
func (h *fakeHost) Firewall() *firewall.Manager {
	m, _ := firewall.New(firewall.Config{Backends: []firewall.Backend{h.fw}, Sockets: noSockets{}, SSH: fixedSSH(h.sshPort)})
	return m
}
func (h *fakeHost) InHostNS() bool { return h.hostNS }
func (h *fakeHost) RunInHostNS(_ context.Context, args []string, _, _ io.Writer) int {
	h.reexec = append(h.reexec, args)
	return h.reCode
}

// priv runs the helper and returns exit code, stdout, stderr.
func priv(h Host, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := RunPriv(context.Background(), h, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestPriv_RefusesProtectedUnits(t *testing.T) {
	for _, unit := range []string{
		"ssh", "sshd", "ssh.service", "sshd.service", "ssh.socket", "systemd-journald.service",
		"systemd-logind", "dbus.service", "dbus-broker.service", "networking.service",
		"NetworkManager.service", "systemd-networkd.service", "systemd-resolved.service",
		"rootmote-agent.service", "getty@tty1.service", "docker.service", "docker", "docker.socket",
		"containerd.service",
	} {
		for _, action := range []string{"service.restart", "service.stop", "service.start", "service.reload"} {
			h := newHost()
			code, _, stderr := priv(h, action, unit)
			if code != ExitRefused {
				t.Errorf("%s %s: exit %d, want 2 (stderr %q)", action, unit, code, stderr)
			}
			if h.ran("systemctl", "restart") || h.ran("systemctl", "stop") || h.ran("systemctl", "start") || h.ran("systemctl", "reload") {
				t.Errorf("%s %s: systemctl was called", action, unit)
			}
		}
	}
}

func TestPriv_RefusesProtectedUnitBehindAlias(t *testing.T) {
	h := newHost()
	h.runFn = func(name string, args []string) ([]byte, error) {
		return []byte("Id=ssh.service\nLoadState=loaded\n"), nil
	}
	if code, _, _ := priv(h, "service.stop", "remote-login.service"); code != ExitRefused {
		t.Fatalf("alias of ssh: exit %d, want 2", code)
	}
	if h.ran("systemctl", "stop") {
		t.Fatal("stop ran through an alias of a protected unit")
	}
}

func TestPriv_RefusesBadNamesAndMissingUnits(t *testing.T) {
	for _, unit := range []string{"", "a b", "../x", "-rf", "--now", "x;reboot", "a$(b)", strings.Repeat("a", 129)} {
		h := newHost()
		if code, _, _ := priv(h, "service.restart", unit); code != ExitRefused {
			t.Errorf("unit %q: exit %d, want 2", unit, code)
		}
		if len(h.runs) != 0 {
			t.Errorf("unit %q: a command ran: %v", unit, h.runs)
		}
	}
	h := newHost()
	h.runFn = func(string, []string) ([]byte, error) { return []byte("Id=ghost.service\nLoadState=not-found\n"), nil }
	if code, _, stderr := priv(h, "service.restart", "ghost.service"); code != ExitRefused || !strings.Contains(stderr, "no service") {
		t.Fatalf("missing unit: exit %d stderr %q", code, stderr)
	}
}

func TestPriv_RejectsUnknownActionAndExtraArgs(t *testing.T) {
	h := newHost()
	for _, args := range [][]string{{}, {"rm"}, {"service.restart"}, {"service.restart", "a", "b"}, {"disk.apt_clean", "x"}} {
		if code, _, _ := priv(h, args...); code != ExitRefused {
			t.Errorf("args %v: exit %d, want 2", args, code)
		}
	}
	if len(h.runs) != 0 {
		t.Fatalf("commands ran: %v", h.runs)
	}
}

func TestPriv_ServiceArgv(t *testing.T) {
	for _, verb := range []string{"restart", "start", "stop", "reload"} {
		h := newHost()
		code, _, stderr := priv(h, "service."+verb, "myapp.service")
		if code != ExitOK {
			t.Fatalf("%s: exit %d %q", verb, code, stderr)
		}
		if !h.ran("systemctl", verb, "myapp.service") {
			t.Fatalf("%s: runs %v", verb, h.runs)
		}
	}
	h := newHost()
	if code, _, _ := priv(h, "phpfpm.restart", "nginx.service"); code != ExitRefused {
		t.Fatal("phpfpm.restart accepted a non-php unit")
	}
	if code, _, _ := priv(h, "phpfpm.restart", "php8.3-fpm.service"); code != ExitOK || !h.ran("systemctl", "restart", "php8.3-fpm.service") {
		t.Fatalf("php restart failed: %v", h.runs)
	}
}

func TestPriv_NginxReloadTestsFirst(t *testing.T) {
	h := newHost()
	h.runFn = func(name string, args []string) ([]byte, error) {
		if name == "nginx" {
			return []byte("nginx: [emerg] unexpected end of file"), errors.New("exit 1")
		}
		return []byte("Id=nginx.service\nLoadState=loaded\n"), nil
	}
	code, _, stderr := priv(h, "nginx.reload")
	if code != ExitFailed || !strings.Contains(stderr, "was not reloaded") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if h.ran("systemctl", "reload") {
		t.Fatal("nginx was reloaded after a failed test")
	}

	h = newHost()
	if code, _, stderr := priv(h, "nginx.reload"); code != ExitOK {
		t.Fatalf("exit %d %q", code, stderr)
	}
	var order []string
	for _, r := range h.runs {
		if r[0] == "nginx" || (r[0] == "systemctl" && r[1] == "reload") {
			order = append(order, strings.Join(r, " "))
		}
	}
	if strings.Join(order, "|") != "nginx -t|systemctl reload nginx" {
		t.Fatalf("order %v", order)
	}
}

func TestPriv_JournalAndApt(t *testing.T) {
	for _, bad := range []string{"1G", "100M;id", "", "50M", "-1"} {
		h := newHost()
		if code, _, _ := priv(h, "disk.journal_vacuum", bad); code != ExitRefused || len(h.runs) != 0 {
			t.Errorf("size %q: exit %d runs %v", bad, code, h.runs)
		}
	}
	h := newHost()
	if code, _, _ := priv(h, "disk.journal_vacuum", "200M"); code != ExitOK || !h.ran("journalctl", "--vacuum-size=200M") {
		t.Fatalf("journal: %v", h.runs)
	}
	if code, _, _ := priv(h, "disk.apt_clean"); code != ExitOK || !h.ran("apt-get", "clean") {
		t.Fatalf("apt: %v", h.runs)
	}
	h.paths["apt-get"] = false
	if code, _, _ := priv(h, "disk.apt_clean"); code != ExitRefused {
		t.Fatal("apt clean without apt-get was not refused")
	}
}

func TestPriv_HostNamespaceRouting(t *testing.T) {
	h := newHost()
	h.hostNS = false
	h.reCode = 7
	if code, _, _ := priv(h, "service.restart", "myapp.service"); code != ExitOK || len(h.reexec) != 0 {
		t.Fatalf("service.restart must run in place: code %d reexec %v", code, h.reexec)
	}
	h.runs = nil
	for _, a := range []string{"cert.renew", "disk.journal_vacuum", "disk.apt_clean", "pm2-list", "firewall.allow", "firewall.remove", "firewall-rules"} {
		h.reexec = nil
		args := []string{a}
		switch a {
		case "cert.renew":
			args = append(args, "example.com")
		case "disk.journal_vacuum":
			args = append(args, "100M")
		case "pm2-list":
			args = append(args, "alice")
		}
		if code, _, _ := priv(h, args...); code != 7 || len(h.reexec) != 1 {
			t.Errorf("%s: code %d reexec %v", a, code, h.reexec)
		}
	}
	if len(h.runs) != 0 {
		t.Fatalf("commands ran in the sandbox: %v", h.runs)
	}
}

func writeCert(t *testing.T, h *fakeHost, name string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	h.fsys["etc/letsencrypt/live/"+name+"/fullchain.pem"] = &fstest.MapFile{Data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	h.fsys["etc/letsencrypt/renewal/"+name+".conf"] = &fstest.MapFile{Data: []byte("# renewal\n")}
}

func TestPriv_CertRenew(t *testing.T) {
	h := newHost()
	writeCert(t, h, "example.com", h.now.Add(10*24*time.Hour))
	for _, bad := range []string{"../../etc", "..", ".", "a/b", "/etc/passwd", "example.com/../x", ".hidden", "", "missing.org", "a..b"} {
		if code, _, _ := priv(h, "cert.renew", bad); code != ExitRefused {
			t.Errorf("cert name %q: exit %d, want 2", bad, code)
		}
	}
	writeCert(t, h, "noconf.org", h.now.Add(10*24*time.Hour))
	delete(h.fsys, "etc/letsencrypt/renewal/noconf.org.conf")
	if code, _, stderr := priv(h, "cert.renew", "noconf.org"); code != ExitRefused || !strings.Contains(stderr, "no renewal settings") || h.ran("certbot") {
		t.Fatalf("cert without renewal settings: exit %d stderr %q runs %v", code, stderr, h.runs)
	}
	if h.ran("certbot") {
		t.Fatal("certbot ran for a refused name")
	}
	if code, _, stderr := priv(h, "cert.renew", "example.com"); code != ExitOK {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if !h.ran("certbot", "renew", "--cert-name", "example.com") || h.ran("certbot", "renew", "--cert-name", "example.com", "--dry-run") {
		t.Fatalf("certbot argv: %v", h.runs)
	}
	var sawTest, sawReload bool
	for _, r := range h.runs {
		sawTest = sawTest || (r[0] == "nginx" && r[1] == "-t")
		sawReload = sawReload || (r[0] == "systemctl" && r[1] == "reload")
	}
	if !sawTest || !sawReload {
		t.Fatalf("nginx not tested and reloaded after renew: %v", h.runs)
	}

	h.runs = nil
	if code, _, _ := priv(h, "cert.renew", "example.com", "--dry-run"); code != ExitOK {
		t.Fatal("dry run failed")
	}
	if !h.ran("certbot", "renew", "--cert-name", "example.com", "--dry-run") || h.ran("systemctl", "reload") {
		t.Fatalf("dry run argv/reload: %v", h.runs)
	}
	if code, _, _ := priv(h, "cert.renew", "example.com", "--force-renewal"); code != ExitRefused {
		t.Fatal("unknown cert flag accepted")
	}
}

func TestPriv_ComposeUpIsNotAHelperAction(t *testing.T) {
	for _, a := range PrivActionNames() {
		if strings.HasPrefix(a, "compose") {
			t.Fatalf("helper action %q runs Compose as root", a)
		}
	}
	h := newHost()
	if code, _, _ := priv(h, "compose.up", "shop", "web"); code != ExitRefused || len(h.runs) != 0 {
		t.Fatalf("compose.up: exit %d, runs %v", code, h.runs)
	}
}

func TestPriv_LeavesCallerWorkingDirectory(t *testing.T) {
	h := newHost()
	priv(h, "nginx-test", "extra")
	if len(h.chdirs) != 1 || h.chdirs[0] != "/" {
		t.Fatalf("chdirs = %v, want [/] before anything else runs", h.chdirs)
	}
}

func TestPriv_OnlyServiceUnits(t *testing.T) {
	for _, unit := range []string{
		"poweroff.target", "reboot.target", "halt.target", "kexec.target", "user.slice", "session-3.scope",
		"data.mount", "cron.timer", "foo.socket", "foo.path", "dev-sda.device", "swapfile.swap", "x.automount",
		"ifup@eth0.service", "ifup@eth0", "network", "network.service", "wpa_supplicant.service", "ufw.service", "ufw",
		"firewalld.service", "nftables.service", "iptables.service", "ip6tables.service", "netfilter-persistent.service",
		"user@1000.service", "sshd-session.service", "sshd-session",
	} {
		for _, action := range []string{"service.restart", "service.stop", "service.start", "service.reload"} {
			h := newHost()
			if code, _, stderr := priv(h, action, unit); code != ExitRefused {
				t.Errorf("%s %s: exit %d, want 2 (stderr %q)", action, unit, code, stderr)
			}
			if h.ran("systemctl", "restart") || h.ran("systemctl", "stop") || h.ran("systemctl", "start") || h.ran("systemctl", "reload") {
				t.Errorf("%s %s: systemctl changed something", action, unit)
			}
		}
	}
	// A name that systemd resolves to a non-service unit is refused too.
	h := newHost()
	h.runFn = func(string, []string) ([]byte, error) { return []byte("Id=reboot.target\nLoadState=loaded\n"), nil }
	if code, _, _ := priv(h, "service.start", "innocent"); code != ExitRefused || h.ran("systemctl", "start") {
		t.Fatalf("alias of a target: exit %d, runs %v", code, h.runs)
	}
	// An unknown Id is not trusted either.
	h = newHost()
	h.runFn = func(string, []string) ([]byte, error) { return []byte("LoadState=loaded\n"), nil }
	if code, _, _ := priv(h, "service.start", "innocent"); code != ExitRefused {
		t.Fatalf("missing Id: exit %d", code)
	}
	// Bare names for ordinary services still work.
	h = newHost()
	if code, _, stderr := priv(h, "service.restart", "myapp"); code != ExitOK {
		t.Fatalf("bare name: exit %d %q", code, stderr)
	}
}

func TestPriv_CertsList(t *testing.T) {
	h := newHost()
	writeCert(t, h, "b.example", h.now.Add(48*time.Hour))
	writeCert(t, h, "a.example", h.now.Add(24*time.Hour))
	h.fsys["etc/letsencrypt/live/README"] = &fstest.MapFile{Data: []byte("x")}
	code, out, stderr := priv(h, "certs-list")
	if code != ExitOK {
		t.Fatalf("exit %d %q", code, stderr)
	}
	want := `[{"name":"a.example","expiresAt":"2026-01-02T00:00:00Z"},{"name":"b.example","expiresAt":"2026-01-03T00:00:00Z"}]`
	if strings.TrimSpace(out) != want {
		t.Fatalf("out %s", out)
	}
	h = newHost()
	if _, out, _ := priv(h, "certs-list"); strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty list printed %q", out)
	}
}

func TestPriv_ProcessStop(t *testing.T) {
	setup := func() *fakeHost {
		h := newHost()
		h.procs[1] = &fakeProc{comm: "systemd", alive: true, start: 1}
		h.procs[400] = &fakeProc{comm: "rootmote-agent", ppid: 1, alive: true, start: 10} // the daemon
		h.procs[450] = &fakeProc{comm: "sudo", ppid: 400, alive: true, start: 11}
		h.procs[500] = &fakeProc{comm: "rootmote-agent", ppid: 450, alive: true, start: 12} // helper
		h.procs[410] = &fakeProc{comm: "git", ppid: 400, alive: true, start: 13}            // child of the agent
		h.procs[600] = &fakeProc{comm: "sshd", ppid: 1, alive: true, start: 20}
		h.procs[610] = &fakeProc{comm: "sshd-session", ppid: 600, alive: true, start: 21}
		h.procs[700] = &fakeProc{comm: "worker", ppid: 1, alive: true, start: 30}
		h.procs[2] = &fakeProc{comm: "kthreadd", ppid: 0, alive: true, start: 2}
		h.procs[800] = &fakeProc{comm: "kworker", ppid: 2, alive: true, start: 5}
		return h
	}
	refuse := [][]string{
		{"1", "1"}, {"0", "5"}, {"-1", "5"}, {"-5", "5"}, {"abc", "5"}, {"700", "0"}, {"700", "-3"},
		{"700", "99"},  // start time mismatch
		{"9999", "5"},  // not running
		{"500", "12"},  // the helper itself
		{"450", "11"},  // sudo, an ancestor
		{"400", "10"},  // the agent
		{"410", "13"},  // under the agent
		{"600", "20"},  // sshd
		{"610", "21"},  // sshd-session
		{"2", "2"},     // kernel thread
		{"800", "5"},   // kernel thread child
		{"7 00", "30"}, // spaces
	}
	for _, a := range refuse {
		h := setup()
		if code, _, stderr := priv(h, "process.stop", a[0], a[1]); code != ExitRefused {
			t.Errorf("process.stop %v: exit %d (%q), want 2", a, code, stderr)
		}
		if len(h.signals) != 0 {
			t.Errorf("process.stop %v: signals sent %v", a, h.signals)
		}
	}

	h := setup()
	h.onSig = func(pid int, sig syscall.Signal) { h.procs[pid].alive = false }
	if code, _, stderr := priv(h, "process.stop", "700", "30"); code != ExitOK {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if len(h.signals) != 1 || h.signals[0] != int(syscall.SIGTERM) {
		t.Fatalf("signals %v, want one SIGTERM", h.signals)
	}

	// A process that ignores SIGTERM gets SIGKILL.
	h = setup()
	h.onSig = func(pid int, sig syscall.Signal) {
		if sig == syscall.SIGKILL {
			h.procs[pid].alive = false
		}
	}
	if code, _, stderr := priv(h, "process.stop", "700", "30"); code != ExitOK {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if len(h.signals) != 2 || h.signals[1] != int(syscall.SIGKILL) {
		t.Fatalf("signals %v, want TERM then KILL", h.signals)
	}

	// If the pid is reused after SIGTERM, SIGKILL is never sent.
	h = setup()
	h.onSig = func(pid int, sig syscall.Signal) { h.procs[pid].start = 999 }
	if code, _, stderr := priv(h, "process.stop", "700", "30"); code != ExitOK {
		t.Fatalf("reused pid: exit %d %q", code, stderr)
	}
	if len(h.signals) != 1 {
		t.Fatalf("signals %v, want only SIGTERM through the pinned handle", h.signals)
	}
}

func TestPriv_FirewallNeverClosesSSH(t *testing.T) {
	h := newHost()
	h.sshPort = []int{22, 2222}
	h.fw.rules = []firewall.Rule{{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 22}}
	for _, port := range []string{"22", "2222"} {
		for _, proto := range []string{"tcp", "udp"} {
			code, _, stderr := priv(h, "firewall.remove", port, proto)
			if code != ExitRefused || !strings.Contains(stderr, "SSH") {
				t.Errorf("remove %s/%s: exit %d %q", port, proto, code, stderr)
			}
		}
	}
	if len(h.fw.removed) != 0 {
		t.Fatalf("SSH rule was removed: %v", h.fw.removed)
	}
	for _, args := range [][]string{{"0", "tcp"}, {"65536", "tcp"}, {"-1", "tcp"}, {"80", "icmp"}, {"80", "any"}, {"80; ufw disable", "tcp"}, {"80"}} {
		if code, _, _ := priv(h, append([]string{"firewall.allow"}, args...)...); code != ExitRefused {
			t.Errorf("allow %v: exit %d, want 2", args, code)
		}
	}
	if len(h.fw.added) != 0 || len(h.fw.removed) != 0 {
		t.Fatalf("firewall changed on refusal: %v %v", h.fw.added, h.fw.removed)
	}
	if code, _, stderr := priv(h, "firewall.allow", "8080", "tcp"); code != ExitOK || len(h.fw.added) != 1 || h.fw.added[0].Action != firewall.ActionAllow || h.fw.added[0].Port != 8080 {
		t.Fatalf("allow: %d %q %v", code, stderr, h.fw.added)
	}
	if code, _, _ := priv(h, "firewall.remove", "8080", "tcp"); code != ExitOK || len(h.fw.removed) != 1 {
		t.Fatalf("remove 8080: %v", h.fw.removed)
	}
}

func TestPriv_FirewallRulesListsAllowRules(t *testing.T) {
	h := newHost()
	h.fw.rules = []firewall.Rule{
		{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 443},
		{Action: firewall.ActionDeny, Protocol: firewall.ProtoTCP, Port: 25},
		{Action: firewall.ActionAllow, Protocol: firewall.ProtoAny, Port: 53},
	}
	code, out, _ := priv(h, "firewall-rules")
	want := `[{"port":443,"proto":"tcp"},{"port":53,"proto":"tcp"},{"port":53,"proto":"udp"}]`
	if code != ExitOK || strings.TrimSpace(out) != want {
		t.Fatalf("code %d out %s", code, out)
	}
}

func pm2Host() *fakeHost {
	h := newHost()
	h.users["alice"] = UserInfo{Name: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Shell: "/bin/bash"}
	h.users["root"] = UserInfo{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"}
	h.users["svc"] = UserInfo{Name: "svc", UID: 998, GID: 998, Home: "/var/svc", Shell: "/usr/sbin/nologin"}
	h.users["bob"] = UserInfo{Name: "bob", UID: 1002, GID: 1002, Home: "/home/bob", Shell: "/bin/bash"}
	h.fsys["home/alice/.pm2/dump.pm2"] = &fstest.MapFile{Data: []byte("[]")}
	h.fsys["usr/bin/pm2"] = &fstest.MapFile{Data: []byte("x")}
	h.uids["/home/alice/.pm2"] = 1001
	h.runFn = func(name string, args []string) ([]byte, error) {
		return []byte("[PM2] Spawning PM2 daemon\n[{\"name\":\"api\",\"pm2_env\":{\"status\":\"online\",\"restart_time\":3}}]\n"), nil
	}
	return h
}

func TestPriv_PM2(t *testing.T) {
	h := pm2Host()
	code, out, stderr := priv(h, "pm2-list", "alice")
	if code != ExitOK || strings.TrimSpace(out) != `[{"app":"api","status":"online","restarts":3}]` {
		t.Fatalf("list: %d %q %q", code, out, stderr)
	}
	want := "setpriv --reuid=1001 --regid=1001 --init-groups -- /usr/bin/env HOME=/home/alice USER=alice LOGNAME=alice PATH=/usr/bin:/usr/local/bin:/usr/bin:/bin /usr/bin/pm2 jlist"
	if got := strings.Join(h.runs[0], " "); got != want {
		t.Fatalf("argv\n got %s\nwant %s", got, want)
	}

	h = pm2Host()
	if code, _, stderr := priv(h, "pm2.restart", "alice", "api"); code != ExitOK {
		t.Fatalf("restart: %d %q", code, stderr)
	}
	if got := strings.Join(h.runs[len(h.runs)-1], " "); !strings.HasSuffix(got, "/usr/bin/pm2 restart api") || !strings.HasPrefix(got, "setpriv --reuid=1001") {
		t.Fatalf("restart argv %s", got)
	}

	for _, tc := range [][]string{
		{"root", "api"}, {"svc", "api"}, {"nobody-here", "api"}, {"bob", "api"}, // no .pm2
		{"alice", "ghost"}, {"alice", "-x"}, {"alice", "a b"}, {"../alice", "api"}, {"alice;id", "api"},
	} {
		h := pm2Host()
		if code, _, _ := priv(h, "pm2.restart", tc[0], tc[1]); code != ExitRefused {
			t.Errorf("pm2.restart %v: exit %d, want 2", tc, code)
		}
		if h.ran("setpriv", "--reuid=1001", "--regid=1001", "--init-groups", "--", "/usr/bin/env", "HOME=/home/alice", "USER=alice", "LOGNAME=alice", "PATH=/usr/bin:/usr/local/bin:/usr/bin:/bin", "/usr/bin/pm2", "restart") {
			t.Errorf("pm2.restart %v: pm2 restart ran", tc)
		}
	}
	h = pm2Host()
	if code, out, _ := priv(h, "pm2-list", "bob"); code != ExitOK || strings.TrimSpace(out) != "[]" {
		t.Fatalf("user without pm2: %d %q", code, out)
	}
	if code, _, _ := priv(h, "pm2-list", "root"); code != ExitRefused {
		t.Fatal("pm2-list ran for root")
	}
}

func TestParsePM2JList_SkipsBannerNoise(t *testing.T) {
	apps, err := parsePM2JList([]byte("[PM2] Spawning PM2 daemon with pm2_home=/home/a/.pm2\n[PM2] PM2 Successfully daemonized\n[]\n"))
	if err != nil || len(apps) != 0 {
		t.Fatalf("apps %v err %v", apps, err)
	}
}

func TestPriv_Supervisor(t *testing.T) {
	h := newHost()
	h.runFn = func(name string, args []string) ([]byte, error) {
		if len(args) == 3 && args[2] == "status" {
			return []byte("queue:queue_00     RUNNING   pid 12, uptime 0:01:00\nqueue:queue_01     RUNNING   pid 13, uptime 0:01:00\nmailer             FATAL     Exited too quickly\n"), errors.New("exit 3")
		}
		return []byte("ok"), nil
	}
	code, out, _ := priv(h, "supervisor-status")
	if code != ExitOK || !strings.Contains(out, `"name":"queue:queue_00","state":"RUNNING"`) || !strings.Contains(out, `"state":"FATAL"`) {
		t.Fatalf("status: %d %s", code, out)
	}
	if code, _, _ := priv(h, "supervisor.restart", "queue"); code != ExitOK || !h.ran("supervisorctl", "-c", "/etc/supervisor/supervisord.conf", "restart", "queue") {
		t.Fatalf("group restart: %v", h.runs)
	}
	for _, bad := range []string{"ghost", "-x", "a b", ""} {
		if code, _, _ := priv(h, "supervisor.restart", bad); code != ExitRefused {
			t.Errorf("supervisor.restart %q: exit %d", bad, code)
		}
	}
	if h.ran("supervisorctl", "restart", "ghost") {
		t.Fatal("restarted a program that does not exist")
	}
	for _, r := range h.runs {
		if r[0] == "supervisorctl" && (len(r) < 3 || r[1] != "-c" || r[2] != "/etc/supervisor/supervisord.conf") {
			t.Errorf("supervisorctl ran without the root-owned config: %v", r)
		}
	}

	// A settings file that is not root-owned, or that others can write, is refused.
	h = newHost()
	h.uids["/etc/supervisor/supervisord.conf"] = 1000
	if code, _, _ := priv(h, "supervisor-status"); code != ExitRefused || h.ran("supervisorctl") {
		t.Fatalf("user-owned config: exit %d, runs %v", code, h.runs)
	}
	h = newHost()
	h.fsys["etc/supervisor/supervisord.conf"] = &fstest.MapFile{Data: []byte("x"), Mode: 0o666}
	if code, _, _ := priv(h, "supervisor-status"); code != ExitRefused || h.ran("supervisorctl") {
		t.Fatalf("world-writable config: exit %d, runs %v", code, h.runs)
	}
	h = newHost()
	delete(h.fsys, "etc/supervisor/supervisord.conf")
	if code, _, _ := priv(h, "supervisor-status"); code != ExitRefused || h.ran("supervisorctl") {
		t.Fatalf("no config: exit %d, runs %v", code, h.runs)
	}
}

func webErrorsOutput(t *testing.T, h *fakeHost) []webErrorLog {
	t.Helper()
	code, out, stderr := priv(h, "web-errors")
	if code != ExitOK {
		t.Fatalf("exit %d %q", code, stderr)
	}
	var logs []webErrorLog
	if err := json.Unmarshal([]byte(out), &logs); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	return logs
}

func TestPriv_WebErrors_ReadsTheLastLinesOfWebServerErrorLogs(t *testing.T) {
	h := newHost()
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, "nginx line %d\n", i)
	}
	h.fsys["var/log/nginx/error.log"] = &fstest.MapFile{Data: []byte(sb.String())}
	h.fsys["var/log/apache2/error.log"] = &fstest.MapFile{Data: []byte("apache one\napache two\n")}
	logs := webErrorsOutput(t, h)
	if len(logs) != 2 || logs[0].Path != "/var/log/nginx/error.log" || logs[1].Path != "/var/log/apache2/error.log" {
		t.Fatalf("logs = %+v", logs)
	}
	lines := strings.Split(logs[0].Text, "\n")
	if len(lines) != 200 || lines[199] != "nginx line 499" || lines[0] != "nginx line 300" {
		t.Fatalf("nginx tail has %d lines, first %q last %q", len(lines), lines[0], lines[len(lines)-1])
	}
	if logs[1].Text != "apache one\napache two" {
		t.Fatalf("apache text = %q", logs[1].Text)
	}
	// Nothing to read is an empty list, not a failure.
	if got := webErrorsOutput(t, newHost()); len(got) != 0 {
		t.Fatalf("empty host returned %+v", got)
	}
}

func TestPriv_WebErrors_LimitsBytes(t *testing.T) {
	h := newHost()
	line := strings.Repeat("x", 99) + "\n"
	h.fsys["var/log/nginx/error.log"] = &fstest.MapFile{Data: []byte(strings.Repeat(line, 2000))}
	logs := webErrorsOutput(t, h)
	if len(logs) != 1 || len(logs[0].Text) > 64*1024 {
		t.Fatalf("got %d logs, %d bytes", len(logs), len(logs[0].Text))
	}
	for _, l := range strings.Split(logs[0].Text, "\n") {
		if len(l) != 99 {
			t.Fatalf("a line was cut in half: %d bytes", len(l))
		}
	}
}

func TestPriv_WebErrors_FollowsConfiguredPathsOnlyUnderVarLog(t *testing.T) {
	h := newHost()
	h.fsys["etc/nginx/nginx.conf"] = &fstest.MapFile{Data: []byte("error_log /var/log/custom/web.log warn;\n")}
	h.fsys["etc/apache2/apache2.conf"] = &fstest.MapFile{Data: []byte("ErrorLog ${APACHE_LOG_DIR}/site-error.log\nErrorLog /etc/shadow\n")}
	h.fsys["var/log/custom/web.log"] = &fstest.MapFile{Data: []byte("custom\n")}
	h.fsys["var/log/apache2/site-error.log"] = &fstest.MapFile{Data: []byte("site\n")}
	h.fsys["etc/shadow"] = &fstest.MapFile{Data: []byte("root:secret\n")}
	h.fsys["var/log/auth.log"] = &fstest.MapFile{Data: []byte("sudo secrets\n")}
	logs := webErrorsOutput(t, h)
	var paths []string
	for _, l := range logs {
		paths = append(paths, l.Path)
		if strings.Contains(l.Text, "secret") {
			t.Fatalf("read a file outside the web error logs: %+v", l)
		}
	}
	if !reflect.DeepEqual(paths, []string{"/var/log/custom/web.log", "/var/log/apache2/site-error.log"}) {
		t.Fatalf("paths = %v", paths)
	}
}

func TestPriv_WebErrors_RefusesSymlinksAndNonRegularFiles(t *testing.T) {
	h := newHost()
	// The log is a link to the auth log.
	h.fsys["var/log/nginx/error.log"] = &fstest.MapFile{Data: []byte("sudo secrets\n"), Mode: fs.ModeSymlink}
	// A link in the folder path.
	h.fsys["var/log/apache2"] = &fstest.MapFile{Data: []byte("x"), Mode: fs.ModeSymlink}
	h.fsys["var/log/httpd/error_log"] = &fstest.MapFile{Data: nil, Mode: fs.ModeDir}
	if logs := webErrorsOutput(t, h); len(logs) != 0 {
		t.Fatalf("read %+v", logs)
	}
	if code, _, _ := priv(h, "web-errors", "extra"); code != ExitRefused {
		t.Fatalf("extra argument: exit %d, want refused", code)
	}
}

func TestPriv_WebErrors_RunsInPlace(t *testing.T) {
	h := newHost()
	h.hostNS = false
	if code, _, _ := priv(h, "web-errors"); code != ExitOK || len(h.reexec) != 0 {
		t.Fatalf("code %d reexec %v: read-only action must run in place", code, h.reexec)
	}
}
