package webserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

type fakeSystemd struct {
	status  systemd.Status
	units   []systemd.Unit
	actions []string
	err     error
}

func (f *fakeSystemd) Status(context.Context) systemd.Status {
	if f.status.Available || f.status.UnavailableReason != "" || f.status.UnavailableMessage != "" {
		return f.status
	}
	return systemd.Status{Available: true}
}

func (f *fakeSystemd) List(context.Context) ([]systemd.Unit, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]systemd.Unit(nil), f.units...), nil
}

func (f *fakeSystemd) Action(_ context.Context, name string, action systemd.Action) error {
	f.actions = append(f.actions, name+":"+string(action))
	return f.err
}

type fakeRunner struct {
	output string
	err    error
	calls  []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.output, f.err
}

type fakePrivilegedRunner struct {
	fakeRunner
	privilegedCalls []string
}

func (f *fakePrivilegedRunner) RunPrivileged(_ context.Context, name string, args ...string) (string, error) {
	f.privilegedCalls = append(f.privilegedCalls, name+" "+strings.Join(args, " "))
	return f.output, f.err
}

func write(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestListExtractsDomainsFromCaddyNginxApache(t *testing.T) {
	dir := t.TempDir()
	caddy := write(t, filepath.Join(dir, "caddy", "Caddyfile"), `
example.com, www.example.com {
	reverse_proxy :3000
}
:443 {
	respond ok
}
localhost {
	respond ok
}
`)
	nginx := write(t, filepath.Join(dir, "nginx", "sites-enabled", "app.conf"), `
server {
	server_name app.example.com api.example.com localhost _;
}
`)
	apache := write(t, filepath.Join(dir, "apache2", "sites-enabled", "app.conf"), `
<VirtualHost *:80>
	ServerName old.example.com
	ServerAlias www.old.example.com localhost
</VirtualHost>
`)
	mgr, err := New(Config{
		Systemd: &fakeSystemd{units: []systemd.Unit{
			{Name: "caddy.service", Description: "Caddy", ActiveState: "active", EnabledOnBoot: "enabled"},
			{Name: "nginx.service", Description: "Nginx", ActiveState: "active", EnabledOnBoot: "enabled"},
			{Name: "apache2.service", Description: "Apache", ActiveState: "inactive", EnabledOnBoot: "disabled"},
		}},
		Paths: map[Kind][]string{
			KindCaddy:  {caddy},
			KindNginx:  {nginx},
			KindApache: {apache},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mgr.List(context.Background())
	if !got.Available || len(got.Webservers) != 3 {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	hosts := map[string]bool{}
	for _, ws := range got.Webservers {
		for _, d := range ws.Domains {
			hosts[d.Host] = true
			if d.SourcePath == "" || d.Line == 0 {
				t.Fatalf("domain missing source: %+v", d)
			}
		}
	}
	for _, want := range []string{"example.com", "www.example.com", "app.example.com", "api.example.com", "old.example.com", "www.old.example.com"} {
		if !hosts[want] {
			t.Fatalf("missing host %s in %+v", want, hosts)
		}
	}
	if hosts["localhost"] || hosts["_"] {
		t.Fatalf("filtered host leaked: %+v", hosts)
	}
}

func TestListFollowsOneLevelIncludesAndWarnsOnNested(t *testing.T) {
	dir := t.TempDir()
	root := write(t, filepath.Join(dir, "nginx", "sites-enabled", "root.conf"), `
include child/*.conf;
server { server_name root.example.com; }
`)
	child := write(t, filepath.Join(dir, "nginx", "sites-enabled", "child", "app.conf"), `
include grandchild/*.conf;
server_name child.example.com;
`)
	write(t, filepath.Join(dir, "nginx", "sites-enabled", "child", "grandchild", "ignored.conf"), `server_name ignored.example.com;`)
	mgr, err := New(Config{
		Systemd: &fakeSystemd{units: []systemd.Unit{{Name: "nginx.service"}}},
		Paths:   map[Kind][]string{KindNginx: {root}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mgr.List(context.Background())
	var nginx Instance
	for _, inst := range got.Webservers {
		if inst.Kind == KindNginx {
			nginx = inst
		}
	}
	hosts := map[string]bool{}
	for _, d := range nginx.Domains {
		hosts[d.Host] = true
	}
	if !hosts["child.example.com"] || hosts["ignored.example.com"] {
		t.Fatalf("include depth mismatch, child=%s domains=%+v warnings=%+v", child, nginx.Domains, nginx.Warnings)
	}
	if len(nginx.Warnings) == 0 || !strings.Contains(strings.Join(nginx.Warnings, "\n"), "nested include ignored") {
		t.Fatalf("missing nested include warning: %+v", nginx.Warnings)
	}
}

func TestMissingConfigPathProducesWarning(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "Caddyfile")
	mgr, err := New(Config{
		Systemd: &fakeSystemd{units: []systemd.Unit{{Name: "caddy.service"}}},
		Paths:   map[Kind][]string{KindCaddy: {missing}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mgr.List(context.Background())
	if len(got.Warnings) == 0 || !strings.Contains(got.Warnings[0], "config path missing") {
		t.Fatalf("missing warning not surfaced: %+v", got.Warnings)
	}
}

func TestListMatchesHomebrewLaunchdWebserverUnits(t *testing.T) {
	dir := t.TempDir()
	caddy := write(t, filepath.Join(dir, "Caddyfile"), `mac.example.com { respond ok }`)
	mgr, err := New(Config{
		Systemd: &fakeSystemd{units: []systemd.Unit{
			{Name: "homebrew.mxcl.caddy", Description: "Caddy", ActiveState: "active", EnabledOnBoot: "loaded"},
		}},
		Paths: map[Kind][]string{KindCaddy: {caddy}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mgr.List(context.Background())
	if len(got.Webservers) != 1 {
		t.Fatalf("webservers=%+v", got.Webservers)
	}
	if got.Webservers[0].ID != "caddy:homebrew.mxcl.caddy" || got.Webservers[0].Domains[0].Host != "mac.example.com" {
		t.Fatalf("homebrew launchd instance not mapped: %+v", got.Webservers[0])
	}
}

func TestValidateReturnsFailureOutputWithoutAction(t *testing.T) {
	dir := t.TempDir()
	caddy := write(t, filepath.Join(dir, "Caddyfile"), `example.com { respond ok }`)
	runner := &fakePrivilegedRunner{fakeRunner: fakeRunner{output: "bad config", err: errors.New("exit 1")}}
	mgr, err := New(Config{
		Systemd: &fakeSystemd{units: []systemd.Unit{{Name: "caddy.service"}}},
		Runner:  runner,
		Paths:   map[Kind][]string{KindCaddy: {caddy}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Validate(context.Background(), "caddy:caddy.service")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Output != "bad config" {
		t.Fatalf("unexpected validate result: %+v", res)
	}
	if len(runner.privilegedCalls) != 1 || !strings.Contains(runner.privilegedCalls[0], "caddy validate --config") {
		t.Fatalf("wrong validation command: %+v", runner.privilegedCalls)
	}
}

func TestActionAllowsOnlyReloadRestart(t *testing.T) {
	sys := &fakeSystemd{units: []systemd.Unit{{Name: "nginx.service"}}}
	mgr, err := New(Config{Systemd: sys, Paths: map[Kind][]string{KindNginx: nil}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Action(context.Background(), "nginx:nginx.service", "start"); err == nil {
		t.Fatal("expected unsupported action error")
	}
	if _, err := mgr.Action(context.Background(), "nginx:nginx.service", "reload"); err != nil {
		t.Fatal(err)
	}
	if len(sys.actions) != 1 || sys.actions[0] != "nginx.service:reload" {
		t.Fatalf("wrong action calls: %+v", sys.actions)
	}
}
