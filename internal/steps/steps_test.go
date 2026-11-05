package steps

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestCatalog_IDsAndShape(t *testing.T) {
	want := []ID{
		"service.restart", "service.start", "service.stop", "service.reload",
		"container.restart", "compose.up", "pm2.restart", "nginx.reload",
		"phpfpm.restart", "supervisor.restart",
		"disk.journal_vacuum", "disk.docker_prune", "disk.apt_clean",
		"cert.renew", "process.stop", "firewall.allow", "firewall.remove", "check.http",
	}
	var got []ID
	for _, s := range Catalog() {
		d := s.Def()
		got = append(got, d.ID)
		if d.Title == "" || d.Description == "" || d.Verify == "" {
			t.Errorf("%s: missing title, description or verify text", d.ID)
		}
		if d.Params == nil {
			t.Errorf("%s: params must be [] not null", d.ID)
		}
		for _, p := range d.Params {
			if p.Enum == nil || (p.Type != "string" && p.Type != "integer") || p.Source == "" {
				t.Errorf("%s.%s: bad param %+v", d.ID, p.Name, p)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ids = %v", got)
	}
}

func TestCatalogJSON_Format(t *testing.T) {
	b, err := CatalogJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "}\n") || !strings.HasPrefix(string(b), "{\n  \"catalogVersion\": 1,\n  \"steps\": [\n    {\n      \"id\": \"service.restart\",") {
		t.Fatalf("unexpected format:\n%.200s", b)
	}
	if strings.Contains(string(b), "null") {
		t.Fatal("catalog contains null")
	}
	var doc struct {
		Steps []struct {
			ID   string `json:"id"`
			Root bool   `json:"root"`
			Undo string `json:"undo"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	root := map[string]bool{}
	for _, s := range doc.Steps {
		root[s.ID] = s.Root
	}
	for _, id := range []string{"container.restart", "compose.up", "disk.docker_prune", "check.http"} {
		if root[id] {
			t.Errorf("%s must not need root", id)
		}
	}
	for _, id := range []string{"service.restart", "pm2.restart", "nginx.reload", "cert.renew", "process.stop", "firewall.allow", "disk.apt_clean"} {
		if !root[id] {
			t.Errorf("%s must need root", id)
		}
	}
}

func TestUndoMapping(t *testing.T) {
	p := Params{"unit": "nginx.service"}
	id, up, ok := UndoOf(ServiceStartID, p)
	if !ok || id != ServiceStopID || up.String("unit") != "nginx.service" {
		t.Fatalf("start undo = %v %v %v", id, up, ok)
	}
	if id, _, ok := UndoOf(ServiceStopID, p); !ok || id != ServiceStartID {
		t.Fatalf("stop undo = %v", id)
	}
	fp := Params{"port": float64(8080), "proto": "tcp"}
	id, up, ok = UndoOf(FirewallAllowID, fp)
	if !ok || id != FirewallRemoveID || !reflect.DeepEqual(up, fp) {
		t.Fatalf("allow undo = %v %v", id, up)
	}
	if id, _, ok := UndoOf(FirewallRemoveID, fp); !ok || id != FirewallAllowID {
		t.Fatalf("remove undo = %v", id)
	}
	for _, none := range []ID{ServiceRestartID, ServiceReloadID, ContainerRestartID, ComposeUpID, PM2RestartID, NginxReloadID, PHPFPMRestartID,
		SupervisorRestartID, JournalVacuumID, DockerPruneID, AptCleanID, CertRenewID, ProcessStopID, CheckHTTPID} {
		if _, _, ok := UndoOf(none, p); ok {
			t.Errorf("%s must not be undoable", none)
		}
	}
	// The undo id in the catalog agrees with Undo().
	for _, s := range Catalog() {
		d := s.Def()
		undo, _, ok := s.Undo(Params{})
		if (d.Undo != "") != ok || (ok && undo != d.Undo) {
			t.Errorf("%s: catalog undo %q vs method %q/%v", d.ID, d.Undo, undo, ok)
		}
	}
}

func TestPrivArgs(t *testing.T) {
	cases := []struct {
		id   ID
		p    Params
		want []string
	}{
		{ServiceRestartID, Params{"unit": "nginx.service"}, []string{"nginx.service"}},
		{ServiceReloadID, Params{"unit": "php8.3-fpm"}, []string{"php8.3-fpm"}},
		{NginxReloadID, Params{}, []string{}},
		{PHPFPMRestartID, Params{"unit": "php8.3-fpm.service"}, []string{"php8.3-fpm.service"}},
		{SupervisorRestartID, Params{"program": "queue:queue_00"}, []string{"queue:queue_00"}},
		{JournalVacuumID, Params{"size": "200M"}, []string{"200M"}},
		{AptCleanID, Params{}, []string{}},
		{CertRenewID, Params{"name": "example.com"}, []string{"example.com"}},
		{PM2RestartID, Params{"user": "alice", "app": "api"}, []string{"alice", "api"}},
		{ProcessStopID, Params{"pid": float64(1234), "start_time": float64(99887)}, []string{"1234", "99887"}},
		{FirewallAllowID, Params{"port": float64(443), "proto": "tcp"}, []string{"443", "tcp"}},
		{FirewallRemoveID, Params{"port": 8080, "proto": "udp"}, []string{"8080", "udp"}},
	}
	for _, c := range cases {
		got, err := PrivArgs(c.id, c.p)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v err %v, want %v", c.id, got, err, c.want)
		}
	}
	bad := []struct {
		id ID
		p  Params
	}{
		{ServiceRestartID, Params{"unit": "sshd.service"}},
		{ServiceStopID, Params{"unit": "docker"}},
		{ServiceRestartID, Params{"unit": "-rf"}},
		{PHPFPMRestartID, Params{"unit": "nginx.service"}},
		{JournalVacuumID, Params{"size": "1G"}},
		{CertRenewID, Params{"name": "../../etc"}},
		{PM2RestartID, Params{"user": "a b", "app": "api"}},
		{ProcessStopID, Params{"pid": float64(1), "start_time": float64(5)}},
		{ProcessStopID, Params{"pid": float64(-1), "start_time": float64(5)}},
		{ProcessStopID, Params{"pid": float64(10), "start_time": float64(0)}},
		{ProcessStopID, Params{"pid": 10.5, "start_time": float64(5)}},
		{FirewallAllowID, Params{"port": float64(70000), "proto": "tcp"}},
		{FirewallAllowID, Params{"port": float64(80), "proto": "icmp"}},
		{CheckHTTPID, Params{"url": "http://x"}},
	}
	for _, c := range bad {
		if args, err := PrivArgs(c.id, c.p); err == nil || !IsRefused(err) {
			t.Errorf("%s %v: got %v %v, want refusal", c.id, c.p, args, err)
		}
	}
}

type fakeUnits struct {
	status  []UnitStatus // consumed in order, last repeats
	calls   []string
	actErr  error
	statErr error
}

func (f *fakeUnits) Action(_ context.Context, unit, verb string) error {
	f.calls = append(f.calls, verb+" "+unit)
	return f.actErr
}
func (f *fakeUnits) Status(context.Context, string) (UnitStatus, error) {
	if f.statErr != nil {
		return UnitStatus{}, f.statErr
	}
	s := f.status[0]
	if len(f.status) > 1 {
		f.status = f.status[1:]
	}
	return s, nil
}

type fakePriv struct {
	calls []string
	out   map[string]string
	err   error
}

func (f *fakePriv) Call(_ context.Context, action string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.TrimSpace(action+" "+strings.Join(args, " ")))
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.out[action]), nil
}

func newEnv(u *fakeUnits, p *fakePriv) *Env {
	return &Env{Units: u, Priv: p, Sleep: func(context.Context, time.Duration) {}, Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
}

func TestServiceSteps_RunAndVerify(t *testing.T) {
	ctx := context.Background()
	u := &fakeUnits{status: []UnitStatus{{LoadState: "loaded", ActiveState: "active", NRestarts: 2}}}
	r := &Runner{Env: newEnv(u, &fakePriv{})}
	if _, err := r.Execute(ctx, ServiceRestartID, Params{"unit": "api.service"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(u.calls, []string{"restart api.service"}) {
		t.Fatalf("calls %v", u.calls)
	}
	if err := r.Verify(ctx, ServiceRestartID, Params{"unit": "api.service"}); err != nil {
		t.Fatalf("stable service: %v", err)
	}

	// A service that restarts itself during the wait fails verification.
	u = &fakeUnits{status: []UnitStatus{{ActiveState: "active", NRestarts: 2}, {ActiveState: "active", NRestarts: 3}}}
	r = &Runner{Env: newEnv(u, &fakePriv{})}
	if err := r.Verify(ctx, ServiceRestartID, Params{"unit": "api.service"}); err == nil || !strings.Contains(err.Error(), "keeps restarting") {
		t.Fatalf("crash loop: %v", err)
	}
	// Start verifies "active", stop verifies "not active".
	u = &fakeUnits{status: []UnitStatus{{ActiveState: "failed"}}}
	r = &Runner{Env: newEnv(u, &fakePriv{})}
	if r.Verify(ctx, ServiceStartID, Params{"unit": "x.service"}) == nil {
		t.Fatal("start verify passed for a failed unit")
	}
	if err := r.Verify(ctx, ServiceStopID, Params{"unit": "x.service"}); err != nil {
		t.Fatalf("stop verify: %v", err)
	}
	u.status = []UnitStatus{{ActiveState: "active"}}
	if r.Verify(ctx, ServiceStopID, Params{"unit": "x.service"}) == nil {
		t.Fatal("stop verify passed for an active unit")
	}
}

func TestRunner_RefusesBeforeCallingAnything(t *testing.T) {
	ctx := context.Background()
	u := &fakeUnits{status: []UnitStatus{{LoadState: "loaded", ActiveState: "active"}}}
	p := &fakePriv{}
	r := &Runner{Env: newEnv(u, p)}
	for _, tc := range []struct {
		id ID
		p  Params
	}{
		{ServiceRestartID, Params{"unit": "sshd.service"}},
		{ServiceRestartID, Params{"unit": "docker.service"}},
		{ServiceStopID, Params{"unit": "../etc"}},
		{CertRenewID, Params{"name": "../x"}},
		{FirewallRemoveID, Params{"port": float64(0), "proto": "tcp"}},
		{"shell.exec", Params{"script": "id"}},
		{"", Params{}},
	} {
		_, err := r.Execute(ctx, tc.id, tc.p)
		if err == nil || !IsRefused(err) {
			t.Errorf("%s %v: err %v, want refusal", tc.id, tc.p, err)
		}
	}
	if len(u.calls) != 0 || len(p.calls) != 0 {
		t.Fatalf("something ran: %v %v", u.calls, p.calls)
	}
	// A unit that is not loaded is refused too.
	u.status = []UnitStatus{{LoadState: "not-found"}}
	if _, err := r.Execute(ctx, ServiceRestartID, Params{"unit": "ghost.service"}); !IsRefused(err) {
		t.Fatalf("missing unit: %v", err)
	}
}

func TestRootStepsGoThroughHelper(t *testing.T) {
	ctx := context.Background()
	p := &fakePriv{out: map[string]string{
		"certs-list":        `[{"name":"example.com","expiresAt":"2026-06-01T00:00:00Z"}]`,
		"pm2-list":          `[{"app":"api","status":"online","restarts":1}]`,
		"supervisor-status": `[{"name":"queue:q_00","state":"RUNNING"}]`,
		"firewall-rules":    `[{"port":8080,"proto":"tcp"}]`,
	}}
	u := &fakeUnits{status: []UnitStatus{{LoadState: "loaded", ActiveState: "active"}}}
	r := &Runner{Env: newEnv(u, p)}
	for _, tc := range []struct {
		id   ID
		p    Params
		want string
	}{
		{NginxReloadID, Params{}, "nginx.reload"},
		{PHPFPMRestartID, Params{"unit": "php8.3-fpm.service"}, "phpfpm.restart php8.3-fpm.service"},
		{JournalVacuumID, Params{"size": "100M"}, "disk.journal_vacuum 100M"},
		{AptCleanID, Params{}, "disk.apt_clean"},
		{CertRenewID, Params{"name": "example.com"}, "cert.renew example.com"},
		{PM2RestartID, Params{"user": "alice", "app": "api"}, "pm2.restart alice api"},
		{SupervisorRestartID, Params{"program": "queue"}, "supervisor.restart queue"},
		{FirewallAllowID, Params{"port": float64(8080), "proto": "tcp"}, "firewall.allow 8080 tcp"},
	} {
		p.calls = nil
		if _, err := r.Execute(ctx, tc.id, tc.p); err != nil {
			t.Errorf("%s: %v", tc.id, err)
			continue
		}
		if got := p.calls[len(p.calls)-1]; got != tc.want {
			t.Errorf("%s: last helper call %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestVerify_UsesReadOnlyHelperActions(t *testing.T) {
	ctx := context.Background()
	p := &fakePriv{out: map[string]string{
		"certs-list":     `[{"name":"example.com","expiresAt":"2026-03-01T00:00:00Z"},{"name":"new.com","expiresAt":"2026-06-01T00:00:00Z"}]`,
		"firewall-rules": `[{"port":8080,"proto":"tcp"}]`,
	}}
	u := &fakeUnits{status: []UnitStatus{{LoadState: "loaded", ActiveState: "active"}}}
	r := &Runner{Env: newEnv(u, p)}
	// 59 days away on the fake clock: fine. example.com is 59 days: wait, 2026-03-01 is 59 days: > 30.
	if err := r.Verify(ctx, CertRenewID, Params{"name": "example.com"}); err != nil {
		t.Fatalf("cert 59 days: %v", err)
	}
	p.out["certs-list"] = `[{"name":"example.com","expiresAt":"2026-01-20T00:00:00Z"}]`
	if err := r.Verify(ctx, CertRenewID, Params{"name": "example.com"}); err == nil {
		t.Fatal("cert 19 days passed verify")
	}
	if err := r.Verify(ctx, FirewallAllowID, Params{"port": float64(8080), "proto": "tcp"}); err != nil {
		t.Fatalf("rule present: %v", err)
	}
	if err := r.Verify(ctx, FirewallRemoveID, Params{"port": float64(8080), "proto": "tcp"}); err == nil {
		t.Fatal("remove verify passed while rule exists")
	}
	if err := r.Verify(ctx, FirewallRemoveID, Params{"port": float64(9090), "proto": "tcp"}); err != nil {
		t.Fatalf("rule absent: %v", err)
	}
	if err := r.Verify(ctx, NginxReloadID, Params{}); err != nil {
		t.Fatalf("nginx verify: %v", err)
	}
	if got := p.calls[len(p.calls)-1]; got != "nginx-test" {
		t.Fatalf("nginx verify did not run the config test: %v", p.calls)
	}
	p.err = errors.New("bad config")
	if err := r.Verify(ctx, NginxReloadID, Params{}); err == nil {
		t.Fatal("nginx verify passed with a failing test")
	}
}

type fakeProcs map[int]uint64

func (f fakeProcs) StartTime(pid int) (uint64, bool) { t, ok := f[pid]; return t, ok }

func TestProcessStop_ValidateAndVerify(t *testing.T) {
	ctx := context.Background()
	procs := fakeProcs{700: 30}
	r := &Runner{Env: &Env{Procs: procs, Priv: &fakePriv{}}}
	if err := r.Validate(ctx, ProcessStopID, Params{"pid": float64(700), "start_time": float64(30)}); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(ctx, ProcessStopID, Params{"pid": float64(700), "start_time": float64(31)}); !IsRefused(err) {
		t.Fatalf("start time mismatch: %v", err)
	}
	if err := r.Verify(ctx, ProcessStopID, Params{"pid": float64(700), "start_time": float64(30)}); err == nil {
		t.Fatal("verify passed while the process is alive")
	}
	delete(procs, 700)
	if err := r.Verify(ctx, ProcessStopID, Params{"pid": float64(700), "start_time": float64(30)}); err != nil {
		t.Fatal(err)
	}
	procs[700] = 55 // pid reused by another program
	if err := r.Verify(ctx, ProcessStopID, Params{"pid": float64(700), "start_time": float64(30)}); err != nil {
		t.Fatalf("reused pid counts as gone: %v", err)
	}
}

type fakeHTTP struct {
	status int
	got    []string
}

func (f *fakeHTTP) Get(_ context.Context, u string) (int, error) {
	f.got = append(f.got, u)
	return f.status, nil
}

func TestCheckHTTP(t *testing.T) {
	ctx := context.Background()
	h := &fakeHTTP{status: 200}
	env := &Env{HTTP: h, AllowedURL: func(u string) bool { return u == "https://app.example/health" }}
	r := &Runner{Env: env}
	if _, err := r.Execute(ctx, CheckHTTPID, Params{"url": "https://app.example/health"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"https://evil.example/", "http://169.254.169.254/", "file:///etc/passwd", "ftp://app.example/", "https://u:p@app.example/health", "not a url"} {
		if _, err := r.Execute(ctx, CheckHTTPID, Params{"url": bad}); !IsRefused(err) {
			t.Errorf("%q: %v, want refusal", bad, err)
		}
	}
	if len(h.got) != 1 {
		t.Fatalf("requests made: %v", h.got)
	}
	h.status = 302
	if err := r.Verify(ctx, CheckHTTPID, Params{"url": "https://app.example/health"}); err != nil {
		t.Fatalf("302 should pass: %v", err)
	}
	h.status = 502
	if err := r.Verify(ctx, CheckHTTPID, Params{"url": "https://app.example/health"}); err == nil {
		t.Fatal("502 passed")
	}
}

type fakeDocker struct {
	list     [][]ContainerInfo // consumed in order, last repeats
	restarts []string
	starts   []string
	freed    int64
	root     string
}

func (f *fakeDocker) Containers(context.Context) ([]ContainerInfo, error) {
	l := f.list[0]
	if len(f.list) > 1 {
		f.list = f.list[1:]
	}
	return l, nil
}
func (f *fakeDocker) Restart(_ context.Context, id string) error {
	f.restarts = append(f.restarts, id)
	return nil
}
func (f *fakeDocker) Start(_ context.Context, id string) error {
	f.starts = append(f.starts, id)
	return nil
}
func (f *fakeDocker) PruneDangling(context.Context) (int64, error) { return f.freed, nil }
func (f *fakeDocker) RootDir(context.Context) (string, error)      { return f.root, nil }

func TestContainerRestart(t *testing.T) {
	ctx := context.Background()
	d := &fakeDocker{list: [][]ContainerInfo{{{ID: "abc", Name: "web", State: "running", RestartCount: 1}}}}
	r := &Runner{Env: &Env{Docker: d, Sleep: func(context.Context, time.Duration) {}}}
	if _, err := r.Execute(ctx, ContainerRestartID, Params{"container": "web"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.restarts, []string{"abc"}) {
		t.Fatalf("restarts %v", d.restarts)
	}
	if err := r.Verify(ctx, ContainerRestartID, Params{"container": "web"}); err != nil {
		t.Fatal(err)
	}
	d.list = [][]ContainerInfo{{{ID: "abc", Name: "web", State: "running", RestartCount: 1}}, {{ID: "abc", Name: "web", State: "running", RestartCount: 2}}}
	if err := r.Verify(ctx, ContainerRestartID, Params{"container": "web"}); err == nil {
		t.Fatal("restart loop passed")
	}
	if _, err := r.Execute(ctx, ContainerRestartID, Params{"container": "ghost"}); !IsRefused(err) {
		t.Fatalf("missing container: %v", err)
	}
}

type recordingPriv struct{ calls [][]string }

func (r *recordingPriv) Call(_ context.Context, action string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{action}, args...))
	return []byte("ok\n"), nil
}

func TestComposeUp(t *testing.T) {
	ctx := context.Background()
	web := func(id, state, health string) ContainerInfo {
		return ContainerInfo{ID: id, Name: "shop-web-" + id, State: state, Health: health, ComposeProject: "shop", ComposeService: "web",
			Labels: map[string]string{labelComposeHash: "h1", labelComposeDir: "/srv/shop"}}
	}
	pc := &recordingPriv{}
	run := func(list ...ContainerInfo) (*fakeDocker, error) {
		d := &fakeDocker{list: [][]ContainerInfo{list}}
		r := &Runner{Env: &Env{Docker: d, Priv: pc, Sleep: func(context.Context, time.Duration) {}}}
		_, err := r.Execute(ctx, ComposeUpID, Params{"project": "shop", "service": "web"})
		return d, err
	}

	// Stopped containers are started through the Docker API, never through the helper.
	d, err := run(web("1", "exited", ""), web("2", "created", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.starts, []string{"1", "2"}) || len(d.restarts) != 0 {
		t.Fatalf("starts %v restarts %v", d.starts, d.restarts)
	}
	if len(pc.calls) != 0 {
		t.Fatalf("compose.up used the privilege helper: %v", pc.calls)
	}
	// Healthy running containers are left alone; unhealthy and restarting ones are restarted.
	d, err = run(web("1", "running", "healthy"), web("2", "running", "unhealthy"), web("3", "restarting", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.starts) != 0 || !reflect.DeepEqual(d.restarts, []string{"2", "3"}) {
		t.Fatalf("starts %v restarts %v", d.starts, d.restarts)
	}
	// One-off containers (docker compose run) are ignored.
	oneoff := web("9", "exited", "")
	oneoff.Labels = map[string]string{labelComposeOneoff: "True", labelComposeHash: "other", labelComposeDir: "/tmp"}
	if d, err = run(web("1", "exited", ""), oneoff); err != nil || !reflect.DeepEqual(d.starts, []string{"1"}) {
		t.Fatalf("oneoff: starts %v err %v", d.starts, err)
	}

	// Refusals: nothing is started.
	other := web("2", "exited", "")
	other.Labels = map[string]string{labelComposeHash: "h2", labelComposeDir: "/srv/shop"}
	otherDir := web("3", "exited", "")
	otherDir.Labels = map[string]string{labelComposeHash: "h1", labelComposeDir: "/tmp/evil"}
	noHash := web("4", "exited", "")
	noHash.Labels = map[string]string{labelComposeDir: "/srv/shop"}
	noDir := web("5", "exited", "")
	noDir.Labels = map[string]string{labelComposeHash: "h1"}
	for name, list := range map[string][]ContainerInfo{
		"mismatched config hash": {web("1", "exited", ""), other},
		"mismatched folder":      {web("1", "exited", ""), otherDir},
		"no config hash":         {noHash},
		"no project folder":      {noDir},
	} {
		d, err := run(list...)
		if !IsRefused(err) || len(d.starts) != 0 || len(d.restarts) != 0 {
			t.Errorf("%s: err %v starts %v restarts %v", name, err, d.starts, d.restarts)
		}
	}
	d, err = run()
	if !IsRefused(err) || err.Error() != "This service has no containers to start. Run docker compose up for this project yourself." {
		t.Fatalf("no containers: %v", err)
	}
	d = &fakeDocker{list: [][]ContainerInfo{{web("1", "exited", "")}}}
	r := &Runner{Env: &Env{Docker: d, Sleep: func(context.Context, time.Duration) {}}}
	if _, err := r.Execute(ctx, ComposeUpID, Params{"project": "-p", "service": "web"}); !IsRefused(err) {
		t.Fatalf("bad project: %v", err)
	}
	if _, err := r.Execute(ctx, ComposeUpID, Params{"project": "shop", "service": "ghost"}); !IsRefused(err) {
		t.Fatalf("unknown service: %v", err)
	}

	d = &fakeDocker{}
	r = &Runner{Env: &Env{Docker: d, Sleep: func(context.Context, time.Duration) {}}}
	v := func(state, health string) ContainerInfo { return web("abc", state, health) }

	// Verify waits while the health check is starting, then passes.
	d.list = [][]ContainerInfo{{v("running", "starting")}, {v("running", "starting")}, {v("running", "healthy")}}
	if err := r.Verify(ctx, ComposeUpID, Params{"project": "shop", "service": "web"}); err != nil {
		t.Fatalf("starting then healthy: %v", err)
	}
	// A container that is "running" but restarted during the settle wait fails.
	again := v("running", "")
	again.RestartCount = 1
	d.list = [][]ContainerInfo{{v("running", "")}, {again}}
	if r.Verify(ctx, ComposeUpID, Params{"project": "shop", "service": "web"}) == nil {
		t.Error("crash loop passed verify")
	}
	// Unhealthy, restarting and never-healthy all fail.
	for name, c := range map[string]ContainerInfo{
		"unhealthy":  v("running", "unhealthy"),
		"restarting": v("restarting", ""),
		"stuck":      v("running", "starting"),
	} {
		d.list = [][]ContainerInfo{{c}}
		if r.Verify(ctx, ComposeUpID, Params{"project": "shop", "service": "web"}) == nil {
			t.Errorf("%s verify passed", name)
		}
	}
}

// Each disk step is verified against the mount that holds the folder it frees
// space in, and the answer for another mount is ignored.
func TestDiskVerifyChecksTheMountOfTheFreedFolder(t *testing.T) {
	ctx := context.Background()
	used := map[string]float64{
		JournalDir:     90, // /var is full
		AptCacheDir:    90,
		"/data/docker": 40, // Docker lives on its own disk
		"/":            40,
	}
	var asked []string
	env := &Env{
		Docker: &fakeDocker{root: "/data/docker"},
		DiskPercentAt: func(_ context.Context, path string) (float64, error) {
			asked = append(asked, path)
			return used[path], nil
		},
	}
	r := &Runner{Env: env}
	if r.Verify(ctx, JournalVacuumID, Params{"size": "200M"}) == nil {
		t.Error("journal vacuum passed while the journal's disk is 90% full")
	}
	if r.Verify(ctx, AptCleanID, Params{}) == nil {
		t.Error("apt clean passed while the apt cache's disk is 90% full")
	}
	if err := r.Verify(ctx, DockerPruneID, Params{}); err != nil {
		t.Errorf("docker prune failed although Docker's own disk is 40%% full: %v", err)
	}
	if want := []string{JournalDir, AptCacheDir, "/data/docker"}; !reflect.DeepEqual(asked, want) {
		t.Errorf("checked %v, want %v", asked, want)
	}
	used[JournalDir], used[AptCacheDir], used["/data/docker"] = 60, 60, 90
	if err := r.Verify(ctx, JournalVacuumID, Params{"size": "200M"}); err != nil {
		t.Errorf("journal vacuum failed at 60%%: %v", err)
	}
	if r.Verify(ctx, DockerPruneID, Params{}) == nil {
		t.Error("docker prune passed while Docker's disk is 90% full")
	}
}

func TestDiskVerifyNeedsDockerRootDir(t *testing.T) {
	env := &Env{
		Docker:        &fakeDocker{},
		DiskPercentAt: func(context.Context, string) (float64, error) { return 10, nil },
	}
	if err := (&Runner{Env: env}).Verify(context.Background(), DockerPruneID, Params{}); err == nil {
		t.Fatal("verify passed without knowing where Docker keeps its data")
	}
}

const sampleMountinfo = `22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
30 22 0:25 / /var/lib/docker rw - ext4 /dev/sdb1 rw
31 22 0:26 / /var/log rw - ext4 /dev/sdc1 rw
32 22 0:27 / /mnt/my\040disk rw - ext4 /dev/sdd1 rw
33 22 0:28 / /var/log/journal rw - ext4 /dev/sde1 rw
`

func TestMountPointFrom_PicksTheDeepestMountThatContainsThePath(t *testing.T) {
	for path, want := range map[string]string{
		"/var/cache/apt":          "/",
		"/var/lib/docker":         "/var/lib/docker",
		"/var/lib/docker/overlay": "/var/lib/docker",
		"/var/lib/dockerx":        "/",
		"/var/log/journal":        "/var/log/journal",
		"/var/log/nginx":          "/var/log",
		"/mnt/my disk/x":          "/mnt/my disk",
	} {
		got, err := mountPointFrom(sampleMountinfo, path)
		if err != nil || got != want {
			t.Errorf("mountPointFrom(%q) = %q, %v; want %q", path, got, err, want)
		}
	}
	if _, err := mountPointFrom("", "/x"); err == nil {
		t.Error("an empty mount table must be an error")
	}
}

// On a Linux host (a container whose root is an overlay included) the root
// filesystem is always readable through statfs.
func TestDiskPercentAtPath_ReadsTheContainingMount(t *testing.T) {
	if _, err := os.Stat("/proc/self/mountinfo"); err != nil {
		t.Skip("needs /proc/self/mountinfo")
	}
	pct, err := DiskPercentAtPath(t.TempDir())
	if err != nil || pct <= 0 || pct > 100 {
		t.Fatalf("DiskPercentAtPath = %v, %v", pct, err)
	}
	// A folder that does not exist yet still resolves to its mount.
	if _, err := DiskPercentAtPath("/var/lib/docker/does/not/exist"); err != nil {
		t.Fatalf("missing folder: %v", err)
	}
}

func TestParseHelpers(t *testing.T) {
	for _, s := range []string{"-1", "0", "1", "+5", "0x10", " 5", "5 ", "", "99999999999999999999"} {
		if _, err := ParsePID(s); err == nil {
			t.Errorf("ParsePID(%q) accepted", s)
		}
	}
	if n, err := ParsePID("1234"); err != nil || n != 1234 {
		t.Fatalf("ParsePID(1234) = %d %v", n, err)
	}
	comm, state, ppid, start, ok := ParseProcStat("123 (my (weird) app) S 1 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 100 18446744073709551615")
	if !ok || comm != "my (weird) app" || state != "S" || ppid != 1 || start != 98765 {
		t.Fatalf("ParseProcStat = %q %q %d %d %v", comm, state, ppid, start, ok)
	}
}

// Every pattern in the catalog must compile (Watchtower compiles them too).
func TestCatalog_PatternsCompile(t *testing.T) {
	for _, s := range Catalog() {
		for _, p := range s.Def().Params {
			if p.Pattern == "" {
				continue
			}
			if _, err := regexp.Compile(p.Pattern); err != nil {
				t.Errorf("%s.%s: pattern %q: %v", s.Def().ID, p.Name, p.Pattern, err)
			}
		}
	}
}
