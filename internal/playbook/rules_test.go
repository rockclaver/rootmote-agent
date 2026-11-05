package playbook

import (
	"context"
	"strings"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/steps"
)

func baseInventory() Inventory {
	return Inventory{
		Units:              []string{"nginx.service", "demo-api.service", "php8.3-fpm.service", "mysql.service", "systemd-journald.service", "docker.service"},
		Containers:         []string{"shop-web-1", "worker"},
		ComposeServices:    []ComposePair{{Project: "shop", Service: "web"}},
		PM2Apps:            []PM2App{{User: "ubuntu", App: "worker"}},
		SupervisorPrograms: []string{"queue"},
		Certs:              []string{"shop.example.com"},
		URLs:               []string{"https://shop.example.com/", "http://shop.example.com/"},
		Ports:              []int{80, 443, 3000},
	}
}

func stepIDs(pb Playbook) []steps.ID {
	var ids []steps.ID
	for _, s := range pb.Steps {
		ids = append(ids, s.Step)
	}
	return ids
}

func equalIDs(a, b []steps.ID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func manualText(pb Playbook) string {
	var parts []string
	for _, m := range pb.Manual {
		parts = append(parts, m.Text+" "+m.Command)
	}
	return strings.Join(parts, "\n")
}

func mustCheck(t *testing.T, pb Playbook, inv Inventory) {
	t.Helper()
	if err := Check(context.Background(), &pb, inv, nil); err != nil {
		t.Fatalf("catalog playbook fails its own check: %v\n%+v", err, pb)
	}
}

func TestFromSignature_ContainerRestartLoop_PlainContainer(t *testing.T) {
	b := diagnose.Bundle{
		Components: []diagnose.Component{{ID: "cmp_docker_worker", Kind: "docker_container", Name: "worker", State: "restarting"}},
		Signals:    []diagnose.Signal{{ID: "sig_container_restart_loop", Type: "container_restart_loop", Value: 7, Subject: "worker"}},
	}
	f := Facts{Inventory: baseInventory(), Bundle: b}
	pb, ok := FromBundle(f)
	if !ok {
		t.Fatal("no playbook for a restart loop")
	}
	if !equalIDs(stepIDs(pb), []steps.ID{steps.ContainerRestartID}) || pb.Steps[0].Params.String("container") != "worker" {
		t.Fatalf("steps = %+v, want container.restart worker", pb.Steps)
	}
	if pb.Source != "catalog" || pb.Title == "" {
		t.Fatalf("source/title = %q/%q", pb.Source, pb.Title)
	}
	if strings.Contains(manualText(pb), "last deploy") {
		t.Fatal("deploy hint added although no recent deployment signature fired")
	}
	mustCheck(t, pb, f.Inventory)
}

func TestFromSignature_ContainerStoppedComposeServiceWithRecentDeploy(t *testing.T) {
	b := diagnose.Bundle{
		Components: []diagnose.Component{{
			ID: "cmp_docker_shop-web-1", Kind: "docker_container", Name: "shop-web-1", State: "exited",
			ComposeProject: "shop", ComposeService: "web",
		}},
		RecentChanges: []diagnose.Change{{ID: "chg_container_restart_1", Type: "container_restart", Detail: "shop-web-1 restarted (2 recorded restarts)"}},
	}
	f := Facts{Inventory: baseInventory(), Bundle: b}
	pb, ok := FromBundle(f)
	if !ok {
		t.Fatal("no playbook for a stopped container")
	}
	if !equalIDs(stepIDs(pb), []steps.ID{steps.ComposeUpID}) {
		t.Fatalf("steps = %v, want compose.up", stepIDs(pb))
	}
	if pb.Steps[0].Params.String("project") != "shop" || pb.Steps[0].Params.String("service") != "web" {
		t.Fatalf("params = %v", pb.Steps[0].Params)
	}
	if !strings.Contains(manualText(pb), "Check the last deploy") {
		t.Fatalf("manual = %q, want the deploy hint", manualText(pb))
	}
	mustCheck(t, pb, f.Inventory)
}

func TestFromSignature_ContainerNotInInventoryHasNoPlaybook(t *testing.T) {
	b := diagnose.Bundle{Components: []diagnose.Component{{ID: "c1", Kind: "docker_container", Name: "ghost", State: "exited"}}}
	if _, ok := FromBundle(Facts{Inventory: baseInventory(), Bundle: b}); ok {
		t.Fatal("playbook built for a container that is not in the inventory")
	}
}

func TestFromSignature_UnitFailed(t *testing.T) {
	cases := []struct {
		unit string
		want steps.ID
	}{
		{"demo-api.service", steps.ServiceRestartID},
		{"php8.3-fpm.service", steps.PHPFPMRestartID},
	}
	for _, tc := range cases {
		b := diagnose.Bundle{Components: []diagnose.Component{{ID: "cmp_systemd", Kind: "systemd_unit", Name: tc.unit, State: "failed"}}}
		f := Facts{Inventory: baseInventory(), Bundle: b}
		pb, ok := FromBundle(f)
		if !ok {
			t.Fatalf("%s: no playbook", tc.unit)
		}
		if !equalIDs(stepIDs(pb), []steps.ID{tc.want}) || pb.Steps[0].Params.String("unit") != tc.unit {
			t.Fatalf("%s: steps = %+v, want %s", tc.unit, pb.Steps, tc.want)
		}
		mustCheck(t, pb, f.Inventory)
	}
}

func TestFromSignature_ProtectedOrUnknownUnitHasNoPlaybook(t *testing.T) {
	inv := baseInventory()
	inv.Units = append(inv.Units, "ssh.service")
	for _, unit := range []string{"ssh.service", "not-installed.service"} {
		b := diagnose.Bundle{Components: []diagnose.Component{{ID: "c", Kind: "systemd_unit", Name: unit, State: "failed"}}}
		if _, ok := FromBundle(Facts{Inventory: inv, Bundle: b}); ok {
			t.Fatalf("playbook built for %s", unit)
		}
	}
}

func TestFromSignature_OOMKillRestartsServiceAndExplainsWithExactNumbers(t *testing.T) {
	b := diagnose.Bundle{
		Signals: []diagnose.Signal{{ID: "sig_oom_kill", Type: "oom_kill", Value: 2, Subject: "mysqld", Detail: "2 OOM kill(s) in the last 30m0s, most recent: pid 5 process \"mysqld\""}},
		Metrics: []diagnose.Metric{
			{ID: "m1", Name: "memory_used_percent", Value: 97},
			{ID: "m2", Name: "memory_total_mb", Value: 960},
			{ID: "m3", Name: "swap_total_mb", Value: 0},
		},
	}
	f := Facts{Inventory: baseInventory(), Bundle: b}
	pb, ok := FromBundle(f)
	if !ok {
		t.Fatal("no playbook for an OOM kill")
	}
	if !equalIDs(stepIDs(pb), []steps.ID{steps.ServiceRestartID}) || pb.Steps[0].Params.String("unit") != "mysql.service" {
		t.Fatalf("steps = %+v, want service.restart mysql.service", pb.Steps)
	}
	text := manualText(pb)
	for _, want := range []string{"97%", "960 MB", "no swap", "swapon"} {
		if !strings.Contains(text, want) {
			t.Fatalf("manual steps %q miss %q", text, want)
		}
	}
	mustCheck(t, pb, f.Inventory)
}

func TestFromSignature_OOMKillWithUnknownProcessStaysManual(t *testing.T) {
	b := diagnose.Bundle{
		Signals: []diagnose.Signal{{ID: "sig_oom_kill", Type: "oom_kill", Value: 1, Subject: "mystery"}},
		Metrics: []diagnose.Metric{{ID: "m2", Name: "memory_total_mb", Value: 960}, {ID: "m1", Name: "memory_used_percent", Value: 91}},
	}
	f := Facts{Inventory: baseInventory(), Bundle: b}
	pb, ok := FromBundle(f)
	if !ok || len(pb.Steps) != 0 || len(pb.Manual) == 0 {
		t.Fatalf("pb = %+v ok=%v, want manual steps only", pb, ok)
	}
	if !strings.Contains(manualText(pb), "91% used out of 960 MB") {
		t.Fatalf("manual = %q", manualText(pb))
	}
}

// allOnRoot says every disk step frees space on "/" (a server with one disk).
var allOnRoot = map[steps.ID]string{steps.JournalVacuumID: "/", steps.DockerPruneID: "/", steps.AptCleanID: "/"}

func TestFromSignature_DiskExhaustedPicksOnlyApplicableCleanups(t *testing.T) {
	signals := []diagnose.Signal{
		{ID: "s1", Type: "large_directory", Value: 5120, Subject: "/var/lib/docker"},
		{ID: "s2", Type: "large_directory", Value: 900, Subject: "/var/log"},
	}
	metrics := []diagnose.Metric{{ID: "met_disk_used_percent_root", Name: "disk_used_percent", Value: 95, Subject: "/"}}

	full := Facts{DiskMounts: allOnRoot, Inventory: baseInventory(), OS: OSInfo{Distro: "ubuntu"}, Bundle: diagnose.Bundle{Signals: signals, Metrics: metrics}}
	pb, ok := FromBundle(full)
	if !ok {
		t.Fatal("no playbook for a full disk")
	}
	if !equalIDs(stepIDs(pb), []steps.ID{steps.JournalVacuumID, steps.DockerPruneID, steps.AptCleanID}) {
		t.Fatalf("steps = %v, want journal, docker, apt", stepIDs(pb))
	}
	if !strings.Contains(manualText(pb), "1. /var/lib/docker (5120 MB)") || !strings.Contains(manualText(pb), "2. /var/log (900 MB)") {
		t.Fatalf("manual = %q, want the biggest directories with sizes", manualText(pb))
	}
	mustCheck(t, pb, full.Inventory)

	// No Docker containers and not a Debian family system: only the journal.
	inv := baseInventory()
	inv.Containers, inv.ComposeServices = nil, nil
	lean := Facts{DiskMounts: allOnRoot, Inventory: inv, OS: OSInfo{Distro: "rocky"}, Bundle: diagnose.Bundle{Signals: signals, Metrics: metrics}}
	pb, _ = FromBundle(lean)
	if !equalIDs(stepIDs(pb), []steps.ID{steps.JournalVacuumID}) {
		t.Fatalf("lean steps = %v, want only the journal", stepIDs(pb))
	}
}

func TestFromSignature_InodeExhaustedAlsoCleans(t *testing.T) {
	f := Facts{DiskMounts: allOnRoot, Inventory: baseInventory(), OS: OSInfo{Distro: "debian"}, Bundle: diagnose.Bundle{
		Metrics: []diagnose.Metric{{ID: "met_inode_used_percent_root", Name: "inode_used_percent", Value: 96, Subject: "/"}},
	}}
	pb, ok := FromBundle(f)
	if !ok || len(pb.Steps) == 0 {
		t.Fatalf("pb = %+v ok=%v", pb, ok)
	}
	if !strings.Contains(manualText(pb), "du -xh") {
		t.Fatalf("with no directory evidence the manual step gives the command to find them: %q", manualText(pb))
	}
}

// A full /data disk: the journal and the package cache are on "/", Docker is
// on /data. Only the step that frees space on /data is offered.
func TestFromSignature_DiskStepsOnlyOnTheMountThatFired(t *testing.T) {
	mounts := map[steps.ID]string{steps.JournalVacuumID: "/", steps.AptCleanID: "/", steps.DockerPruneID: "/data"}
	metrics := []diagnose.Metric{{ID: "m", Name: "disk_used_percent", Value: 95, Subject: "/data"}}
	signals := []diagnose.Signal{{ID: "s1", Type: "large_directory", Value: 4096, Subject: "/data/uploads"}}
	f := Facts{DiskMounts: mounts, Inventory: baseInventory(), OS: OSInfo{Distro: "ubuntu"}, Bundle: diagnose.Bundle{Metrics: metrics, Signals: signals}}
	pb, ok := FromBundle(f)
	if !ok || !equalIDs(stepIDs(pb), []steps.ID{steps.DockerPruneID}) {
		t.Fatalf("steps = %v (ok=%v), want only docker prune", stepIDs(pb), ok)
	}
	mustCheck(t, pb, f.Inventory)

	// Nothing frees space on /data: no steps, and the manual step names the
	// mount and its biggest folders.
	mounts[steps.DockerPruneID] = "/"
	pb, ok = FromBundle(f)
	if !ok || len(pb.Steps) != 0 {
		t.Fatalf("steps = %v (ok=%v), want none", stepIDs(pb), ok)
	}
	text := manualText(pb)
	if !strings.Contains(text, "/data") || !strings.Contains(text, "1. /data/uploads (4096 MB)") {
		t.Fatalf("manual = %q, want the mount and its biggest folders", text)
	}
	mustCheck(t, pb, f.Inventory)

	// Unknown mounts are never guessed: nothing is offered.
	f.DiskMounts = nil
	if pb, _ := FromBundle(f); len(pb.Steps) != 0 {
		t.Fatalf("steps = %v, want none when mounts are unknown", stepIDs(pb))
	}
}

func TestFromSignature_CertificateExpiring(t *testing.T) {
	b := diagnose.Bundle{Components: []diagnose.Component{{ID: "cmp_cert_shop", Kind: "certificate", Name: "shop.example.com", State: "expiring", Detail: "shop.example.com expires in 9 days"}}}
	f := Facts{Inventory: baseInventory(), Bundle: b}
	pb, ok := FromBundle(f)
	if !ok || !equalIDs(stepIDs(pb), []steps.ID{steps.CertRenewID}) || pb.Steps[0].Params.String("name") != "shop.example.com" {
		t.Fatalf("pb = %+v ok=%v, want cert.renew shop.example.com", pb, ok)
	}
	mustCheck(t, pb, f.Inventory)

	inv := baseInventory()
	inv.Certs = nil
	if _, ok := FromBundle(Facts{Inventory: inv, Bundle: b}); ok {
		t.Fatal("playbook built for a certificate that is not in the inventory")
	}
}

func TestFromSignature_ProxyUpstreamErrorRestartsUpstreamThenChecksAddress(t *testing.T) {
	b := diagnose.Bundle{
		Logs:       []diagnose.LogExcerpt{{ID: "log_proxy", Source: "proxy:error.log", Content: "connect() failed (111: Connection refused) while connecting to upstream"}},
		Components: []diagnose.Component{{ID: "cmp_upstream_unit_demo-api.service", Kind: "upstream_unit", Name: "demo-api.service"}},
	}
	f := Facts{Inventory: baseInventory(), Bundle: b, Target: "https://shop.example.com/"}
	pb, ok := FromBundle(f)
	if !ok {
		t.Fatal("no playbook for a proxy upstream error")
	}
	if !equalIDs(stepIDs(pb), []steps.ID{steps.ServiceRestartID, steps.CheckHTTPID}) {
		t.Fatalf("steps = %v, want service.restart then check.http", stepIDs(pb))
	}
	if pb.Steps[0].Params.String("unit") != "demo-api.service" || pb.Steps[1].Params.String("url") != "https://shop.example.com/" {
		t.Fatalf("params = %v / %v", pb.Steps[0].Params, pb.Steps[1].Params)
	}
	mustCheck(t, pb, f.Inventory)

	// A bare host target still finds an address on that host.
	f.Target = "shop.example.com"
	pb, _ = FromBundle(f)
	if pb.Steps[len(pb.Steps)-1].Params.String("url") != "https://shop.example.com/" {
		t.Fatalf("steps = %+v", pb.Steps)
	}
}

func TestFromSignature_ProxyUpstreamContainerAndUnknownBackend(t *testing.T) {
	logs := []diagnose.LogExcerpt{{ID: "log_proxy", Source: "proxy:error.log", Content: "502 Bad Gateway"}}
	withContainer := diagnose.Bundle{Logs: logs, Components: []diagnose.Component{{ID: "cmp_up", Kind: "upstream_container", Name: "worker"}}}
	pb, ok := FromBundle(Facts{Inventory: baseInventory(), Bundle: withContainer})
	if !ok || !equalIDs(stepIDs(pb), []steps.ID{steps.ContainerRestartID}) {
		t.Fatalf("pb = %+v ok=%v, want container.restart (no check.http without a known address)", pb, ok)
	}
	unknown := diagnose.Bundle{Logs: logs, Components: []diagnose.Component{{ID: "cmp_up", Kind: "upstream_address", Name: "127.0.0.1:3999"}}}
	if _, ok := FromBundle(Facts{Inventory: baseInventory(), Bundle: unknown}); ok {
		t.Fatal("playbook built although the backend is not a known service")
	}
}

func TestFromSignature_PM2AppStopped(t *testing.T) {
	b := diagnose.Bundle{Components: []diagnose.Component{{ID: "cmp_pm2_ubuntu_worker", Kind: "pm2_app", Name: "worker", State: "stopped", Owner: "ubuntu"}}}
	f := Facts{Inventory: baseInventory(), Bundle: b}
	pb, ok := FromBundle(f)
	if !ok || !equalIDs(stepIDs(pb), []steps.ID{steps.PM2RestartID}) {
		t.Fatalf("pb = %+v ok=%v, want pm2.restart", pb, ok)
	}
	if pb.Steps[0].Params.String("app") != "worker" || pb.Steps[0].Params.String("user") != "ubuntu" {
		t.Fatalf("params = %v", pb.Steps[0].Params)
	}
	mustCheck(t, pb, f.Inventory)

	other := diagnose.Bundle{Components: []diagnose.Component{{ID: "c", Kind: "pm2_app", Name: "worker", State: "stopped", Owner: "deploy"}}}
	if _, ok := FromBundle(Facts{Inventory: baseInventory(), Bundle: other}); ok {
		t.Fatal("playbook built for a PM2 app owned by a user the inventory does not list")
	}
}

func TestFromBundle_NothingMatchesGivesNoPlaybook(t *testing.T) {
	if _, ok := FromBundle(Facts{Inventory: baseInventory()}); ok {
		t.Fatal("playbook built from no evidence")
	}
}

func TestFromBundle_OwnServiceBeatsUnrelatedOOMKill(t *testing.T) {
	f := Facts{
		Inventory: baseInventory(),
		Bundle:    diagnose.Bundle{Service: diagnose.Service{Name: "demo-api.service", Kind: "systemd_unit"}},
		Signatures: []diagnose.Signature{
			{Type: "oom_kill", Confidence: 1.0, Subject: "java", Detail: "1 OOM kill"},
			{Type: "unit_failed", Confidence: 0.85, Subject: "demo-api.service"},
		},
	}
	pb, ok := FromBundle(f)
	if !ok {
		t.Fatal("no playbook")
	}
	if !equalIDs(stepIDs(pb), []steps.ID{steps.ServiceRestartID}) {
		t.Fatalf("steps = %v, want one service.restart (unrelated OOM kill won)", stepIDs(pb))
	}
}

func TestFromBundle_ProxyIncidentIgnoresUnrelatedFullDisk(t *testing.T) {
	f := Facts{
		Inventory: baseInventory(),
		Bundle:    diagnose.Bundle{Service: diagnose.Service{Name: "https://shop.example.com/", Kind: "external_http"}},
		Signatures: []diagnose.Signature{
			{Type: "disk_exhausted", Confidence: 0.95, Subject: "/data", Title: "Disk usage at 96.0%"},
			{Type: "proxy_upstream_error", Confidence: 0.8, Subject: "unit:demo-api.service"},
		},
	}
	pb, ok := FromBundle(f)
	for _, id := range stepIDs(pb) {
		if id == steps.AptCleanID || id == steps.DockerPruneID || id == steps.JournalVacuumID {
			t.Fatalf("a proxy incident got a disk playbook: %v (ok=%v)", stepIDs(pb), ok)
		}
	}
}

func TestFromBundle_DiskIncidentStillGetsDiskPlaybook(t *testing.T) {
	f := Facts{
		Inventory:  baseInventory(),
		DiskMounts: allOnRoot,
		OS:         OSInfo{Distro: "ubuntu"},
		Bundle:     diagnose.Bundle{Service: diagnose.Service{Name: "/", Kind: "disk_capacity"}},
		Signatures: []diagnose.Signature{
			{Type: "disk_exhausted", Confidence: 0.95, Subject: "/", Title: "Disk usage at 96.0%"},
		},
	}
	if _, ok := FromBundle(f); !ok {
		t.Fatal("disk incident lost its disk playbook")
	}
}
