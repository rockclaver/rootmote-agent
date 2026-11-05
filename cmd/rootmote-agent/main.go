package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/monitor"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/server"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/version"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pairing-key" {
		printPairingKey(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "priv" {
		os.Exit(runPriv(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "steps" {
		os.Exit(runSteps(os.Args[2:], os.Stdout))
	}
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for agent state")
	requirePairing := flag.Bool("require-pairing", true, "require the mobile app to present the control-plane pairing key on the WebSocket; disable only for local development")
	watchtowerRelayURL := flag.String("watchtower-relay-url", envOr("ROOTMOTE_WATCHTOWER_RELAY_URL", ""), "base URL of the Watchtower relay (github.com/rockclaver/rootmote-watchtower); starts the outbound heartbeat loop at boot. Leave empty to stay opt-out until enrolled via the watchtower.enable control-plane kind (also auto-resumes at boot if a prior enrollment's cred file exists)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		// Phase 1 AC: bootstrap "prints the installed version on stdout".
		_, _ = os.Stdout.WriteString(version.Version + "\n")
		return
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("rootmote-agent: mkdir data-dir: %v", err)
	}
	controlPlaneKey, err := loadOrCreateControlPlaneKey(*dataDir)
	if err != nil {
		log.Fatalf("rootmote-agent: control-plane key: %v", err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "state.db"))
	if err != nil {
		log.Fatalf("rootmote-agent: open state store: %v", err)
	}
	defer st.Close()

	removeRetiredCredentials(*dataDir)
	reviewMgr := review.New(st)
	diagnoseRedactor, err := redact.New(nil)
	if err != nil {
		log.Fatalf("rootmote-agent: init redaction rules: %v", err)
	}
	dockerMgr, err := docker.New(docker.Config{
		Client: docker.NewSocketClient(""),
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init docker: %v", err)
	}
	infraMgr, err := infra.New(infra.Config{})
	if err != nil {
		log.Fatalf("rootmote-agent: init infra: %v", err)
	}
	var serviceClient systemd.Client = systemd.NewSystemctlClient()
	if runtime.GOOS == "darwin" {
		serviceClient = systemd.NewLaunchctlClient()
	}
	systemdMgr, err := systemd.New(systemd.Config{Client: serviceClient})
	if err != nil {
		log.Fatalf("rootmote-agent: init systemd: %v", err)
	}
	webserverMgr, err := webserver.New(webserver.Config{Systemd: systemdMgr})
	if err != nil {
		log.Fatalf("rootmote-agent: init webservers: %v", err)
	}

	// Watchtower Phase 1 tracer (issue #79): a pure outbound heartbeat
	// client. Constructed unconditionally (from any prior enrollment's cred
	// file, if present) so the watchtower.enable control-plane kind can
	// enroll it on demand even when the agent boots with no relay
	// pre-configured. Non-fatal: a failure to even load the cred file
	// (e.g. permission issue) disables the watchtower.* kinds rather than
	// blocking agent startup.
	wtClient, err := watchtower.NewClient(*dataDir, version.Version, nil)
	if err != nil {
		log.Printf("rootmote-agent: init watchtower client: %v (watchtower disabled)", err)
		wtClient = nil
	}

	// Remediation owns the durable "approve, execute, verify" lifecycle for
	// one approved runbook. Steps run through the typed step catalog: each
	// step is validated, root steps go through the privilege helper
	// (`sudo -n rootmote-agent priv ...`), and nothing runs a free-form
	// command. The Projector posts every lifecycle event to the relay
	// through the watchtower client, which redacts to the relay's accepted
	// wire shape and resolves each event's incident from st. wtClient may
	// be nil (watchtower disabled); RemediationProjector is then a no-op.
	privCaller := steps.ExecPriv{}
	urlAllowlist := server.NewURLAllowlist(webserverMgr)
	stepRunner := &steps.Runner{Env: server.NewStepsEnv(server.StepsDeps{
		Systemd: systemdMgr,
		Docker:  dockerMgr,
		Priv:    privCaller,
		URLs:    urlAllowlist,
	})}
	remediationMgr, err := remediation.New(remediation.Config{
		Store:     st,
		Executor:  server.NewRemediationStepExecutor(stepRunner),
		Validator: server.NewRemediationApprovalValidator(reviewMgr, st),
		Verifier:  server.NewRemediationInternalVerifier(stepRunner, stepRunner.Env.Units),
		Projector: watchtower.RemediationProjector{Client: wtClient, Store: st},
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init remediation: %v", err)
	}
	notificationHub := notifications.NewHub()

	// Watchtower Phase 2 local monitor engine (issue #78): the agent-side
	// state machine that evaluates the disk/inode/memory/docker/systemd
	// collectors and emits signed firing/resolved transitions to the relay.
	// Constructed only when the watchtower client exists; started below on
	// the same enrollment gate as the heartbeat loop.
	var monMgr *monitor.Manager
	if wtClient != nil {
		monMgr, err = monitor.New(monitor.Config{
			Infra:   infraMgr,
			Docker:  dockerMgr,
			Systemd: systemdMgr,
			PM2:     monitor.NewPM2Source(privCaller),
			Store:   st,
			Client:  wtClient,
		})
		if err != nil {
			log.Printf("rootmote-agent: init monitor engine: %v (local monitors disabled)", err)
			monMgr = nil
		}
	}
	var monitorStartOnce sync.Once
	startMonitorEngine := func() {
		if monMgr == nil || wtClient == nil {
			return
		}
		monitorStartOnce.Do(func() {
			// Mirror watchtower.Client.EnsureRunning: these loops belong to
			// the agent process, not to the WebSocket request that enabled
			// Watchtower.
			bg := context.Background()
			monMgr.Start(bg)
			go syncMonitorsLoop(bg, wtClient, monMgr, urlAllowlist)
			log.Printf("rootmote-agent: watchtower monitor engine started")
		})
	}
	srvCfg := server.Config{
		Addr:                *addr,
		Review:              reviewMgr,
		Docker:              dockerMgr,
		Infra:               infraMgr,
		Systemd:             systemdMgr,
		Webservers:          webserverMgr,
		Notifications:       notificationHub,
		Remediation:         remediationMgr,
		Store:               st,
		URLs:                urlAllowlist,
		Steps:               stepRunner,
		DiagnoseRedactor:    diagnoseRedactor,
		Priv:                privCaller,
		Watchtower:          wtClient,
		OnWatchtowerEnabled: startMonitorEngine,
		ControlPlaneKey:     controlPlaneKey,
		RequirePairing:      *requirePairing,
	}
	if monMgr != nil {
		srvCfg.Monitor = monMgr
	}
	srv := server.New(srvCfg)
	if wtClient != nil {
		// The relay answers each firing monitor event with the incident it
		// opened; the server proposes a playbook for it.
		wtClient.IncidentOpened = srv.IncidentOpened
	}
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("rootmote-agent: %v", err)
	}
	log.Printf("rootmote-agent %s listening on %s (data %s)", version.Version, ln.Addr(), *dataDir)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	srv.StartPlaybooks(ctx)
	// A host command may have been mid-flight when the agent last stopped;
	// RecoverInterrupted fails those executions closed (remediation_failed)
	// rather than guessing whether the last step actually completed on the
	// host -- see remediation.Manager.RecoverInterrupted. Never replayed.
	if recovered, rerr := remediationMgr.RecoverInterrupted(ctx); rerr != nil {
		log.Printf("rootmote-agent: recover interrupted remediations: %v", rerr)
	} else if len(recovered) > 0 {
		log.Printf("rootmote-agent: recovered %d interrupted remediation(s) as failed", len(recovered))
	}

	// Watchtower heartbeat loop: opt-in. Starts at boot when either a relay
	// URL is pre-configured (--watchtower-relay-url / ROOTMOTE_WATCHTOWER_RELAY_URL)
	// or a prior enrollment's cred file already exists (resuming after a
	// restart). Otherwise the loop starts lazily the first time the mobile
	// app calls the watchtower.enable control-plane kind. Either way, at
	// most one loop ever runs (EnsureRunning is idempotent) and unenrolled
	// ticks are a non-fatal no-op.
	if wtClient != nil && (*watchtowerRelayURL != "" || wtClient.Creds() != nil) {
		wtClient.EnsureRunning(0)
		log.Printf("rootmote-agent: watchtower heartbeat loop started")
	}

	// Watchtower Phase 2 local monitor engine: start at boot for a resumed
	// enrollment. First-time mobile enrollment invokes the same idempotent
	// callback from watchtower.enable.
	if *watchtowerRelayURL != "" || (wtClient != nil && wtClient.Creds() != nil) {
		startMonitorEngine()
	}

	if err := srv.Serve(ctx, ln); err != nil {
		log.Fatalf("rootmote-agent serve: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "rootmote")
	}
	return "./rootmote-data"
}

// removeRetiredCredentials deletes the encrypted CLI and repository
// credentials earlier agent versions kept. The agent no longer uses them.
func removeRetiredCredentials(dataDir string) {
	for _, name := range []string{"github-token.key", "github-tokens"} {
		if err := os.RemoveAll(filepath.Join(dataDir, name)); err != nil {
			log.Printf("rootmote-agent: remove retired %s: %v", name, err)
		}
	}
}

// controlPlaneKeyPath is the 0600 file holding the WebSocket pairing key the
// mobile app must present. It lives beside state.db so it inherits the data
// dir's ownership and permissions.
func controlPlaneKeyPath(dataDir string) string {
	return filepath.Join(dataDir, "control_plane.key")
}

// loadOrCreateControlPlaneKey returns the persisted pairing key, generating a
// fresh 32-byte random one on first run. The file is 0600 so only the agent
// user (and root) can read it; the app fetches it over the operator-
// authenticated SSH channel.
func loadOrCreateControlPlaneKey(dataDir string) (string, error) {
	path := controlPlaneKeyPath(dataDir)
	if b, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(b)); key != "" {
			// Enforce 0600 on every boot so an earlier version or a manual edit
			// that left the secret group/other-readable can't quietly defeat the
			// WebSocket pairing check.
			if err := os.Chmod(path, 0o600); err != nil {
				return "", err
			}
			return key, nil
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	return key, nil
}

// syncMonitorsLoop periodically pulls the relay-owned monitor definitions and
// overlays them on the engine's built-in defaults, so mobile CRUD (create /
// edit / disable) reaches the agent. It runs an immediate sync, then every
// minute until ctx is done. A failed sync is logged and retried on the next
// tick; the engine keeps evaluating whatever definitions it last had.
func syncMonitorsLoop(ctx context.Context, wt *watchtower.Client, mon *monitor.Manager, urls *server.URLAllowlist) {
	sync := func() {
		defs, err := wt.SyncMonitors(ctx)
		if err != nil {
			log.Printf("rootmote-agent: monitor sync: %v", err)
			return
		}
		mon.SetSyncedDefinitions(monitor.DefinitionsFromSync(defs))
		// check.http may only request addresses of this host: its own name,
		// its web server domains, and the hosts of the user's web monitors.
		var targets []string
		for _, d := range defs {
			if d.Kind == "external_http" || d.Kind == "tls_expiry" {
				targets = append(targets, d.Target)
			}
		}
		urls.SetMonitorTargets(targets)
	}
	sync()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sync()
		}
	}
}

// serviceDataDir is the data dir of the systemd service the installer sets up
// (the `rootmote` user's home is /var/lib/rootmote and the agent keeps its
// data in the `rootmote` folder inside it).
const serviceDataDir = "/var/lib/rootmote/rootmote"

// pairingKeyDirs lists the data dirs that may hold the pairing key, in order.
// An explicit --data-dir comes first. On Linux, when the service's data dir
// exists it is used whatever $HOME is: a root shell has its own
// ~/rootmote, and reading a key from there would hand the app a key the
// running agent does not accept. Without a service dir (a manual or macOS
// run) the user's own data dir is used.
func pairingKeyDirs(flagDir, goos, serviceDir string) []string {
	var dirs []string
	if flagDir != "" {
		dirs = append(dirs, flagDir)
	}
	if goos == "linux" {
		if fi, err := os.Stat(serviceDir); err == nil && fi.IsDir() {
			return append(dirs, serviceDir)
		}
	}
	return append(dirs, defaultDataDir(), serviceDir)
}

// readPairingKey returns the first non-empty pairing key found in dirs.
func readPairingKey(dirs []string) (string, bool) {
	for _, dir := range dirs {
		if b, err := os.ReadFile(controlPlaneKeyPath(dir)); err == nil {
			if key := strings.TrimSpace(string(b)); key != "" {
				return key, true
			}
		}
	}
	return "", false
}

// printPairingKey implements `rootmote-agent pairing-key`: it prints the
// control-plane pairing key so the mobile app can read it over SSH. It scans
// the standard install locations so an operator can run it (as root / via
// sudo) without knowing the daemon's exact data dir.
func printPairingKey(args []string) {
	fs := flag.NewFlagSet("pairing-key", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "agent data dir (defaults to the standard install locations)")
	_ = fs.Parse(args)
	if key, ok := readPairingKey(pairingKeyDirs(*dataDir, runtime.GOOS, serviceDataDir)); ok {
		_, _ = os.Stdout.WriteString(key + "\n")
		return
	}
	log.Fatal("rootmote-agent: pairing key not found; is the agent installed and started?")
}
