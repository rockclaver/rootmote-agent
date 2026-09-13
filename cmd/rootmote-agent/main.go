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

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/alerts"
	"github.com/rockclaver/rootmote-agent/internal/cliauth"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	gh "github.com/rockclaver/rootmote-agent/internal/github"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/inventory"
	"github.com/rockclaver/rootmote-agent/internal/monitor"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/push"
	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/server"
	"github.com/rockclaver/rootmote-agent/internal/storage"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/tooling"
	"github.com/rockclaver/rootmote-agent/internal/version"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// defaultNotifyRelayURL is the org-operated rootmote-notify deployment (see
// github.com/rockclaver/rootmote-notify). Override with --notify-relay-url or
// ROOTMOTE_NOTIFY_RELAY_URL to point at a self-hosted relay instead, or set
// to "" to disable server-side push entirely.
const defaultNotifyRelayURL = "https://notify.orivo.app"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pairing-key" {
		printPairingKey(os.Args[2:])
		return
	}
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for state, encrypted CLI credentials, and managed tooling")
	requirePairing := flag.Bool("require-pairing", true, "require the mobile app to present the control-plane pairing key on the WebSocket; disable only for local development")
	notifyRelayURL := flag.String("notify-relay-url", envOr("ROOTMOTE_NOTIFY_RELAY_URL", defaultNotifyRelayURL), "base URL of the central rootmote-notify relay; set to empty to disable push")
	notifyToken := flag.String("notify-token", envOr("ROOTMOTE_NOTIFY_TOKEN", ""), "bearer token for the notify relay; auto-registered and persisted on first run when empty")
	notifyEnrollSecret := flag.String("notify-enroll-secret", envOr("ROOTMOTE_NOTIFY_ENROLL_SECRET", ""), "enrollment secret presented to the notify relay's /v1/register; required when the relay enforces enrollment auth")
	watchtowerRelayURL := flag.String("watchtower-relay-url", envOr("ROOTMOTE_WATCHTOWER_RELAY_URL", ""), "base URL of the Watchtower relay (github.com/rockclaver/rootmote-watchtower); starts the outbound heartbeat loop at boot. Leave empty to stay opt-out until enrolled via the watchtower.enable control-plane kind (also auto-resumes at boot if a prior enrollment's cred file exists)")
	runbookAgent := flag.String("runbook-agent", envOr("ROOTMOTE_RUNBOOK_AGENT", "claude"), "AI CLI to use for runbook generation (claude|codex)")
	serverID := flag.String("server-id", envOr("ROOTMOTE_SERVER_ID", "local"), "stable identifier attached to this host's operational telemetry")
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

	toolingMgr, err := tooling.New(tooling.Config{
		BinDir:    filepath.Join(*dataDir, "bin"),
		NpmPrefix: filepath.Join(*dataDir, "npm-prefix"),
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init tooling: %v", err)
	}
	reviewMgr := review.New(st)
	// Keep the established vault paths so upgrades can still decrypt existing
	// AI provider credentials, even though repository operations are retired.
	vault := gh.NewTokenVault(filepath.Join(*dataDir, "github-token.key"), filepath.Join(*dataDir, "github-tokens"))

	// cliauth reuses the same vault for CLI credentials. SQLite keeps the
	// two namespaces separate (cli_tokens vs github_tokens).
	authMgr, err := cliauth.New(cliauth.Config{
		BinDir:  toolingMgr.BinDir(),
		HomeDir: homeDirOr(*dataDir),
		Vault:   vault,
		Store:   st,
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init cliauth: %v", err)
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
	storageMgr, err := storage.New(storage.Config{
		HomeDir: homeDirOr(*dataDir),
		DataDir: *dataDir,
		Docker:  dockerMgr,
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init storage: %v", err)
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
	processMgr, err := agentprocess.New(agentprocess.Config{Platform: runtime.GOOS})
	if err != nil {
		log.Fatalf("rootmote-agent: init process inspector: %v", err)
	}
	var socketReader firewall.SocketReader = firewall.NewSSCommandReader()
	if runtime.GOOS == "darwin" {
		socketReader = firewall.NewNetstatSocketReader()
	}
	firewallMgr, err := firewall.New(firewall.Config{
		Backends: []firewall.Backend{firewall.NewUFWBackend(), firewall.NewFirewalldBackend()},
		Sockets:  socketReader,
		SSH:      firewall.SSHFromSockets{Reader: socketReader},
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init firewall: %v", err)
	}
	securityMgr, err := security.New(security.Config{
		Firewall:  firewallMgr,
		Processes: processMgr,
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init security audit: %v", err)
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
	// one approved runbook (issue #74). The typed StepExecutor/
	// InternalVerifier adapters reuse exactly the same systemd/process/
	// firewall/security managers infra.service.action / infra.process.kill
	// / infra.firewall.rule_* / security.fix mutate through -- no second,
	// unguarded execution path. The Projector posts every lifecycle event
	// to the relay through the watchtower client (issue #74 Task 4) via
	// watchtower.RemediationProjector, which redacts to the relay's
	// accepted wire shape and resolves each event's incident from st.
	// wtClient may be nil (watchtower disabled); RemediationProjector is a
	// safe no-op in that case, exactly like an unenrolled client.
	remediationMgr, err := remediation.New(remediation.Config{
		Store:     st,
		Executor:  server.NewRemediationStepExecutor(systemdMgr, processMgr, firewallMgr, securityMgr),
		Validator: server.NewRemediationApprovalValidator(reviewMgr, st),
		Verifier:  server.NewRemediationInternalVerifier(systemdMgr, firewallMgr),
		Projector: watchtower.RemediationProjector{Client: wtClient, Store: st},
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init remediation: %v", err)
	}
	notificationHub := notifications.NewHub()
	alertMgr, err := alerts.New(alerts.Config{
		Store:   st,
		Metrics: infraMgr,
		Systemd: systemdMgr,
		Sink:    notificationHub,
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init alerts: %v", err)
	}

	aiProposalMgr := aiproposal.New()

	// Runbook turns fired alerts into AI-proposed remediations that fan out
	// through the existing aiproposal queue. The proposer shells out to the
	// host-installed claude/codex CLI (already authenticated via cliauth),
	// so we add no second auth surface.
	runbookMgr, err := runbook.New(runbook.Config{
		AIProposals: aiProposalMgr,
		Proposer: runbook.CLIProposer{
			Agent:   *runbookAgent,
			BinDir:  toolingMgr.BinDir(),
			HomeDir: homeDirOr(*dataDir),
			Secrets: authMgr.Secrets,
		},
		ProposerForAgent: func(agent string) runbook.Proposer {
			switch agent {
			case "claude", "codex":
				return runbook.CLIProposer{
					Agent:   agent,
					BinDir:  toolingMgr.BinDir(),
					HomeDir: homeDirOr(*dataDir),
					Secrets: authMgr.Secrets,
				}
			default:
				return nil
			}
		},
		Snapshotter: runbook.SnapshotFunc(func(ctx context.Context) runbook.Grounding {
			g := runbook.Grounding{Metrics: infraMgr.Sample(ctx)}
			if systemdMgr != nil {
				if units, err := systemdMgr.List(ctx); err == nil {
					g.Services = units
				}
			}
			if processMgr != nil {
				if procs, err := processMgr.List(ctx, "cpu", 50); err == nil {
					g.Processes = procs
				}
			}
			if firewallMgr != nil {
				if st, err := firewallMgr.Status(ctx); err == nil {
					g.Firewall = st
				}
			}
			return g
		}),
		Notifications: notificationHub,
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init runbook: %v", err)
	}

	hostname, _ := os.Hostname()
	pushDeliveryConfigured := false
	inventoryMgr := inventory.New(inventory.Config{
		Docker:         dockerMgr,
		Systemd:        systemdMgr,
		Processes:      processMgr,
		PushDevices:    st,
		PushConfigured: func() bool { return pushDeliveryConfigured },
		Auth:           authMgr,
	})

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
			go syncMonitorsLoop(bg, wtClient, monMgr)
			log.Printf("rootmote-agent: watchtower monitor engine started")
		})
	}
	srv := server.New(server.Config{
		Addr:                *addr,
		Review:              reviewMgr,
		Tooling:             toolingMgr,
		Auth:                authMgr,
		Docker:              dockerMgr,
		Infra:               infraMgr,
		Systemd:             systemdMgr,
		Webservers:          webserverMgr,
		Processes:           processMgr,
		Firewall:            firewallMgr,
		Storage:             storageMgr,
		Security:            securityMgr,
		Alerts:              alertMgr,
		AIProposals:         aiProposalMgr,
		Notifications:       notificationHub,
		Runbook:             runbookMgr,
		Remediation:         remediationMgr,
		Inventory:           inventoryMgr,
		PushDevices:         st,
		Watchtower:          wtClient,
		OnWatchtowerEnabled: startMonitorEngine,
		ControlPlaneKey:     controlPlaneKey,
		RequirePairing:      *requirePairing,
	})
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("rootmote-agent: %v", err)
	}
	log.Printf("rootmote-agent %s listening on %s (data %s)", version.Version, ln.Addr(), *dataDir)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// A host command may have been mid-flight when the agent last stopped;
	// RecoverInterrupted fails those executions closed (remediation_failed)
	// rather than guessing whether the last step actually completed on the
	// host -- see remediation.Manager.RecoverInterrupted. Never replayed.
	if recovered, rerr := remediationMgr.RecoverInterrupted(ctx); rerr != nil {
		log.Printf("rootmote-agent: recover interrupted remediations: %v", rerr)
	} else if len(recovered) > 0 {
		log.Printf("rootmote-agent: recovered %d interrupted remediation(s) as failed", len(recovered))
	}
	alertMgr.Start(ctx)
	runbookCleanup := runbookMgr.Start(ctx)
	defer runbookCleanup()

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

	// Push delivery: optional. The agent stays fully functional without it
	// (the notification hub + inbox keep delivering to connected sockets).
	// With a relay URL configured, we additionally fan high-signal events
	// out as system-level push so a backgrounded device still wakes the
	// user. The relay (github.com/rockclaver/rootmote-notify) holds the one
	// shared FCM service-account credential, so no per-install Firebase
	// project is required: the agent self-registers for a bearer token on
	// first run and persists it in agent_settings.
	if *notifyRelayURL != "" {
		token := *notifyToken
		if token == "" {
			if saved, getErr := st.GetAgentSetting("notify_relay_token"); getErr == nil {
				token = saved
			}
		}
		if token == "" {
			registerCtx, registerCancel := context.WithTimeout(context.Background(), 10*time.Second)
			registeredToken, regErr := push.Register(registerCtx, *notifyRelayURL, hostname, *notifyEnrollSecret, nil)
			registerCancel()
			if regErr != nil {
				log.Printf("rootmote-agent: notify relay register failed, push disabled: %v", regErr)
			} else {
				token = registeredToken
				if putErr := st.PutAgentSetting("notify_relay_token", token); putErr != nil {
					log.Printf("rootmote-agent: persist notify token: %v", putErr)
				}
			}
		}
		if token != "" {
			// Prefer the operator-set --server-id (the same label used for
			// cross-fleet cost/usage rows) when it has actually been set;
			// otherwise fall back to the host's own name. Either way this
			// prefixes the push title so a phone receiving alerts from
			// several agents through the shared relay can tell them apart --
			// every agent's alert body otherwise reads identically (e.g.
			// "sshd.service recovered").
			label := *serverID
			if label == "" || label == alerts.ServerLocal {
				label = hostname
			}
			pushHub := &push.Hub{
				Sender: push.NewRelayClient(*notifyRelayURL, token, nil),
				Store:  st,
				Label:  label,
				Logf:   log.Printf,
			}
			pushCleanup := pushHub.Subscribe(ctx, notificationHub)
			defer pushCleanup()
			pushDeliveryConfigured = true
			log.Printf("rootmote-agent: notify relay push enabled (%s)", *notifyRelayURL)
		}
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

// homeDirOr falls back to the parent of dataDir if $HOME isn't set, so the
// CLIs' credential files land somewhere stable. On the systemd-managed agent
// $HOME=/var/lib/rootmote, dataDir=/var/lib/rootmote/rootmote, parent matches.
func homeDirOr(dataDir string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return filepath.Dir(dataDir)
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
func syncMonitorsLoop(ctx context.Context, wt *watchtower.Client, mon *monitor.Manager) {
	sync := func() {
		defs, err := wt.SyncMonitors(ctx)
		if err != nil {
			log.Printf("rootmote-agent: monitor sync: %v", err)
			return
		}
		mon.SetSyncedDefinitions(monitor.DefinitionsFromSync(defs))
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

// printPairingKey implements `rootmote-agent pairing-key`: it prints the
// control-plane pairing key so the mobile app can read it over SSH. It scans
// the standard install locations so an operator can run it (as root / via
// sudo) without knowing the daemon's exact data dir.
func printPairingKey(args []string) {
	fs := flag.NewFlagSet("pairing-key", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "agent data dir (defaults to the standard install locations)")
	_ = fs.Parse(args)
	var candidates []string
	if *dataDir != "" {
		candidates = append(candidates, *dataDir)
	}
	candidates = append(candidates, defaultDataDir(), "/var/lib/rootmote/rootmote")
	for _, dir := range candidates {
		if b, err := os.ReadFile(controlPlaneKeyPath(dir)); err == nil {
			if key := strings.TrimSpace(string(b)); key != "" {
				_, _ = os.Stdout.WriteString(key + "\n")
				return
			}
		}
	}
	log.Fatal("rootmote-agent: pairing key not found; is the agent installed and started?")
}
