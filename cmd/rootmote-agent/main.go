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
	"syscall"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/actions"
	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/alerts"
	"github.com/rockclaver/rootmote-agent/internal/cliauth"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	gh "github.com/rockclaver/rootmote-agent/internal/github"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/inventory"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/projects"
	"github.com/rockclaver/rootmote-agent/internal/push"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/server"
	"github.com/rockclaver/rootmote-agent/internal/sessions"
	"github.com/rockclaver/rootmote-agent/internal/skills"
	"github.com/rockclaver/rootmote-agent/internal/storage"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/tooling"
	"github.com/rockclaver/rootmote-agent/internal/version"
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
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for state.db and project workspaces")
	requirePairing := flag.Bool("require-pairing", true, "require the mobile app to present the control-plane pairing key on the WebSocket; disable only for local development")
	notifyRelayURL := flag.String("notify-relay-url", envOr("ROOTMOTE_NOTIFY_RELAY_URL", defaultNotifyRelayURL), "base URL of the central rootmote-notify relay; set to empty to disable push")
	notifyToken := flag.String("notify-token", envOr("ROOTMOTE_NOTIFY_TOKEN", ""), "bearer token for the notify relay; auto-registered and persisted on first run when empty")
	notifyEnrollSecret := flag.String("notify-enroll-secret", envOr("ROOTMOTE_NOTIFY_ENROLL_SECRET", ""), "enrollment secret presented to the notify relay's /v1/register; required when the relay enforces enrollment auth")
	runbookAgent := flag.String("runbook-agent", envOr("ROOTMOTE_RUNBOOK_AGENT", "claude"), "AI CLI to use for runbook generation (claude|codex)")
	codexRuntimeKind := flag.String("codex-runtime", envOr("ROOTMOTE_CODEX_RUNTIME", "app-server"), "codex structured runtime: app-server (default) or exec (fallback)")
	serverID := flag.String("server-id", envOr("ROOTMOTE_SERVER_ID", "local"), "stable id labelling this server's cost/usage rows in the cross-fleet dashboard")
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

	mgr, err := projects.New(filepath.Join(*dataDir, "projects"), st)
	if err != nil {
		log.Fatalf("rootmote-agent: init workspaces: %v", err)
	}
	toolingMgr, err := tooling.New(tooling.Config{
		BinDir:    filepath.Join(*dataDir, "bin"),
		NpmPrefix: filepath.Join(*dataDir, "npm-prefix"),
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init tooling: %v", err)
	}
	reviewMgr := review.New(mgr, st, review.HeuristicSummarizer{})
	vault := gh.NewTokenVault(filepath.Join(*dataDir, "github-token.key"), filepath.Join(*dataDir, "github-tokens"))
	githubMgr := gh.New(st, mgr, reviewMgr, vault)

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
	terminalRuntime := sessions.TmuxRuntime{
		ExtraPath: toolingMgr.BinDir(),
		HomeDir:   homeDirOr(*dataDir),
		Secrets:   authMgr.Secrets,
	}
	claudeRuntime := sessions.NewClaudeStructuredRuntime(toolingMgr.BinDir(), homeDirOr(*dataDir), authMgr.Secrets)
	// Codex defaults to the richer app-server protocol; the exec --json fallback
	// is selectable for hosts where app-server is unavailable.
	var codexRuntime sessions.Runtime = sessions.NewCodexStructuredRuntime(toolingMgr.BinDir(), homeDirOr(*dataDir), authMgr.Secrets)
	if *codexRuntimeKind == "exec" {
		codexRuntime = sessions.NewCodexExecRuntime(toolingMgr.BinDir(), homeDirOr(*dataDir), authMgr.Secrets)
	}
	sessionRuntime := sessions.NewRoutingRuntime(
		terminalRuntime,
		map[string]sessions.Runtime{"claude": claudeRuntime, "codex": codexRuntime},
		func(sessionID string) (string, string) {
			s, err := st.GetSession(sessionID)
			if err != nil {
				return "", ""
			}
			return s.Agent, s.Transport
		},
	)
	sessionMgr := sessions.New(st, mgr, sessionRuntime)
	// Real token usage is read from the claude CLI transcript root, which lives
	// under the same HOME the runtime gives the CLI.
	sessionMgr.ClaudeProjectsDir = filepath.Join(homeDirOr(*dataDir), ".claude", "projects")
	sessionMgr.AuthOK = func(ctx context.Context, agent string) bool {
		st, err := authMgr.Status(ctx, agent)
		return err == nil && st.LoggedIn
	}

	dockerMgr, err := docker.New(docker.Config{
		Client:      docker.NewSocketClient(""),
		ProjectRoot: filepath.Join(*dataDir, "projects"),
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init docker: %v", err)
	}
	infraMgr, err := infra.New(infra.Config{})
	if err != nil {
		log.Fatalf("rootmote-agent: init infra: %v", err)
	}
	storageMgr, err := storage.New(storage.Config{
		HomeDir:      homeDirOr(*dataDir),
		DataDir:      *dataDir,
		ProjectsRoot: filepath.Join(*dataDir, "projects"),
		Docker:       dockerMgr,
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

	// AI Action Plane orchestrator (Phase 1, read-only tracer). The host-query
	// planner answers server-scoped resource questions (memory, swap, disk, CPU,
	// load) from live host metrics — the agent is itself the host, so these need
	// no target resolution. Requests outside that scope still return "needs
	// target" honestly, until the full target resolver is wired on the agent. No
	// mutation happens in this phase.
	hostname, _ := os.Hostname()
	actionsMgr, err := actions.New(actions.Config{
		Store: st,
		Planner: actions.HostQueryPlanner{
			Metrics:  infraMgr,
			Hostname: hostname,
		},
		Notifications: notificationHub,
	})
	if err != nil {
		log.Fatalf("rootmote-agent: init actions: %v", err)
	}
	pushDeliveryConfigured := false
	inventoryMgr := inventory.New(inventory.Config{
		Docker:         dockerMgr,
		Systemd:        systemdMgr,
		Processes:      processMgr,
		PushDevices:    st,
		PushConfigured: func() bool { return pushDeliveryConfigured },
		Auth:           authMgr,
	})

	srv := server.New(server.Config{
		Addr:            *addr,
		Projects:        mgr,
		Sessions:        sessionMgr,
		Skills:          skills.New(homeDirOr(*dataDir)),
		Review:          reviewMgr,
		GitHub:          githubMgr,
		Tooling:         toolingMgr,
		Auth:            authMgr,
		Docker:          dockerMgr,
		Infra:           infraMgr,
		Systemd:         systemdMgr,
		Webservers:      webserverMgr,
		Processes:       processMgr,
		Firewall:        firewallMgr,
		Storage:         storageMgr,
		Security:        securityMgr,
		Alerts:          alertMgr,
		AIProposals:     aiProposalMgr,
		Notifications:   notificationHub,
		Runbook:         runbookMgr,
		Actions:         actionsMgr,
		Inventory:       inventoryMgr,
		PushDevices:     st,
		ControlPlaneKey: controlPlaneKey,
		RequirePairing:  *requirePairing,
	})
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("rootmote-agent: %v", err)
	}
	log.Printf("rootmote-agent %s listening on %s (data %s)", version.Version, ln.Addr(), *dataDir)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := sessionMgr.Rehydrate(ctx); err != nil {
		log.Printf("rootmote-agent: rehydrate sessions: %v", err)
	}
	sessionMgr.StartReaper(ctx, 0)
	alertMgr.Start(ctx)
	runbookCleanup := runbookMgr.Start(ctx)
	defer runbookCleanup()

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
