package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/rockclaver/claver-agent/internal/actions"
	"github.com/rockclaver/claver-agent/internal/aiproposal"
	"github.com/rockclaver/claver-agent/internal/alerts"
	"github.com/rockclaver/claver-agent/internal/billing"
	"github.com/rockclaver/claver-agent/internal/cliauth"
	"github.com/rockclaver/claver-agent/internal/cost"
	"github.com/rockclaver/claver-agent/internal/docker"
	"github.com/rockclaver/claver-agent/internal/firewall"
	gh "github.com/rockclaver/claver-agent/internal/github"
	"github.com/rockclaver/claver-agent/internal/inbox"
	"github.com/rockclaver/claver-agent/internal/infra"
	"github.com/rockclaver/claver-agent/internal/inventory"
	"github.com/rockclaver/claver-agent/internal/memory"
	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/previews"
	agentprocess "github.com/rockclaver/claver-agent/internal/process"
	"github.com/rockclaver/claver-agent/internal/projects"
	"github.com/rockclaver/claver-agent/internal/push"
	"github.com/rockclaver/claver-agent/internal/review"
	"github.com/rockclaver/claver-agent/internal/runbook"
	"github.com/rockclaver/claver-agent/internal/security"
	"github.com/rockclaver/claver-agent/internal/server"
	"github.com/rockclaver/claver-agent/internal/sessions"
	"github.com/rockclaver/claver-agent/internal/skills"
	"github.com/rockclaver/claver-agent/internal/storage"
	"github.com/rockclaver/claver-agent/internal/store"
	"github.com/rockclaver/claver-agent/internal/systemd"
	"github.com/rockclaver/claver-agent/internal/tooling"
	"github.com/rockclaver/claver-agent/internal/version"
	"github.com/rockclaver/claver-agent/internal/webserver"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for state.db and project workspaces")
	caddyFragmentsDir := flag.String("caddy-fragments-dir", envOr("CLAVER_CADDY_FRAGMENTS_DIR", "/etc/caddy/claver"), "directory for per-preview Caddy site blocks")
	previewExpectedIP := flag.String("preview-expected-ip", os.Getenv("CLAVER_PREVIEW_EXPECTED_IP"), "if set, DNS validation requires the wildcard to resolve to this IP")
	notifyRelayURL := flag.String("notify-relay-url", envOr("CLAVER_NOTIFY_RELAY_URL", ""), "base URL of the central claver-notify relay; enables server-side push when set")
	notifyToken := flag.String("notify-token", envOr("CLAVER_NOTIFY_TOKEN", ""), "bearer token for the notify relay; auto-registered and persisted on first run when empty")
	runbookAgent := flag.String("runbook-agent", envOr("CLAVER_RUNBOOK_AGENT", "claude"), "AI CLI to use for runbook generation (claude|codex)")
	codexRuntimeKind := flag.String("codex-runtime", envOr("CLAVER_CODEX_RUNTIME", "app-server"), "codex structured runtime: app-server (default) or exec (fallback)")
	serverID := flag.String("server-id", envOr("CLAVER_SERVER_ID", "local"), "stable id labelling this server's cost/usage rows in the cross-fleet dashboard")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		// Phase 1 AC: bootstrap "prints the installed version on stdout".
		_, _ = os.Stdout.WriteString(version.Version + "\n")
		return
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("claver-agent: mkdir data-dir: %v", err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "state.db"))
	if err != nil {
		log.Fatalf("claver-agent: open state store: %v", err)
	}
	defer st.Close()

	mgr, err := projects.New(filepath.Join(*dataDir, "projects"), st)
	if err != nil {
		log.Fatalf("claver-agent: init workspaces: %v", err)
	}
	toolingMgr, err := tooling.New(tooling.Config{
		BinDir:    filepath.Join(*dataDir, "bin"),
		NpmPrefix: filepath.Join(*dataDir, "npm-prefix"),
	})
	if err != nil {
		log.Fatalf("claver-agent: init tooling: %v", err)
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
		log.Fatalf("claver-agent: init cliauth: %v", err)
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

	// Per-project agent memory + project journal (Stickiness #5). Sessions load
	// rendered memory as context on start, and a session-end summarizer shells
	// out to the same authenticated CLI to write a journal entry and propose
	// new memory entries (which require one-tap user confirmation).
	memoryMgr := memory.New(st)
	memoryMgr.Transcript = sessionMgr.Log
	memoryMgr.Summarizer = memory.CLISummarizer{
		Agent:   *runbookAgent,
		BinDir:  toolingMgr.BinDir(),
		HomeDir: homeDirOr(*dataDir),
		Secrets: authMgr.Secrets,
	}
	sessionMgr.MemorySource = memoryMgr.Render
	// Summarization shells out to a CLI (seconds), so run it off the Stop path
	// with a fresh context that outlives the request connection.
	sessionMgr.OnEnd = func(_ context.Context, sess store.Session) {
		go func() {
			if err := memoryMgr.OnSessionEnd(context.Background(), sess); err != nil {
				log.Printf("claver-agent: session %s journal: %v", sess.ID, err)
			}
		}()
	}

	// Cross-fleet cost & usage dashboard (Stickiness #8). The cost calculator
	// prices session token usage and folds in the per-server infra bills the
	// billing manager pulls daily from VPS provider APIs. Provider credentials
	// are sealed with their own AES key (separate namespace from the CLI/GitHub
	// vault) and stored encrypted in SQLite.
	costCalc := cost.New(st, *serverID)
	billingVault := billing.NewVault(filepath.Join(*dataDir, "billing.key"))
	billingMgr := billing.New(st, billingVault, *serverID)
	billingMgr.Logf = log.Printf

	previewMgr, err := previews.New(previews.Config{
		FragmentsDir: *caddyFragmentsDir,
		ExpectedIP:   *previewExpectedIP,
	}, st, mgr)
	if err != nil {
		// A missing /etc/caddy/claver on a non-root install is expected
		// during local development; log and continue with previews
		// disabled rather than crashing the agent.
		log.Printf("claver-agent: previews disabled: %v", err)
		previewMgr = nil
	}

	dockerMgr, err := docker.New(docker.Config{
		Client:      docker.NewSocketClient(""),
		ProjectRoot: filepath.Join(*dataDir, "projects"),
	})
	if err != nil {
		log.Fatalf("claver-agent: init docker: %v", err)
	}
	infraMgr, err := infra.New(infra.Config{})
	if err != nil {
		log.Fatalf("claver-agent: init infra: %v", err)
	}
	storageMgr, err := storage.New(storage.Config{
		HomeDir:      homeDirOr(*dataDir),
		DataDir:      *dataDir,
		ProjectsRoot: filepath.Join(*dataDir, "projects"),
		Docker:       dockerMgr,
	})
	if err != nil {
		log.Fatalf("claver-agent: init storage: %v", err)
	}
	var serviceClient systemd.Client = systemd.NewSystemctlClient()
	if runtime.GOOS == "darwin" {
		serviceClient = systemd.NewLaunchctlClient()
	}
	systemdMgr, err := systemd.New(systemd.Config{Client: serviceClient})
	if err != nil {
		log.Fatalf("claver-agent: init systemd: %v", err)
	}
	webserverMgr, err := webserver.New(webserver.Config{Systemd: systemdMgr})
	if err != nil {
		log.Fatalf("claver-agent: init webservers: %v", err)
	}
	processMgr, err := agentprocess.New(agentprocess.Config{Platform: runtime.GOOS})
	if err != nil {
		log.Fatalf("claver-agent: init process inspector: %v", err)
	}
	var socketReader firewall.SocketReader = firewall.NewSSCommandReader()
	if runtime.GOOS == "darwin" {
		socketReader = firewall.NewLsofSocketReader()
	}
	firewallMgr, err := firewall.New(firewall.Config{
		Backends: []firewall.Backend{firewall.NewUFWBackend(), firewall.NewFirewalldBackend()},
		Sockets:  socketReader,
		SSH:      firewall.SSHFromSockets{Reader: socketReader},
	})
	if err != nil {
		log.Fatalf("claver-agent: init firewall: %v", err)
	}
	securityMgr, err := security.New(security.Config{
		Firewall:  firewallMgr,
		Processes: processMgr,
	})
	if err != nil {
		log.Fatalf("claver-agent: init security audit: %v", err)
	}
	notificationHub := notifications.NewHub()
	alertMgr, err := alerts.New(alerts.Config{
		Store:   st,
		Metrics: infraMgr,
		Systemd: systemdMgr,
		Sink:    notificationHub,
	})
	if err != nil {
		log.Fatalf("claver-agent: init alerts: %v", err)
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
		log.Fatalf("claver-agent: init runbook: %v", err)
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
		log.Fatalf("claver-agent: init actions: %v", err)
	}
	pushDeliveryConfigured := false
	inventoryMgr := inventory.New(inventory.Config{
		Docker:         dockerMgr,
		Systemd:        systemdMgr,
		Processes:      processMgr,
		Previews:       previewMgr,
		PushDevices:    st,
		PushConfigured: func() bool { return pushDeliveryConfigured },
		Auth:           authMgr,
	})

	inboxMgr := inbox.New()
	inboxMgr.SetStateStore(st)
	inboxMgr.AddSource(&inbox.ProposalSource{Mgr: aiProposalMgr})
	inboxMgr.AddSource(&inbox.AlertSource{Mgr: alertMgr})
	inboxMgr.AddSource(&inbox.SessionSource{Store: st})
	inboxMgr.AddSource(&inbox.RunbookSource{Mgr: runbookMgr})
	githubSource := &inbox.GitHubSource{
		GitHub:  githubMgr,
		Store:   st,
		Publish: inboxMgr.Publish,
	}
	inboxMgr.AddSource(githubSource)
	inboxBridgeCleanup := inbox.BridgeAlertNotifications(notificationHub, inboxMgr)
	defer inboxBridgeCleanup()

	srv := server.New(server.Config{
		Addr:          *addr,
		Projects:      mgr,
		Sessions:      sessionMgr,
		Skills:        skills.New(homeDirOr(*dataDir)),
		Review:        reviewMgr,
		GitHub:        githubMgr,
		Previews:      previewMgr,
		Tooling:       toolingMgr,
		Auth:          authMgr,
		Docker:        dockerMgr,
		Infra:         infraMgr,
		Systemd:       systemdMgr,
		Webservers:    webserverMgr,
		Processes:     processMgr,
		Firewall:      firewallMgr,
		Storage:       storageMgr,
		Security:      securityMgr,
		Alerts:        alertMgr,
		AIProposals:   aiProposalMgr,
		Notifications: notificationHub,
		Inbox:         inboxMgr,
		Runbook:       runbookMgr,
		Actions:       actionsMgr,
		Inventory:     inventoryMgr,
		PushDevices:   st,
		Memory:        memoryMgr,
		Cost:          costCalc,
		Billing:       billingMgr,
	})
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("claver-agent: %v", err)
	}
	log.Printf("claver-agent %s listening on %s (data %s)", version.Version, ln.Addr(), *dataDir)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := sessionMgr.Rehydrate(ctx); err != nil {
		log.Printf("claver-agent: rehydrate sessions: %v", err)
	}
	sessionMgr.StartReaper(ctx, 0)
	alertMgr.Start(ctx)
	billingCleanup := billingMgr.StartDaily(ctx)
	defer billingCleanup()
	runbookCleanup := runbookMgr.Start(ctx)
	defer runbookCleanup()

	// Push delivery: optional. The agent stays fully functional without it
	// (the notification hub + inbox keep delivering to connected sockets).
	// With a relay URL configured, we additionally fan high-signal events
	// out as system-level push so a backgrounded device still wakes the
	// user. The relay (github.com/rockclaver/claver-notify) holds the one
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
			registeredToken, regErr := push.Register(registerCtx, *notifyRelayURL, hostname, nil)
			registerCancel()
			if regErr != nil {
				log.Printf("claver-agent: notify relay register failed, push disabled: %v", regErr)
			} else {
				token = registeredToken
				if putErr := st.PutAgentSetting("notify_relay_token", token); putErr != nil {
					log.Printf("claver-agent: persist notify token: %v", putErr)
				}
			}
		}
		if token != "" {
			pushHub := &push.Hub{
				Sender: push.NewRelayClient(*notifyRelayURL, token, nil),
				Store:  st,
				Types:  map[string]bool{"infra.alert": true, "infra.runbook": true},
				Logf:   log.Printf,
			}
			pushCleanup := pushHub.Subscribe(ctx, notificationHub)
			defer pushCleanup()
			pushDeliveryConfigured = true
			log.Printf("claver-agent: notify relay push enabled (%s)", *notifyRelayURL)
		}
	}

	githubSource.Start(ctx)
	// Reap resolved inbox-state rows so the table can't grow without bound as
	// item ids churn. Resolved entries older than 30 days are well past any
	// chance of their source item reappearing.
	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			if _, err := st.GCInboxState(time.Now().Add(-30 * 24 * time.Hour)); err != nil {
				log.Printf("claver-agent: inbox-state GC: %v", err)
			}
			select {
			case <-t.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	if err := srv.Serve(ctx, ln); err != nil {
		log.Fatalf("claver-agent serve: %v", err)
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
		return filepath.Join(home, "claver")
	}
	return "./claver-data"
}

// homeDirOr falls back to the parent of dataDir if $HOME isn't set, so the
// CLIs' credential files land somewhere stable. On the systemd-managed agent
// $HOME=/var/lib/claver, dataDir=/var/lib/claver/claver, parent matches.
func homeDirOr(dataDir string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return filepath.Dir(dataDir)
}
