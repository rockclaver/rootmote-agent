package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rockclaver/claver/agent/internal/aiproposal"
	"github.com/rockclaver/claver/agent/internal/alerts"
	"github.com/rockclaver/claver/agent/internal/cliauth"
	"github.com/rockclaver/claver/agent/internal/docker"
	"github.com/rockclaver/claver/agent/internal/firewall"
	gh "github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/inbox"
	"github.com/rockclaver/claver/agent/internal/infra"
	"github.com/rockclaver/claver/agent/internal/memory"
	"github.com/rockclaver/claver/agent/internal/notifications"
	"github.com/rockclaver/claver/agent/internal/previews"
	agentprocess "github.com/rockclaver/claver/agent/internal/process"
	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/push"
	"github.com/rockclaver/claver/agent/internal/review"
	"github.com/rockclaver/claver/agent/internal/runbook"
	"github.com/rockclaver/claver/agent/internal/server"
	"github.com/rockclaver/claver/agent/internal/sessions"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/systemd"
	"github.com/rockclaver/claver/agent/internal/tooling"
	"github.com/rockclaver/claver/agent/internal/version"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for state.db and project workspaces")
	caddyFragmentsDir := flag.String("caddy-fragments-dir", envOr("CLAVER_CADDY_FRAGMENTS_DIR", "/etc/caddy/claver"), "directory for per-preview Caddy site blocks")
	previewExpectedIP := flag.String("preview-expected-ip", os.Getenv("CLAVER_PREVIEW_EXPECTED_IP"), "if set, DNS validation requires the wildcard to resolve to this IP")
	fcmServiceAccount := flag.String("fcm-service-account", envOr("CLAVER_FCM_SERVICE_ACCOUNT", ""), "path to Firebase service-account JSON; enables server-side push when set")
	runbookAgent := flag.String("runbook-agent", envOr("CLAVER_RUNBOOK_AGENT", "claude"), "AI CLI to use for runbook generation (claude|codex)")
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
	sessionMgr := sessions.New(st, mgr, sessions.TmuxRuntime{
		ExtraPath: toolingMgr.BinDir(),
		HomeDir:   homeDirOr(*dataDir),
		Secrets:   authMgr.Secrets,
	})
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
	systemdMgr, err := systemd.New(systemd.Config{Client: systemd.NewSystemctlClient()})
	if err != nil {
		log.Fatalf("claver-agent: init systemd: %v", err)
	}
	processMgr, err := agentprocess.New(agentprocess.Config{})
	if err != nil {
		log.Fatalf("claver-agent: init process inspector: %v", err)
	}
	socketReader := firewall.NewSSCommandReader()
	firewallMgr, err := firewall.New(firewall.Config{
		Backends: []firewall.Backend{firewall.NewUFWBackend(), firewall.NewFirewalldBackend()},
		Sockets:  socketReader,
		SSH:      firewall.SSHFromSockets{Reader: socketReader},
	})
	if err != nil {
		log.Fatalf("claver-agent: init firewall: %v", err)
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

	inboxMgr := inbox.New()
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
		Review:        reviewMgr,
		GitHub:        githubMgr,
		Previews:      previewMgr,
		Tooling:       toolingMgr,
		Auth:          authMgr,
		Docker:        dockerMgr,
		Infra:         infraMgr,
		Systemd:       systemdMgr,
		Processes:     processMgr,
		Firewall:      firewallMgr,
		Alerts:        alertMgr,
		AIProposals:   aiProposalMgr,
		Notifications: notificationHub,
		Inbox:         inboxMgr,
		Runbook:       runbookMgr,
		PushDevices:   st,
		Memory:        memoryMgr,
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
	runbookCleanup := runbookMgr.Start(ctx)
	defer runbookCleanup()

	// FCM push: optional. The agent stays fully functional without it (the
	// notification hub + inbox keep delivering to connected sockets). With
	// a service-account JSON, we additionally fan high-signal events out
	// as system-level push so a backgrounded device still wakes the user.
	if *fcmServiceAccount != "" {
		sa, err := push.LoadServiceAccount(*fcmServiceAccount)
		if err != nil {
			log.Printf("claver-agent: FCM disabled: %v", err)
		} else {
			pushClient := push.NewClient(sa, nil)
			pushHub := &push.Hub{
				Sender: pushClient,
				Store:  st,
				Types:  map[string]bool{"infra.alert": true, "infra.runbook": true},
				Logf:   log.Printf,
			}
			pushCleanup := pushHub.Subscribe(ctx, notificationHub)
			defer pushCleanup()
			log.Printf("claver-agent: FCM push enabled (project %s)", sa.ProjectID)
		}
	}

	githubSource.Start(ctx)
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
