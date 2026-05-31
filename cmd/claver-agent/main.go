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
	"github.com/rockclaver/claver/agent/internal/notifications"
	"github.com/rockclaver/claver/agent/internal/previews"
	agentprocess "github.com/rockclaver/claver/agent/internal/process"
	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/review"
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

	inboxMgr := inbox.New()
	inboxMgr.AddSource(&inbox.ProposalSource{Mgr: aiProposalMgr})
	inboxMgr.AddSource(&inbox.AlertSource{Mgr: alertMgr})
	inboxMgr.AddSource(&inbox.SessionSource{Store: st})
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
