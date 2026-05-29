package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	gh "github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/previews"
	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/review"
	"github.com/rockclaver/claver/agent/internal/server"
	"github.com/rockclaver/claver/agent/internal/sessions"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/version"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for state.db and project workspaces")
	githubClientID := flag.String("github-client-id", os.Getenv("CLAVER_GITHUB_CLIENT_ID"), "GitHub OAuth device-flow client ID")
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
	sessionMgr := sessions.New(st, mgr, sessions.TmuxRuntime{})
	reviewMgr := review.New(mgr, st, review.HeuristicSummarizer{})
	vault := gh.NewTokenVault(filepath.Join(*dataDir, "github-token.key"), filepath.Join(*dataDir, "github-tokens"))
	githubMgr := gh.New(st, mgr, reviewMgr, vault, *githubClientID)

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

	srv := server.New(server.Config{
		Addr:     *addr,
		Projects: mgr,
		Sessions: sessionMgr,
		Review:   reviewMgr,
		GitHub:   githubMgr,
		Previews: previewMgr,
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
