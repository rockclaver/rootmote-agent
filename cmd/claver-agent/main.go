package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/server"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/version"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for state.db and project workspaces")
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

	srv := server.New(server.Config{Addr: *addr, Projects: mgr})
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("claver-agent: %v", err)
	}
	log.Printf("claver-agent %s listening on %s (data %s)", version.Version, ln.Addr(), *dataDir)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := srv.Serve(ctx, ln); err != nil {
		log.Fatalf("claver-agent serve: %v", err)
	}
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "claver")
	}
	return "./claver-data"
}
