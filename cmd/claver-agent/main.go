package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rockclaver/claver/agent/internal/server"
	"github.com/rockclaver/claver/agent/internal/version"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7676", "loopback bind address")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		// Phase 1 AC: bootstrap "prints the installed version on stdout".
		_, _ = os.Stdout.WriteString(version.Version + "\n")
		return
	}

	srv := server.New(server.Config{Addr: *addr})
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("claver-agent: %v", err)
	}
	log.Printf("claver-agent %s listening on %s", version.Version, ln.Addr())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := srv.Serve(ctx, ln); err != nil {
		log.Fatalf("claver-agent serve: %v", err)
	}
}
