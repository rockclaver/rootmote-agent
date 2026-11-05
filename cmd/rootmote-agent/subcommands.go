package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/rockclaver/rootmote-agent/internal/steps"
)

// runPriv implements `rootmote-agent priv <action> [args...]`: the privilege
// helper. It is meant to run as root through the single sudoers rule
//
//	rootmote ALL=(root) NOPASSWD: /usr/local/bin/rootmote-agent priv *
//
// and validates every argument itself. Exit codes: 0 ok, 2 refused (stderr
// holds one plain-English sentence), 1 failed.
func runPriv(args []string) int {
	return steps.RunPriv(context.Background(), steps.NewOSHost(), args, os.Stdout, os.Stderr)
}

// runSteps implements `rootmote-agent steps [--json]`. With --json it prints
// the step catalog (contract C1) exactly as Watchtower vendors it.
func runSteps(args []string, out io.Writer) int {
	asJSON := false
	for _, a := range args {
		if a != "--json" {
			fmt.Fprintln(os.Stderr, "usage: rootmote-agent steps [--json]")
			return 2
		}
		asJSON = true
	}
	if asJSON {
		b, err := steps.CatalogJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_, _ = out.Write(b)
		return 0
	}
	for _, s := range steps.Catalog() {
		d := s.Def()
		root := ""
		if d.Root {
			root = " (root)"
		}
		fmt.Fprintf(out, "%-22s %s%s\n", d.ID, d.Title, root)
	}
	return 0
}
