// Package playbook turns an incident into a fix the user can approve. A
// playbook is a short list of catalog steps (internal/steps) plus manual
// steps the user does by hand. Known problems get a playbook from fixed rules
// (FromSignature); everything else is asked of the playbook service
// (Generator). Either way the result is checked against the catalog and the
// server's own inventory before it becomes a runbook for approval.
package playbook

import (
	"sort"
	"strings"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// MaxSteps is the most executable steps one playbook may hold.
const MaxSteps = 6

// Step is one catalog step with its parameters.
type Step struct {
	Step   steps.ID     `json:"step"`
	Params steps.Params `json:"params"`
}

// Manual is a step the user does by hand. Command is text to copy; the
// agent never runs it.
type Manual struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// Playbook is a proposed fix. Source is "catalog" or "generated".
type Playbook struct {
	Title           string
	Summary         string
	Source          string
	ReviewCarefully bool
	Steps           []Step
	Manual          []Manual
}

// ComposePair names a Compose service and its project.
type ComposePair struct {
	Project string
	Service string
}

// PM2App names a PM2 app and its owner.
type PM2App struct {
	User string
	App  string
}

// Inventory is the names on this server a step may target. It holds names
// only: no paths, no settings, no values.
type Inventory struct {
	Units              []string
	Containers         []string
	ComposeServices    []ComposePair
	PM2Apps            []PM2App
	SupervisorPrograms []string
	Certs              []string
	URLs               []string
	Ports              []int
}

// OSInfo names the Linux distribution.
type OSInfo struct {
	Distro  string
	Version string
}

// Facts is everything the fixed rules look at for one incident.
type Facts struct {
	Inventory Inventory
	// Bundle is the redacted evidence collected for the incident.
	Bundle diagnose.Bundle
	// Signatures are the matches against Bundle (diagnose.Match). When nil,
	// FromBundle computes them.
	Signatures []diagnose.Signature
	OS         OSInfo
	// Target is the monitor target of the incident (a URL for web checks).
	Target string
	// DiskMounts maps each disk step to the mount point that holds the folder
	// it frees space in (journal, apt cache, Docker's data directory). A step
	// that is missing is not known to free space anywhere and is not offered.
	DiskMounts map[steps.ID]string
}

func (i Inventory) hasUnit(name string) bool {
	return contains(i.Units, name)
}

func (i Inventory) hasContainer(name string) bool {
	return contains(i.Containers, name)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Wire converts the inventory to the request shape. Names that the shared
// redaction rules would change are left out: they could not be sent without
// being altered, and an altered name would not match anything on the server.
func (i Inventory) wire(clean func(string) bool) watchtower.PlaybookInventory {
	keep := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			if s != "" && clean(s) {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	w := watchtower.PlaybookInventory{
		Units:              keep(i.Units),
		Containers:         keep(i.Containers),
		SupervisorPrograms: keep(i.SupervisorPrograms),
		Certs:              keep(i.Certs),
		URLs:               keep(i.URLs),
		ComposeServices:    []watchtower.PlaybookCompose{},
		PM2Apps:            []watchtower.PlaybookPM2{},
		Ports:              append([]int{}, i.Ports...),
	}
	for _, c := range i.ComposeServices {
		if clean(c.Project) && clean(c.Service) {
			w.ComposeServices = append(w.ComposeServices, watchtower.PlaybookCompose{Project: c.Project, Service: c.Service})
		}
	}
	for _, p := range i.PM2Apps {
		if clean(p.User) && clean(p.App) {
			w.PM2Apps = append(w.PM2Apps, watchtower.PlaybookPM2{User: p.User, App: p.App})
		}
	}
	sort.Ints(w.Ports)
	return w
}

func lowerBase(unit string) string {
	return strings.TrimSuffix(strings.ToLower(unit), ".service")
}
