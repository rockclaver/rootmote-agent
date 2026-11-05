// Package steps is the typed catalog of fix steps the agent can run. Every
// step has one Go type with Validate, Run, Verify and Undo. A playbook can
// only name steps from this catalog; the agent never runs a free-form command.
//
// Steps that need root run through the privilege helper
// (`rootmote-agent priv <action> <args>`, see helper.go), which validates its
// own arguments again as root. Steps that do not need root run directly.
package steps

import (
	"bytes"
	"encoding/json"
)

// CatalogVersion is bumped whenever a step id, param or meaning changes.
const CatalogVersion = 1

// ID is a catalog step id such as "service.restart".
type ID string

const (
	ServiceRestartID    ID = "service.restart"
	ServiceStartID      ID = "service.start"
	ServiceStopID       ID = "service.stop"
	ServiceReloadID     ID = "service.reload"
	ContainerRestartID  ID = "container.restart"
	ComposeUpID         ID = "compose.up"
	PM2RestartID        ID = "pm2.restart"
	NginxReloadID       ID = "nginx.reload"
	PHPFPMRestartID     ID = "phpfpm.restart"
	SupervisorRestartID ID = "supervisor.restart"
	JournalVacuumID     ID = "disk.journal_vacuum"
	DockerPruneID       ID = "disk.docker_prune"
	AptCleanID          ID = "disk.apt_clean"
	CertRenewID         ID = "cert.renew"
	ProcessStopID       ID = "process.stop"
	FirewallAllowID     ID = "firewall.allow"
	FirewallRemoveID    ID = "firewall.remove"
	CheckHTTPID         ID = "check.http"
)

// Patterns shared by the catalog and the validators.
const (
	namePattern = `^[A-Za-z0-9@._:-]{1,128}$`
	certPattern = `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
	phpPattern  = `^php[0-9.]*-fpm(\.service)?$`
	sizePattern = `^(100M|200M|500M)$`
	protoPatten = `^(tcp|udp)$`
	urlPattern  = `^https?://[^\s]{1,1000}$`
)

// Param describes one step parameter. Source names the inventory list the
// value must come from (units, containers, compose_services, pm2_apps,
// supervisor_programs, certs, urls, ports or none).
type Param struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Pattern     string   `json:"pattern"`
	Enum        []string `json:"enum"`
	Source      string   `json:"source"`
	Description string   `json:"description"`
}

// Def is the machine-readable description of one step (contract C1).
type Def struct {
	ID          ID      `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Root        bool    `json:"root"`
	Params      []Param `json:"params"`
	Verify      string  `json:"verify"`
	Undo        ID      `json:"undo"`
}

type catalogDoc struct {
	CatalogVersion int   `json:"catalogVersion"`
	Steps          []Def `json:"steps"`
}

func nameParam(name, source, desc string) Param {
	return Param{Name: name, Type: "string", Pattern: namePattern, Enum: []string{}, Source: source, Description: desc}
}

func portParam() Param {
	return Param{Name: "port", Type: "integer", Pattern: "", Enum: []string{}, Source: "ports", Description: "port number from 1 to 65535"}
}

func protoParam() Param {
	return Param{Name: "proto", Type: "string", Pattern: protoPatten, Enum: []string{"tcp", "udp"}, Source: "none", Description: "tcp or udp"}
}

// Catalog returns every step in catalog order.
func Catalog() []Step {
	return []Step{
		ServiceRestart{}, ServiceStart{}, ServiceStop{}, ServiceReload{},
		ContainerRestart{}, ComposeUp{}, PM2Restart{}, NginxReload{},
		PHPFPMRestart{}, SupervisorRestart{},
		JournalVacuum{}, DockerPrune{}, AptClean{},
		CertRenew{}, ProcessStop{}, FirewallAllow{}, FirewallRemove{}, CheckHTTP{},
	}
}

// Lookup returns the step with the given id.
func Lookup(id ID) (Step, bool) {
	for _, s := range Catalog() {
		if s.Def().ID == id {
			return s, true
		}
	}
	return nil, false
}

// CatalogJSON is the exact output of `rootmote-agent steps --json`: 2-space
// indent, stable key order, trailing newline.
func CatalogJSON() ([]byte, error) {
	doc := catalogDoc{CatalogVersion: CatalogVersion}
	for _, s := range Catalog() {
		doc.Steps = append(doc.Steps, s.Def())
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UndoOf returns the undo step id and params for a step, or ok=false when the
// step cannot be undone. Undo steps reuse the original params.
func UndoOf(id ID, params Params) (ID, Params, bool) {
	s, ok := Lookup(id)
	if !ok {
		return "", nil, false
	}
	return s.Undo(params)
}
