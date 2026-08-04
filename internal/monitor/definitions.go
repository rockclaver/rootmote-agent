package monitor

import "sync"

// DefinitionResolver resolves the effective Definition for one (kind,target)
// -- relay-synced overrides win outright, falling back to a built-in
// default (an exact-target default, or a wildcard default for the
// dynamically-enumerated docker_container/systemd_unit kinds) -- and lists
// every target with an exact (non-wildcard) definition for a kind.
type DefinitionResolver interface {
	// Resolve returns the effective definition and whether it is enabled.
	// enabled=false covers both "no monitor exists for this (kind,target)"
	// and "a monitor exists but was disabled" -- either way the caller must
	// skip evaluation.
	Resolve(kind Kind, target string) (def Definition, enabled bool)
	// Targets lists every target with a concrete (non-wildcard) definition
	// for kind, from defaults and relay sync combined. Used by evaluators
	// whose live collector doesn't itself enumerate instances (disk/inode
	// mountpoints, the single host-wide memory target).
	Targets(kind Kind) []string
}

// DefinitionSet is a DefinitionResolver overlaying relay-synced monitor
// definitions on top of the built-in defaults. Safe for concurrent use: the
// engine's tick loop reads it while a separate periodic sync goroutine calls
// SetSynced.
type DefinitionSet struct {
	mu       sync.RWMutex
	defaults map[string]Definition
	synced   map[string]Definition
}

// NewDefinitionSet builds a DefinitionSet from the given defaults (normally
// DefaultDefinitions()).
func NewDefinitionSet(defaults []Definition) *DefinitionSet {
	d := &DefinitionSet{defaults: make(map[string]Definition, len(defaults)), synced: map[string]Definition{}}
	for _, def := range defaults {
		d.defaults[key(def.Kind, def.Target)] = def
	}
	return d
}

// SetSynced replaces the relay-synced overlay wholesale (a fresh sync
// response fully supersedes the previous one).
func (d *DefinitionSet) SetSynced(defs []Definition) {
	m := make(map[string]Definition, len(defs))
	for _, def := range defs {
		m[key(def.Kind, def.Target)] = def
	}
	d.mu.Lock()
	d.synced = m
	d.mu.Unlock()
}

// Resolve implements DefinitionResolver.
func (d *DefinitionSet) Resolve(kind Kind, target string) (Definition, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	k := key(kind, target)
	if def, ok := d.synced[k]; ok {
		return def, def.Enabled
	}
	// Dynamic monitor kinds (Docker/systemd) can be configured once for all
	// discovered targets using a relay-synced "*" definition. It must win
	// over the shipped wildcard default so disabling it really stops every
	// target's evaluation.
	if def, ok := d.synced[key(kind, wildcardTarget)]; ok {
		def.Target = target
		return def, def.Enabled
	}
	if def, ok := d.defaults[k]; ok {
		return def, def.Enabled
	}
	if def, ok := d.defaults[key(kind, wildcardTarget)]; ok {
		def.Target = target
		return def, def.Enabled
	}
	return Definition{}, false
}

// Targets implements DefinitionResolver.
func (d *DefinitionSet) Targets(kind Kind) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	add := func(def Definition) {
		if def.Kind != kind || def.Target == wildcardTarget || seen[def.Target] {
			return
		}
		seen[def.Target] = true
		out = append(out, def.Target)
	}
	for _, def := range d.defaults {
		add(def)
	}
	for _, def := range d.synced {
		add(def)
	}
	return out
}
