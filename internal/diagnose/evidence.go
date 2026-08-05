// Package diagnose implements the agent-side bounded diagnostic pipeline
// (PRD 12/13): collect a small, redacted evidence bundle for an incident,
// run deterministic signature checks against it, and optionally ask an AI
// provider to summarize it. Raw evidence never leaves the server: every
// piece of text this package puts into a Bundle has already passed through
// a redact.Redactor.
package diagnose

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// Service identifies the incident's affected service and its current
// observed status.
type Service struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"` // up | down | degraded | unknown
}

// Signal is a deterministic, Collector-computed numeric observation (e.g. a
// restart count or an OOM-kill tally) that signatures.go's Match uses as
// evidence.
type Signal struct {
	ID            string  `json:"id"`
	Type          string  `json:"type"`
	Value         float64 `json:"value,omitempty"`
	WindowSeconds int     `json:"windowSeconds,omitempty"`
	Detail        string  `json:"detail,omitempty"`
}

// LogExcerpt is a bounded, redacted tail of a log source.
type LogExcerpt struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	LineCount int    `json:"lineCount"`
	Truncated bool   `json:"truncated"`
	Redacted  bool   `json:"redacted"`
	Content   string `json:"content"`
}

// Component is a point-in-time snapshot of one piece of host state (a
// container, a systemd unit, a webserver instance).
type Component struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Health string `json:"health,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Change is a recent, diagnostically relevant host event (a restart, a
// deployment).
type Change struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurredAt"`
	Detail     string    `json:"detail,omitempty"`
}

// Metric is a single named resource-pressure measurement.
type Metric struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}

// Bundle is the full, REDACTED evidence collected for one incident. It is
// never posted to the relay; only its derived Assessment.Summary() is.
type Bundle struct {
	IncidentID    string        `json:"incidentId"`
	CapturedAt    time.Time     `json:"capturedAt"`
	Service       Service       `json:"service"`
	Redaction     redact.Report `json:"redaction"`
	Signals       []Signal      `json:"signals"`
	Logs          []LogExcerpt  `json:"logs"`
	Components    []Component   `json:"components"`
	RecentChanges []Change      `json:"recentChanges"`
	Metrics       []Metric      `json:"metrics"`
	Warnings      []string      `json:"warnings"`
	DroppedItems  int           `json:"droppedItems"`
}

// EvidenceIDs returns every id in the bundle, sorted. Used to validate that
// AI hypotheses reference real evidence.
func (b Bundle) EvidenceIDs() []string {
	ids := make([]string, 0, len(b.Signals)+len(b.Logs)+len(b.Components)+len(b.RecentChanges)+len(b.Metrics))
	for _, s := range b.Signals {
		ids = append(ids, s.ID)
	}
	for _, l := range b.Logs {
		ids = append(ids, l.ID)
	}
	for _, c := range b.Components {
		ids = append(ids, c.ID)
	}
	for _, c := range b.RecentChanges {
		ids = append(ids, c.ID)
	}
	for _, m := range b.Metrics {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return ids
}

// Default budget values; see Budget.
const (
	DefaultMaxLogLines  = 200
	DefaultMaxItemBytes = 16 * 1024
	DefaultMaxItems     = 32
	DefaultReadTimeout  = 10 * time.Second
	DefaultTotalTimeout = 30 * time.Second
	DefaultChangeWindow = 30 * time.Minute
)

// Budget bounds a collection pass. Zero fields take the Default* values.
type Budget struct {
	MaxLogLines  int           // DefaultMaxLogLines = 200
	MaxItemBytes int           // DefaultMaxItemBytes = 16 * 1024
	MaxItems     int           // DefaultMaxItems = 32
	ReadTimeout  time.Duration // DefaultReadTimeout = 10 * time.Second
	TotalTimeout time.Duration // DefaultTotalTimeout = 30 * time.Second
	ChangeWindow time.Duration // DefaultChangeWindow = 30 * time.Minute
}

func (b Budget) withDefaults() Budget {
	if b.MaxLogLines <= 0 {
		b.MaxLogLines = DefaultMaxLogLines
	}
	if b.MaxItemBytes <= 0 {
		b.MaxItemBytes = DefaultMaxItemBytes
	}
	if b.MaxItems <= 0 {
		b.MaxItems = DefaultMaxItems
	}
	if b.ReadTimeout <= 0 {
		b.ReadTimeout = DefaultReadTimeout
	}
	if b.TotalTimeout <= 0 {
		b.TotalTimeout = DefaultTotalTimeout
	}
	if b.ChangeWindow <= 0 {
		b.ChangeWindow = DefaultChangeWindow
	}
	return b
}

// Narrow source interfaces so tests inject fakes instead of real managers.
//
// These match the REAL manager method sets, not a hypothetical sketch:
// *infra.Manager.Sample and *webserver.Manager.List do not return an error
// (a source-level failure shows up as an unavailable/empty result instead),
// and *systemd.Manager.Get returns systemd.UnitDetail (which embeds Unit).
// *systemd.Manager has no unit-log-reading method at all; a caller wiring a
// real SystemdSource must supply an adapter (e.g. shelling out to
// `journalctl -u <unit>`).
type DockerSource interface {
	Containers(ctx context.Context) ([]docker.ContainerSummary, error)
	Container(ctx context.Context, id string) (docker.ContainerDetail, error)
	Logs(ctx context.Context, id string, tail int) ([]docker.LogEntry, error)
}

type SystemdSource interface {
	Get(ctx context.Context, name string) (systemd.UnitDetail, error)
	List(ctx context.Context) ([]systemd.Unit, error)
	Logs(ctx context.Context, unit string, tail int) (string, error)
}

type InfraSource interface {
	Sample(ctx context.Context) infra.HostMetrics
	OOMEvents(ctx context.Context, since time.Time) ([]infra.OOMEvent, error)
}

type WebserverSource interface {
	List(ctx context.Context) webserver.Snapshot
}

// CollectorConfig configures a Collector. Every source is optional; a nil
// source contributes a Warning instead of evidence.
type CollectorConfig struct {
	Docker    DockerSource    // optional
	Systemd   SystemdSource   // optional
	Infra     InfraSource     // optional
	Webserver WebserverSource // optional
	Redactor  *redact.Redactor
	Budget    Budget
	Now       func() time.Time
}

// Collector runs the bounded PRD 12.1 evidence-collection workflow.
type Collector struct {
	docker    DockerSource
	systemd   SystemdSource
	infra     InfraSource
	webserver WebserverSource
	redactor  *redact.Redactor
	budget    Budget
	now       func() time.Time
}

// NewCollector builds a Collector from cfg, applying Budget defaults. A nil
// cfg.Redactor falls back to a Redactor with no user patterns so Collect is
// always safe to call.
func NewCollector(cfg CollectorConfig) *Collector {
	redactor := cfg.Redactor
	if redactor == nil {
		redactor, _ = redact.New(nil)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Collector{
		docker:    cfg.Docker,
		systemd:   cfg.Systemd,
		infra:     cfg.Infra,
		webserver: cfg.Webserver,
		redactor:  redactor,
		budget:    cfg.Budget.withDefaults(),
		now:       now,
	}
}

// Target names what failed: the monitor kind and target from the incident.
type Target struct {
	IncidentID  string
	MonitorKind string // docker_container | systemd_unit | disk_capacity | …
	Target      string
}

// Collect runs the bounded PRD 12.1 workflow and returns a REDACTED bundle.
// It never returns an error for a partially available host: a failing
// collector appends to Warnings and leaves its section empty.
func (c *Collector) Collect(ctx context.Context, t Target) Bundle {
	now := c.now()
	cctx, cancel := context.WithTimeout(ctx, c.budget.TotalTimeout)
	defer cancel()

	b := Bundle{
		IncidentID: t.IncidentID,
		CapturedAt: now,
		Service:    Service{Name: t.Target, Kind: t.MonitorKind, Status: "unknown"},
	}
	ids := newIDAllocator()

	switch t.MonitorKind {
	case "docker_container":
		c.collectDocker(cctx, t, &b, ids)
	case "systemd_unit":
		c.collectSystemd(cctx, t, &b, ids)
	}

	if cctx.Err() != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("collection budget exceeded before host metrics could be gathered: %s", cctx.Err()))
		return b
	}
	c.collectInfra(cctx, &b, ids)
	c.collectWebserver(cctx, &b, ids)
	return b
}

// itemBudgetOK reports whether one more item may be added to b. When the
// budget is exhausted it increments DroppedItems and returns false.
func (c *Collector) itemBudgetOK(b *Bundle) bool {
	total := len(b.Signals) + len(b.Logs) + len(b.Components) + len(b.RecentChanges) + len(b.Metrics)
	if total >= c.budget.MaxItems {
		b.DroppedItems++
		return false
	}
	return true
}

// --- docker ---

func (c *Collector) collectDocker(ctx context.Context, t Target, b *Bundle, ids *idAllocator) {
	if c.docker == nil {
		b.Warnings = append(b.Warnings, "docker evidence unavailable: no docker source configured")
		return
	}

	rctx, cancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	summaries, err := c.docker.Containers(rctx)
	cancel()
	if err != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("docker containers unavailable: %s", err))
		return
	}

	var primary *docker.ContainerSummary
	for i := range summaries {
		if strings.EqualFold(summaries[i].Name, t.Target) {
			primary = &summaries[i]
			break
		}
	}
	if primary == nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("docker container %q not found", t.Target))
		return
	}

	var detail *docker.ContainerDetail
	dctx, dcancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	if d, derr := c.docker.Container(dctx, primary.ID); derr == nil {
		detail = &d
	} else {
		b.Warnings = append(b.Warnings, fmt.Sprintf("docker container %q detail unavailable: %s", t.Target, derr))
	}
	dcancel()

	if c.itemBudgetOK(b) {
		comp, rep := c.buildDockerComponent(ids, *primary, detail)
		b.Redaction.Merge(rep)
		b.Components = append(b.Components, comp)
	}
	b.Service.Status = dockerStatus(*primary)

	project := primary.ComposeProject
	if detail != nil && detail.ComposeProject != "" {
		project = detail.ComposeProject
	}
	if project != "" {
		for i := range summaries {
			s := summaries[i]
			if s.ID == primary.ID || s.ComposeProject != project {
				continue
			}
			if !c.itemBudgetOK(b) {
				break
			}
			comp, rep := c.buildDockerComponent(ids, s, nil)
			b.Redaction.Merge(rep)
			b.Components = append(b.Components, comp)
		}
	}

	lctx, lcancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	entries, lerr := c.docker.Logs(lctx, primary.ID, c.budget.MaxLogLines)
	lcancel()
	if lerr != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("docker logs for %q unavailable: %s", t.Target, lerr))
	} else if c.itemBudgetOK(b) {
		lines := make([]string, 0, len(entries))
		for _, e := range entries {
			lines = append(lines, e.Line)
		}
		excerpt, rep, dropped := c.buildLog(ids, "docker:"+primary.Name, lines)
		b.Redaction.Merge(rep)
		b.DroppedItems += dropped
		b.Logs = append(b.Logs, excerpt)
	}

	if detail == nil {
		return
	}
	if detail.RestartCount >= restartLoopThreshold && c.itemBudgetOK(b) {
		text := fmt.Sprintf("%s restarted %d times", primary.Name, detail.RestartCount)
		redacted, rep := c.redactor.Text(text)
		b.Redaction.Merge(rep)
		b.Signals = append(b.Signals, Signal{
			ID:     ids.id("sig_container_restart_loop"),
			Type:   "container_restart_loop",
			Value:  float64(detail.RestartCount),
			Detail: redacted,
		})
	}
	if detail.RestartCount > 0 && c.itemBudgetOK(b) {
		text := fmt.Sprintf("%s restarted (%d recorded restarts)", primary.Name, detail.RestartCount)
		redacted, rep := c.redactor.Text(text)
		b.Redaction.Merge(rep)
		b.RecentChanges = append(b.RecentChanges, Change{
			ID:         ids.changeID("container_restart"),
			Type:       "container_restart",
			OccurredAt: c.now(),
			Detail:     redacted,
		})
	}
}

// restartLoopThreshold is the RestartCount at or above which the Collector
// records a container_restart_loop Signal.
const restartLoopThreshold = 3

func dockerStatus(s docker.ContainerSummary) string {
	if !strings.EqualFold(s.State, "running") {
		return "down"
	}
	if strings.EqualFold(s.Health, "unhealthy") {
		return "degraded"
	}
	return "up"
}

// buildDockerComponent redacts every piece of text derived from s/detail
// before it enters the returned Component; the caller merges the returned
// Report into Bundle.Redaction.
func (c *Collector) buildDockerComponent(ids *idAllocator, s docker.ContainerSummary, detail *docker.ContainerDetail) (Component, redact.Report) {
	var rep redact.Report
	var parts []string
	switch {
	case detail != nil && detail.Status != "":
		parts = append(parts, detail.Status)
	case s.Status != "":
		parts = append(parts, s.Status)
	}
	if detail != nil {
		if detail.RestartCount > 0 {
			parts = append(parts, fmt.Sprintf("restarts=%d", detail.RestartCount))
		}
		if len(detail.EnvironmentVars) > 0 {
			env := make(map[string]string, len(detail.EnvironmentVars))
			for _, e := range detail.EnvironmentVars {
				env[e.Key] = e.Value
			}
			redactedEnv, envRep := c.redactor.Map(env)
			rep.Merge(envRep)
			parts = append(parts, "env: "+formatEnv(redactedEnv))
		}
	}
	detailText, textRep := c.redactor.Text(strings.Join(parts, "; "))
	rep.Merge(textRep)

	return Component{
		ID:     ids.id(fmt.Sprintf("cmp_docker_%s", sanitize(s.Name))),
		Kind:   "docker_container",
		Name:   s.Name,
		State:  s.State,
		Health: s.Health,
		Detail: detailText,
	}, rep
}

// --- systemd ---

func (c *Collector) collectSystemd(ctx context.Context, t Target, b *Bundle, ids *idAllocator) {
	if c.systemd == nil {
		b.Warnings = append(b.Warnings, "systemd evidence unavailable: no systemd source configured")
		return
	}

	rctx, cancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	unit, err := c.systemd.Get(rctx, t.Target)
	cancel()
	if err != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("systemd unit %q unavailable: %s", t.Target, err))
		return
	}

	if c.itemBudgetOK(b) {
		comp, rep := c.buildSystemdComponent(ids, unit)
		b.Redaction.Merge(rep)
		b.Components = append(b.Components, comp)
	}
	b.Service.Status = systemdStatus(unit.Unit)

	lctx, lcancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	raw, lerr := c.systemd.Logs(lctx, t.Target, c.budget.MaxLogLines)
	lcancel()
	if lerr != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("systemd logs for %q unavailable: %s", t.Target, lerr))
		return
	}
	if !c.itemBudgetOK(b) {
		return
	}
	excerpt, rep, dropped := c.buildLog(ids, "systemd:"+t.Target, strings.Split(raw, "\n"))
	b.Redaction.Merge(rep)
	b.DroppedItems += dropped
	b.Logs = append(b.Logs, excerpt)
}

func systemdStatus(u systemd.Unit) string {
	switch strings.ToLower(u.ActiveState) {
	case "active":
		return "up"
	case "activating", "reloading":
		return "degraded"
	case "":
		return "unknown"
	default:
		return "down"
	}
}

func (c *Collector) buildSystemdComponent(ids *idAllocator, unit systemd.UnitDetail) (Component, redact.Report) {
	var parts []string
	if unit.SubState != "" {
		parts = append(parts, "sub_state="+unit.SubState)
	}
	if unit.LoadState != "" {
		parts = append(parts, "load_state="+unit.LoadState)
	}
	if unit.FragmentPath != "" {
		parts = append(parts, "unit_file="+unit.FragmentPath)
	}
	if unit.Following != "" {
		parts = append(parts, "following="+unit.Following)
	}
	detailText, rep := c.redactor.Text(strings.Join(parts, "; "))
	return Component{
		ID:     ids.id(fmt.Sprintf("cmp_systemd_%s", sanitize(unit.Name))),
		Kind:   "systemd_unit",
		Name:   unit.Name,
		State:  unit.ActiveState,
		Detail: detailText,
	}, rep
}

// --- infra ---

func (c *Collector) collectInfra(ctx context.Context, b *Bundle, ids *idAllocator) {
	if c.infra == nil {
		b.Warnings = append(b.Warnings, "infra evidence unavailable: no infra source configured")
		return
	}

	rctx, cancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	hm := c.infra.Sample(rctx)
	deadlineErr := rctx.Err()
	cancel()
	if deadlineErr != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("infra metrics unavailable: %s", deadlineErr))
	} else {
		c.addInfraMetrics(hm, b, ids)
	}

	octx, ocancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	events, oerr := c.infra.OOMEvents(octx, c.now().Add(-c.budget.ChangeWindow))
	ocancel()
	switch {
	case oerr != nil:
		b.Warnings = append(b.Warnings, fmt.Sprintf("oom events unavailable: %s", oerr))
	case len(events) > 0 && c.itemBudgetOK(b):
		last := events[len(events)-1]
		text := fmt.Sprintf("%d OOM kill(s) in the last %s, most recent: pid %d process %q", len(events), c.budget.ChangeWindow, last.PID, last.Process)
		redacted, rep := c.redactor.Text(text)
		b.Redaction.Merge(rep)
		b.Signals = append(b.Signals, Signal{
			ID:            ids.id("sig_oom_kill"),
			Type:          "oom_kill",
			Value:         float64(len(events)),
			WindowSeconds: int(c.budget.ChangeWindow.Seconds()),
			Detail:        redacted,
		})
	}
}

func (c *Collector) addInfraMetrics(hm infra.HostMetrics, b *Bundle, ids *idAllocator) {
	add := func(id, name string, value float64, unit string) {
		if !c.itemBudgetOK(b) {
			return
		}
		b.Metrics = append(b.Metrics, Metric{ID: ids.id(id), Name: name, Value: value, Unit: unit})
	}
	if hm.Memory.Available {
		add("met_available_memory_percent", "available_memory_percent", 100-hm.Memory.Percent, "%")
	}
	if hm.Swap.Available {
		add("met_swap_used_percent", "swap_used_percent", hm.Swap.Percent, "%")
	}
	if hm.Load.Available {
		add("met_load_one", "load_one", hm.Load.One, "")
	}
	for _, d := range hm.Disks {
		if !d.Available {
			continue
		}
		mount := sanitize(d.Mountpoint)
		add("met_disk_used_percent_"+mount, "disk_used_percent", d.Percent, "%")
		add("met_inode_used_percent_"+mount, "inode_used_percent", d.InodePercent, "%")
	}
}

// --- webserver ---

func (c *Collector) collectWebserver(ctx context.Context, b *Bundle, ids *idAllocator) {
	if c.webserver == nil {
		b.Warnings = append(b.Warnings, "webserver evidence unavailable: no webserver source configured")
		return
	}

	rctx, cancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	snap := c.webserver.List(rctx)
	cancel()
	if !snap.Available {
		msg := "webserver evidence unavailable"
		if len(snap.Warnings) > 0 {
			msg += ": " + strings.Join(snap.Warnings, "; ")
		}
		b.Warnings = append(b.Warnings, msg)
		return
	}
	for _, w := range snap.Warnings {
		b.Warnings = append(b.Warnings, "webserver: "+w)
	}
	for _, inst := range snap.Webservers {
		if !c.itemBudgetOK(b) {
			break
		}
		hosts := make([]string, 0, len(inst.Domains))
		for _, d := range inst.Domains {
			hosts = append(hosts, d.Host)
		}
		text := fmt.Sprintf("kind=%s domains=%s", inst.Kind, strings.Join(hosts, ","))
		redacted, rep := c.redactor.Text(text)
		b.Redaction.Merge(rep)
		b.Components = append(b.Components, Component{
			ID:     ids.id(fmt.Sprintf("cmp_webserver_%s", sanitize(inst.ID))),
			Kind:   "webserver_instance",
			Name:   inst.ID,
			State:  inst.ActiveState,
			Detail: redacted,
		})
	}
}

// --- shared log bounding/redaction ---

// buildLog trims lines to the MaxLogLines budget (keeping the most recent),
// redacts the joined content, then trims to the MaxItemBytes budget. It
// returns the extra Report for the caller to merge and the number of lines
// dropped by the line-count bound (the caller adds this to
// Bundle.DroppedItems).
func (c *Collector) buildLog(ids *idAllocator, source string, lines []string) (LogExcerpt, redact.Report, int) {
	total := len(lines)
	truncated := false
	dropped := 0
	if total > c.budget.MaxLogLines {
		dropped = total - c.budget.MaxLogLines
		lines = lines[total-c.budget.MaxLogLines:]
		truncated = true
	}
	redacted, rep := c.redactor.Text(strings.Join(lines, "\n"))
	if len(redacted) > c.budget.MaxItemBytes {
		redacted = redacted[:c.budget.MaxItemBytes]
		truncated = true
	}
	return LogExcerpt{
		ID:        ids.id("log_" + sanitize(source)),
		Source:    source,
		LineCount: len(lines),
		Truncated: truncated,
		Redacted:  true,
		Content:   redacted,
	}, rep, dropped
}

// --- ids ---

// idAllocator hands out deterministic, bundle-unique evidence ids. Base ids
// (sig_<type>, log_<source>, cmp_<kind>_<name>, met_<name>) are unique by
// construction in the common case; a numeric suffix is appended only on
// collision so ids stay stable when nothing collides.
type idAllocator struct {
	used   map[string]int
	change map[string]int
}

func newIDAllocator() *idAllocator {
	return &idAllocator{used: map[string]int{}, change: map[string]int{}}
}

func (a *idAllocator) id(base string) string {
	a.used[base]++
	if a.used[base] == 1 {
		return base
	}
	return fmt.Sprintf("%s_%d", base, a.used[base])
}

// changeID implements the chg_<type>_<n> scheme: n always starts at 1 and
// increments per type, so multiple changes of the same type are distinct
// and stable in the order they were recorded.
func (a *idAllocator) changeID(typ string) string {
	a.change[typ]++
	return fmt.Sprintf("chg_%s_%d", typ, a.change[typ])
}

// sanitize lower-cases s and replaces characters that would be awkward in
// an id (':', '/', whitespace) with '_'.
func sanitize(s string) string {
	s = strings.ToLower(s)
	replacer := strings.NewReplacer(":", "_", "/", "_", " ", "_", "\t", "_")
	return replacer.Replace(s)
}

func formatEnv(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ", ")
}
