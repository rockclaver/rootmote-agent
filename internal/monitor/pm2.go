package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KindPM2App watches one PM2 app. The target is "<user>/<app>": the login
// user that owns the PM2 daemon and the app's name.
const KindPM2App Kind = "pm2_app"

const (
	// pm2LoopRestarts restarts inside pm2LoopWindow mark an app as
	// restarting over and over.
	pm2LoopRestarts = 3
	pm2LoopWindow   = 5 * time.Minute
	// pm2LoopQuiet is how long the restart count must stay still before a
	// restart loop counts as over.
	pm2LoopQuiet = 60 * time.Second
)

// PM2App is one row of `priv pm2-list <user>`.
type PM2App struct {
	Name     string
	Status   string
	Restarts int
}

// PM2Source lists the PM2 apps one user runs. An empty list with no error
// means the user runs none.
type PM2Source interface {
	Apps(ctx context.Context, user string) ([]PM2App, error)
}

// PrivCaller runs one privilege-helper action (steps.PrivCaller has the same
// shape).
type PrivCaller interface {
	Call(ctx context.Context, action string, args ...string) ([]byte, error)
}

type privPM2Source struct{ priv PrivCaller }

// NewPM2Source reads PM2 apps through the read-only `pm2-list` helper action.
func NewPM2Source(priv PrivCaller) PM2Source { return privPM2Source{priv: priv} }

func (s privPM2Source) Apps(ctx context.Context, user string) ([]PM2App, error) {
	out, err := s.priv.Call(ctx, "pm2-list", user)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		App      string `json:"app"`
		Status   string `json:"status"`
		Restarts int    `json:"restarts"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("read pm2-list output: %w", err)
	}
	apps := make([]PM2App, 0, len(rows))
	for _, r := range rows {
		apps = append(apps, PM2App{Name: r.App, Status: r.Status, Restarts: r.Restarts})
	}
	return apps, nil
}

// ParsePM2Target splits "<user>/<app>".
func ParsePM2Target(target string) (user, app string, ok bool) {
	user, app, ok = strings.Cut(target, "/")
	if !ok || user == "" || app == "" {
		return "", "", false
	}
	return user, app, true
}

// pm2Track follows one app's restart count. A loop starts when
// pm2LoopRestarts increments land inside pm2LoopWindow and ends once the
// count has not moved for pm2LoopQuiet.
type pm2Track struct {
	lastCount    int
	increases    []time.Time
	looping      bool
	lastIncrease time.Time
}

func (t *pm2Track) observe(count int, now time.Time) bool {
	if count < t.lastCount {
		// PM2 reset its counters (or the app was recreated).
		t.lastCount = count
		t.increases = nil
	}
	if delta := count - t.lastCount; delta > 0 {
		for range delta {
			t.increases = append(t.increases, now)
		}
		t.lastCount = count
		t.lastIncrease = now
	}
	cutoff := now.Add(-pm2LoopWindow)
	kept := t.increases[:0]
	for _, at := range t.increases {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	t.increases = kept
	if len(t.increases) >= pm2LoopRestarts {
		t.looping = true
	}
	if t.looping && now.Sub(t.lastIncrease) >= pm2LoopQuiet {
		t.looping = false
		t.increases = nil
	}
	return t.looping
}

// PM2Evaluator evaluates pm2_app for every target with a definition. It fails
// when the app is missing, stopped or errored, or restarts over and over.
type PM2Evaluator struct {
	PM2  PM2Source
	Defs DefinitionResolver
	Now  func() time.Time

	tracks map[string]*pm2Track
}

func (e *PM2Evaluator) Kind() Kind { return KindPM2App }

func (e *PM2Evaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	targets := e.Defs.Targets(KindPM2App)
	if len(targets) == 0 {
		e.tracks = nil
		return nil, nil
	}
	if e.tracks == nil {
		e.tracks = map[string]*pm2Track{}
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	sort.Strings(targets)

	listed := map[string][]PM2App{}
	listErr := map[string]bool{}
	var out []Observation
	live := map[string]bool{}
	for _, target := range targets {
		def, enabled := e.Defs.Resolve(KindPM2App, target)
		if !enabled {
			continue
		}
		user, name, ok := ParsePM2Target(target)
		if !ok {
			continue
		}
		live[target] = true
		if listErr[user] {
			out = append(out, Observation{Target: target, Hold: true})
			continue
		}
		apps, seen := listed[user]
		if !seen {
			var err error
			apps, err = e.PM2.Apps(ctx, user)
			if err != nil {
				listErr[user] = true
				out = append(out, Observation{Target: target, Hold: true})
				continue
			}
			listed[user] = apps
		}

		var app *PM2App
		for i := range apps {
			if apps[i].Name == name {
				app = &apps[i]
				break
			}
		}
		if app == nil {
			delete(e.tracks, target)
			out = append(out, Observation{
				Target: target, Failing: true, Severity: severityOr(def, "critical"),
				Summary:    fmt.Sprintf("PM2 app %s (user %s) is missing", name, user),
				Attributes: map[string]string{"status": "missing"},
			})
			continue
		}

		tr := e.tracks[target]
		if tr == nil {
			tr = &pm2Track{lastCount: app.Restarts}
			e.tracks[target] = tr
		}
		loop := tr.observe(app.Restarts, now)
		status := strings.ToLower(app.Status)
		down := status == "stopped" || status == "errored"
		summary := fmt.Sprintf("PM2 app %s (user %s) is %s", name, user, status)
		if !down && loop {
			summary = fmt.Sprintf("PM2 app %s (user %s) keeps restarting (%d restarts within %s)", name, user, pm2LoopRestarts, pm2LoopWindow)
		}
		out = append(out, Observation{
			Target: target, Failing: down || loop, Severity: severityOr(def, "critical"), Summary: summary,
			Attributes: map[string]string{"status": status, "restarts": strconv.Itoa(app.Restarts)},
		})
	}
	for target := range e.tracks {
		if !live[target] {
			delete(e.tracks, target)
		}
	}
	return out, nil
}
