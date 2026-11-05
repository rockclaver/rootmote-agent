package monitor

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/infra"
)

// Event attribute keys carried by every observation of the sustained-value
// kinds so the relay and app can show "observed vs threshold" without
// parsing the summary.
const (
	attrObserved  = "observed"
	attrThreshold = "threshold"
	attrUnit      = "unit"
)

func fmtNum(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func valueAttrs(observed, threshold float64, unit string) map[string]string {
	return map[string]string{
		attrObserved:  fmtNum(observed),
		attrThreshold: fmtNum(threshold),
		attrUnit:      unit,
	}
}

func severityOr(def Definition, fallback string) string {
	if def.Severity != "" {
		return def.Severity
	}
	return fallback
}

// --- cpu_pressure --------------------------------------------------------

const (
	defaultCPUFire    = 95.0
	defaultCPURecover = 80.0
)

// CPUEvaluator evaluates the host-wide cpu_pressure monitor. Sustained-ness
// comes from the definition's failure threshold (default 10 ticks, ~5
// minutes), not from the evaluator.
type CPUEvaluator struct {
	Infra InfraSampler
	Defs  DefinitionResolver
	Held  WasFailingResolver
}

func (e *CPUEvaluator) Kind() Kind { return KindCPUPressure }

func (e *CPUEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	def, enabled := e.Defs.Resolve(KindCPUPressure, "")
	if !enabled {
		return nil, nil
	}
	cpu := e.Infra.Sample(ctx).CPU
	if !cpu.Available {
		return nil, nil
	}
	fire, recover := def.thresholds(defaultCPUFire, defaultCPURecover, true)
	failing := evalThreshold(cpu.Percent, fire, recover, e.Held.WasFailing(KindCPUPressure, ""))
	return []Observation{{
		Failing:    failing,
		Severity:   severityOr(def, "warning"),
		Summary:    fmt.Sprintf("CPU at %.0f%% (fires >=%.0f%%)", cpu.Percent, fire),
		Attributes: valueAttrs(cpu.Percent, fire, "%"),
	}}, nil
}

// --- load_per_core -------------------------------------------------------

const (
	defaultLoadFire    = 2.0
	defaultLoadRecover = 1.5
)

// LoadEvaluator evaluates load_per_core: 5-minute load average divided by
// the number of logical CPUs.
type LoadEvaluator struct {
	Infra InfraSampler
	Defs  DefinitionResolver
	Held  WasFailingResolver
	Cores func() int
}

func (e *LoadEvaluator) Kind() Kind { return KindLoadPerCore }

func (e *LoadEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	def, enabled := e.Defs.Resolve(KindLoadPerCore, "")
	if !enabled {
		return nil, nil
	}
	load := e.Infra.Sample(ctx).Load
	if !load.Available {
		return nil, nil
	}
	cores := runtime.NumCPU()
	if e.Cores != nil {
		cores = e.Cores()
	}
	if cores < 1 {
		cores = 1
	}
	perCore := load.Five / float64(cores)
	fire, recover := def.thresholds(defaultLoadFire, defaultLoadRecover, true)
	failing := evalThreshold(perCore, fire, recover, e.Held.WasFailing(KindLoadPerCore, ""))
	attrs := valueAttrs(perCore, fire, "x per core")
	attrs["load5"] = fmtNum(load.Five)
	attrs["cores"] = strconv.Itoa(cores)
	return []Observation{{
		Failing:    failing,
		Severity:   severityOr(def, "warning"),
		Summary:    fmt.Sprintf("5-min load %.2f on %d cores = %.2f per core (fires >=%.1f)", load.Five, cores, perCore, fire),
		Attributes: attrs,
	}}, nil
}

// --- disk_fill_rate ------------------------------------------------------

const (
	defaultFillWarnHours     = 24.0
	defaultFillRecoverHours  = 36.0
	defaultFillCriticalHours = 4.0
	defaultFillMinWindow     = 30 * time.Minute

	fillSampleEvery = time.Minute
	fillWindowMax   = 3 * time.Hour
	// fillMinR2 is the least-squares fit quality a window needs before its
	// slope is trusted; scattered writes that happen to net positive do not
	// qualify as a fill trend.
	fillMinR2 = 0.6
	// fillMinGrowthBytes / fillMinGrowthFraction: the fitted growth across
	// the window must exceed both, so a few MiB of log noise on a huge
	// volume never extrapolates to "full in 20 hours".
	fillMinGrowthBytes    = 64 << 20
	fillMinGrowthFraction = 0.002
	// fillResetDropFraction: a drop in used space bigger than this share of
	// capacity (a purge, a rotated backup) invalidates the history.
	fillResetDropFraction = 0.02
)

type fillSample struct {
	at   time.Time
	used float64
}

type fillWindow struct {
	samples []fillSample
	reset   bool // history was discarded after a large drop; report healthy until a new trend can be measured
}

// DiskFillEvaluator evaluates disk_fill_rate per mountpoint from a rolling
// in-memory window of used-bytes samples. The window is not persisted: after
// an agent restart it takes MinWindow to produce a verdict again, and while
// it is warming an already-firing episode simply holds its state.
type DiskFillEvaluator struct {
	Infra InfraSampler
	Defs  DefinitionResolver
	Held  WasFailingResolver
	Now   func() time.Time

	windows map[string]*fillWindow
}

func (e *DiskFillEvaluator) Kind() Kind { return KindDiskFillRate }

func (e *DiskFillEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *DiskFillEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	targets := e.Defs.Targets(KindDiskFillRate)
	if len(targets) == 0 {
		return nil, nil
	}
	if e.windows == nil {
		e.windows = map[string]*fillWindow{}
	}
	now := e.now()
	sample := e.Infra.Sample(ctx)
	byMount := make(map[string]infra.DiskMetric, len(sample.Disks))
	for _, d := range sample.Disks {
		byMount[d.Mountpoint] = d
	}
	var out []Observation
	for _, target := range targets {
		def, enabled := e.Defs.Resolve(KindDiskFillRate, target)
		if !enabled {
			continue
		}
		d, ok := byMount[target]
		if !ok || !d.Available || d.TotalBytes == 0 {
			continue
		}
		w := e.windows[target]
		if w == nil {
			w = &fillWindow{}
			e.windows[target] = w
		}
		e.record(w, d, now)

		minWindow := time.Duration(def.paramFloat("min_window_minutes", defaultFillMinWindow.Minutes()) * float64(time.Minute))
		span := time.Duration(0)
		if len(w.samples) > 1 {
			span = w.samples[len(w.samples)-1].at.Sub(w.samples[0].at)
		}
		if span < minWindow {
			if w.reset {
				out = append(out, Observation{
					Target: target, Severity: severityOr(def, "warning"),
					Summary: fmt.Sprintf("disk %s usage dropped; fill-rate history restarted", target),
				})
			}
			continue
		}
		w.reset = false

		fire, recover := def.thresholds(defaultFillWarnHours, defaultFillRecoverHours, false)
		critical := def.paramFloat("critical_hours", defaultFillCriticalHours)
		hours, trending := timeToFull(w.samples, float64(d.AvailableBytes), float64(d.TotalBytes))
		obs := Observation{Target: target, Severity: severityOr(def, "warning")}
		switch {
		case !trending:
			obs.Summary = fmt.Sprintf("disk %s has no sustained growth trend", target)
		default:
			limit := fire
			if e.Held.WasFailing(KindDiskFillRate, target) {
				limit = recover
			}
			obs.Failing = hours < limit
			obs.Summary = fmt.Sprintf("disk %s full in ~%s at current growth (alerts <%.0fh)", target, humanHours(hours), fire)
			obs.Attributes = valueAttrs(hours, fire, "hours")
			obs.Attributes["percent"] = fmtNum(d.Percent)
			if obs.Failing && hours < critical {
				obs.Severity = "critical"
			}
		}
		out = append(out, obs)
	}
	return out, nil
}

// record appends a sample at most once per fillSampleEvery, discards history
// after a large drop, and prunes anything older than fillWindowMax.
func (e *DiskFillEvaluator) record(w *fillWindow, d infra.DiskMetric, now time.Time) {
	used := float64(d.UsedBytes)
	if n := len(w.samples); n > 0 {
		last := w.samples[n-1]
		if last.used-used > fillResetDropFraction*float64(d.TotalBytes) {
			w.samples = w.samples[:0]
			w.reset = true
		} else if now.Sub(last.at) < fillSampleEvery {
			return
		}
	}
	w.samples = append(w.samples, fillSample{at: now, used: used})
	cut := 0
	for cut < len(w.samples)-1 && now.Sub(w.samples[cut].at) > fillWindowMax {
		cut++
	}
	w.samples = w.samples[cut:]
}

// timeToFull fits used bytes against time and, when the growth is a real
// sustained trend (good fit, material growth, both halves of the window
// growing), returns the hours until availBytes is consumed.
func timeToFull(samples []fillSample, availBytes, totalBytes float64) (hours float64, trending bool) {
	if len(samples) < 4 {
		return 0, false
	}
	slope, r2 := fitSlope(samples)
	if slope <= 0 || r2 < fillMinR2 {
		return 0, false
	}
	span := samples[len(samples)-1].at.Sub(samples[0].at).Seconds()
	if slope*span < math.Max(fillMinGrowthBytes, fillMinGrowthFraction*totalBytes) {
		return 0, false
	}
	mid := len(samples) / 2
	if s, _ := fitSlope(samples[:mid+1]); s <= 0 {
		return 0, false
	}
	if s, _ := fitSlope(samples[mid:]); s <= 0 {
		return 0, false
	}
	return availBytes / slope / 3600, true
}

// fitSlope returns the least-squares slope (bytes/second) and R^2.
func fitSlope(samples []fillSample) (slope, r2 float64) {
	n := float64(len(samples))
	t0 := samples[0].at
	var sx, sy, sxx, sxy, syy float64
	for _, s := range samples {
		x := s.at.Sub(t0).Seconds()
		sx += x
		sy += s.used
		sxx += x * x
		sxy += x * s.used
		syy += s.used * s.used
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0, 0
	}
	slope = (n*sxy - sx*sy) / den
	varY := n*syy - sy*sy
	if varY <= 0 {
		return slope, 0
	}
	r := (n*sxy - sx*sy) / math.Sqrt(den*varY)
	return slope, r * r
}

func humanHours(h float64) string {
	if h < 1 {
		return fmt.Sprintf("%.0fm", h*60)
	}
	return fmt.Sprintf("%.1fh", h)
}

// --- log_error_spike -----------------------------------------------------

const (
	defaultLogPattern    = `(?i)error|fatal|panic`
	defaultLogFire       = 50.0
	defaultLogMultiplier = 3.0
	logWindow            = 5 * time.Minute
	logReadEvery         = time.Minute
	// logBaselineMin is how many closed 5-minute samples must exist before
	// a spike can be judged against a baseline.
	logBaselineMin   = 3
	logBaselineMax   = 12
	logReadMaxBytes  = 4 << 20
	logJournalMaxRow = 20000
)

type logEvent struct {
	at time.Time
	n  int
}

type logTrack struct {
	lastRead    time.Time
	boundary    int64 // journald: unix second the next read starts at
	offset      int64 // file: size at last read
	started     bool
	events      []logEvent
	history     []int
	lastHistory time.Time
}

// LogSpikeEvaluator evaluates log_error_spike. A target that starts with "/"
// is a log file read incrementally (at most logReadMaxBytes per read);
// anything else is a systemd unit read with journalctl (at most
// logJournalMaxRow lines per read). Matching lines are counted over a
// trailing 5 minutes and compared with the mean of up to the last hour of
// 5-minute samples.
type LogSpikeEvaluator struct {
	Host Host
	Defs DefinitionResolver
	Held WasFailingResolver
	Now  func() time.Time

	tracks map[string]*logTrack
}

func (e *LogSpikeEvaluator) Kind() Kind { return KindLogErrorSpike }

func (e *LogSpikeEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *LogSpikeEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	targets := e.Defs.Targets(KindLogErrorSpike)
	if e.tracks == nil {
		e.tracks = map[string]*logTrack{}
	}
	now := e.now()
	var out []Observation
	var firstErr error
	for _, target := range targets {
		def, enabled := e.Defs.Resolve(KindLogErrorSpike, target)
		if !enabled {
			continue
		}
		pattern := def.param("pattern")
		if pattern == "" {
			pattern = defaultLogPattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue // the relay rejects invalid patterns; a stale definition is skipped
		}
		tr := e.tracks[target]
		if tr == nil {
			tr = &logTrack{}
			e.tracks[target] = tr
		}
		if now.Sub(tr.lastRead) >= logReadEvery {
			n, err := e.read(ctx, target, re, tr, now)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("monitor: log_error_spike %s: %w", target, err)
				}
				continue
			}
			tr.lastRead = now
			if n > 0 {
				tr.events = append(tr.events, logEvent{at: now, n: n})
			}
		}
		cutoff := now.Add(-logWindow)
		kept := tr.events[:0]
		count := 0
		for _, ev := range tr.events {
			if ev.at.After(cutoff) {
				kept = append(kept, ev)
				count += ev.n
			}
		}
		tr.events = kept

		ready := len(tr.history) >= logBaselineMin
		baseline := 0.0
		for _, h := range tr.history {
			baseline += float64(h)
		}
		if len(tr.history) > 0 {
			baseline /= float64(len(tr.history))
		}
		if tr.lastHistory.IsZero() || now.Sub(tr.lastHistory) >= logWindow {
			tr.history = append(tr.history, count)
			if len(tr.history) > logBaselineMax {
				tr.history = tr.history[len(tr.history)-logBaselineMax:]
			}
			tr.lastHistory = now
		}
		if !ready {
			continue
		}

		fire, recover := def.thresholds(defaultLogFire, defaultLogFire/2, true)
		mult := def.paramFloat("multiplier", defaultLogMultiplier)
		c := float64(count)
		var failing bool
		if e.Held.WasFailing(KindLogErrorSpike, target) {
			failing = c >= recover
		} else {
			failing = c > fire && c > mult*math.Max(baseline, 1)
		}
		attrs := valueAttrs(c, fire, "count")
		attrs["baseline"] = fmtNum(baseline)
		out = append(out, Observation{
			Target:     target,
			Failing:    failing,
			Severity:   severityOr(def, "warning"),
			Summary:    fmt.Sprintf("%s logged %d matching lines in 5m (baseline %.0f, fires >%.0f and >%.0fx baseline)", target, count, baseline, fire, mult),
			Attributes: attrs,
		})
	}
	return out, firstErr
}

// read returns the number of matching lines appended since the previous
// read. The first read of a file only records its size (its history has no
// timestamps); the first journald read covers the trailing logWindow.
func (e *LogSpikeEvaluator) read(ctx context.Context, target string, re *regexp.Regexp, tr *logTrack, now time.Time) (int, error) {
	if strings.HasPrefix(target, "/") {
		max := int64(logReadMaxBytes)
		if !tr.started {
			max = 0
		}
		data, size, err := e.Host.ReadFrom(target, tr.offset, max)
		if err != nil {
			return 0, err
		}
		tr.offset = size
		tr.started = true
		return countMatches(string(data), re), nil
	}
	until := now.Unix()
	since := tr.boundary
	if !tr.started {
		since = until - int64(logWindow.Seconds())
	}
	out, err := e.Host.Run(ctx, "journalctl", "-u", target, "--no-pager", "-q", "-o", "cat",
		"--since", "@"+strconv.FormatInt(since, 10), "--until", "@"+strconv.FormatInt(until, 10),
		"-n", strconv.Itoa(logJournalMaxRow))
	if err != nil {
		return 0, err
	}
	tr.boundary = until
	tr.started = true
	return countMatches(string(out), re), nil
}

func countMatches(text string, re *regexp.Regexp) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if line != "" && re.MatchString(line) {
			n++
		}
	}
	return n
}
