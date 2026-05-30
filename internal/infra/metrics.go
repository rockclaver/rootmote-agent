// Package infra collects read-only host infrastructure metrics from native
// Linux procfs/sysfs/statfs sources.
package infra

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ReasonUnavailable = "unavailable"
	ReasonParseError  = "parse_error"
)

type MetricReason struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

type CPUMetric struct {
	MetricReason
	Percent float64 `json:"percent,omitempty"`
}

type LoadMetric struct {
	MetricReason
	One     float64 `json:"one,omitempty"`
	Five    float64 `json:"five,omitempty"`
	Fifteen float64 `json:"fifteen,omitempty"`
}

type MemoryMetric struct {
	MetricReason
	TotalBytes     uint64  `json:"total_bytes,omitempty"`
	AvailableBytes uint64  `json:"available_bytes,omitempty"`
	UsedBytes      uint64  `json:"used_bytes,omitempty"`
	Percent        float64 `json:"percent,omitempty"`
}

type DiskMetric struct {
	Mountpoint     string  `json:"mountpoint"`
	Filesystem     string  `json:"filesystem,omitempty"`
	TotalBytes     uint64  `json:"total_bytes,omitempty"`
	AvailableBytes uint64  `json:"available_bytes,omitempty"`
	UsedBytes      uint64  `json:"used_bytes,omitempty"`
	Percent        float64 `json:"percent,omitempty"`
	Available      bool    `json:"available"`
	Reason         string  `json:"reason,omitempty"`
	Message        string  `json:"message,omitempty"`
}

type NetworkMetric struct {
	MetricReason
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec,omitempty"`
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec,omitempty"`
}

type HostMetrics struct {
	Timestamp time.Time     `json:"timestamp"`
	CPU       CPUMetric     `json:"cpu"`
	Load      LoadMetric    `json:"load"`
	Memory    MemoryMetric  `json:"memory"`
	Swap      MemoryMetric  `json:"swap"`
	Disks     []DiskMetric  `json:"disks"`
	Network   NetworkMetric `json:"network"`
}

type FileReader interface {
	ReadFile(name string) ([]byte, error)
}

type osReader struct{}

func (osReader) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

type StatFS func(path string) (syscall.Statfs_t, error)

type Config struct {
	ProcRoot string
	SysRoot  string
	Reader   FileReader
	StatFS   StatFS
	Now      func() time.Time
	Cadence  time.Duration
}

type Manager struct {
	procRoot string
	sysRoot  string
	reader   FileReader
	statFS   StatFS
	now      func() time.Time
	cadence  time.Duration

	mu       sync.Mutex
	lastCPU  cpuTimes
	lastNet  map[string]netCounters
	lastTime time.Time
}

func New(cfg Config) (*Manager, error) {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.SysRoot == "" {
		cfg.SysRoot = "/sys"
	}
	if cfg.Reader == nil {
		cfg.Reader = osReader{}
	}
	if cfg.StatFS == nil {
		cfg.StatFS = func(path string) (syscall.Statfs_t, error) {
			var st syscall.Statfs_t
			err := syscall.Statfs(path, &st)
			return st, err
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Cadence <= 0 {
		cfg.Cadence = time.Second
	}
	return &Manager{
		procRoot: cfg.ProcRoot,
		sysRoot:  cfg.SysRoot,
		reader:   cfg.Reader,
		statFS:   cfg.StatFS,
		now:      cfg.Now,
		cadence:  cfg.Cadence,
	}, nil
}

func (m *Manager) Sample(ctx context.Context) HostMetrics {
	return m.collect(ctx, m.now())
}

func (m *Manager) Subscribe(ctx context.Context, emit func(HostMetrics)) error {
	ticker := time.NewTicker(m.cadence)
	defer ticker.Stop()
	emit(m.Sample(ctx))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			emit(m.collect(ctx, t))
		}
	}
}

func (m *Manager) collect(ctx context.Context, at time.Time) HostMetrics {
	_ = ctx
	snap := HostMetrics{Timestamp: at}

	cpu, cpuOK, cpuErr := parseCPU(m.read("stat"))
	load, loadErr := parseLoad(m.read("loadavg"))
	mem, swap, memErr := parseMeminfo(m.read("meminfo"))
	net, netOK, netErr := parseNetDev(m.read("net/dev"))
	if netOK {
		net = m.filterActiveInterfaces(net)
		netOK = len(net) > 0
		if !netOK {
			netErr = errors.New("no active non-loopback interfaces")
		}
	}
	mounts, mountErr := parseMounts(m.read("mounts"))

	m.mu.Lock()
	if cpuErr != nil || !cpuOK {
		snap.CPU = unavailableCPU(cpuErr)
	} else if !m.lastTime.IsZero() && m.lastCPU.total() > 0 {
		snap.CPU = CPUMetric{MetricReason: MetricReason{Available: true}, Percent: cpuPercent(m.lastCPU, cpu)}
	} else {
		snap.CPU = unavailableCPU(errors.New("cpu delta pending"))
	}
	if netErr != nil || !netOK {
		snap.Network = unavailableNet(netErr)
	} else if !m.lastTime.IsZero() && len(m.lastNet) > 0 {
		dt := at.Sub(m.lastTime).Seconds()
		snap.Network = NetworkMetric{MetricReason: MetricReason{Available: true}}
		if dt > 0 {
			var rx, tx uint64
			for name, next := range net {
				prev, ok := m.lastNet[name]
				if !ok {
					continue
				}
				if next.rx >= prev.rx {
					rx += uint64(float64(next.rx-prev.rx) / dt)
				}
				if next.tx >= prev.tx {
					tx += uint64(float64(next.tx-prev.tx) / dt)
				}
			}
			snap.Network.RxBytesPerSec = rx
			snap.Network.TxBytesPerSec = tx
		}
	} else {
		snap.Network = unavailableNet(errors.New("network delta pending"))
	}
	if cpuOK {
		m.lastCPU = cpu
	}
	if netOK {
		m.lastNet = net
	}
	m.lastTime = at
	m.mu.Unlock()

	if loadErr != nil {
		snap.Load = LoadMetric{MetricReason: MetricReason{Available: false, Reason: ReasonParseError, Message: loadErr.Error()}}
	} else {
		snap.Load = load
	}
	if memErr != nil {
		reason := MetricReason{Available: false, Reason: ReasonParseError, Message: memErr.Error()}
		snap.Memory = MemoryMetric{MetricReason: reason}
		snap.Swap = MemoryMetric{MetricReason: reason}
	} else {
		snap.Memory = mem
		snap.Swap = swap
	}
	if mountErr != nil {
		snap.Disks = []DiskMetric{{Mountpoint: "/", Available: false, Reason: ReasonParseError, Message: mountErr.Error()}}
	} else {
		snap.Disks = m.collectDisks(mounts)
	}
	return snap
}

func (m *Manager) read(rel string) ([]byte, error) {
	return m.reader.ReadFile(filepath.Join(m.procRoot, rel))
}

func (m *Manager) readSys(rel string) ([]byte, error) {
	return m.reader.ReadFile(filepath.Join(m.sysRoot, rel))
}

func (m *Manager) filterActiveInterfaces(in map[string]netCounters) map[string]netCounters {
	out := make(map[string]netCounters, len(in))
	for name, counters := range in {
		state, err := m.readSys(filepath.Join("class/net", name, "operstate"))
		if err == nil {
			switch strings.TrimSpace(string(state)) {
			case "up", "unknown":
				out[name] = counters
			}
			continue
		}
		out[name] = counters
	}
	return out
}

type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (c cpuTimes) idleAll() uint64 { return c.idle + c.iowait }
func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

func parseCPU(b []byte, err error) (cpuTimes, bool, error) {
	if err != nil {
		return cpuTimes{}, false, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		vals := make([]uint64, 8)
		for i := 0; i < len(vals) && i+1 < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return cpuTimes{}, false, err
			}
			vals[i] = v
		}
		return cpuTimes{vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7]}, true, nil
	}
	return cpuTimes{}, false, errors.New("aggregate cpu row missing")
}

func cpuPercent(prev, next cpuTimes) float64 {
	totalDelta := next.total() - prev.total()
	if totalDelta == 0 {
		return 0
	}
	idleDelta := next.idleAll() - prev.idleAll()
	return float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
}

func parseLoad(b []byte, err error) (LoadMetric, error) {
	if err != nil {
		return LoadMetric{}, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return LoadMetric{}, errors.New("loadavg missing fields")
	}
	one, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return LoadMetric{}, err
	}
	five, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return LoadMetric{}, err
	}
	fifteen, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return LoadMetric{}, err
	}
	return LoadMetric{MetricReason: MetricReason{Available: true}, One: one, Five: five, Fifteen: fifteen}, nil
}

func parseMeminfo(b []byte, err error) (MemoryMetric, MemoryMetric, error) {
	if err != nil {
		return MemoryMetric{}, MemoryMetric{}, err
	}
	vals := map[string]uint64{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return MemoryMetric{}, MemoryMetric{}, err
		}
		vals[key] = v * 1024
	}
	memTotal := vals["MemTotal"]
	memAvail := vals["MemAvailable"]
	if memTotal == 0 {
		return MemoryMetric{}, MemoryMetric{}, errors.New("MemTotal missing")
	}
	mem := memoryMetric(memTotal, memAvail)
	swap := memoryMetric(vals["SwapTotal"], vals["SwapFree"])
	return mem, swap, nil
}

func memoryMetric(total, avail uint64) MemoryMetric {
	if total == 0 {
		return MemoryMetric{MetricReason: MetricReason{Available: true}, TotalBytes: 0, AvailableBytes: 0, UsedBytes: 0, Percent: 0}
	}
	used := total - avail
	return MemoryMetric{
		MetricReason:   MetricReason{Available: true},
		TotalBytes:     total,
		AvailableBytes: avail,
		UsedBytes:      used,
		Percent:        float64(used) * 100 / float64(total),
	}
}

type netCounters struct {
	rx uint64
	tx uint64
}

func parseNetDev(b []byte, err error) (map[string]netCounters, bool, error) {
	if err != nil {
		return nil, false, err
	}
	out := map[string]netCounters{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter-|") || strings.HasPrefix(line, "face |") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(parts[0])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, false, err
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return nil, false, err
		}
		out[name] = netCounters{rx: rx, tx: tx}
	}
	if len(out) == 0 {
		return out, false, errors.New("no non-loopback interfaces")
	}
	return out, true, nil
}

type mount struct {
	fs   string
	path string
}

func parseMounts(b []byte, err error) ([]mount, error) {
	if err != nil {
		return nil, err
	}
	var mounts []mount
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	seen := map[string]struct{}{}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		fsType := fields[2]
		if fsType == "proc" || fsType == "sysfs" || fsType == "tmpfs" || fsType == "devtmpfs" || fsType == "devpts" || fsType == "cgroup2" || fsType == "overlay" {
			continue
		}
		path := unescapeMount(fields[1])
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		mounts = append(mounts, mount{fs: fsType, path: path})
	}
	if len(mounts) == 0 {
		mounts = []mount{{fs: "unknown", path: "/"}}
	}
	return mounts, nil
}

func unescapeMount(s string) string {
	return strings.ReplaceAll(s, `\040`, " ")
}

func (m *Manager) collectDisks(mounts []mount) []DiskMetric {
	out := make([]DiskMetric, 0, len(mounts))
	for _, row := range mounts {
		st, err := m.statFS(row.path)
		if err != nil {
			out = append(out, DiskMetric{Mountpoint: row.path, Filesystem: row.fs, Available: false, Reason: ReasonUnavailable, Message: err.Error()})
			continue
		}
		total := uint64(st.Blocks) * uint64(st.Bsize)
		avail := uint64(st.Bavail) * uint64(st.Bsize)
		used := total - avail
		percent := 0.0
		if total > 0 {
			percent = float64(used) * 100 / float64(total)
		}
		out = append(out, DiskMetric{Mountpoint: row.path, Filesystem: row.fs, TotalBytes: total, AvailableBytes: avail, UsedBytes: used, Percent: percent, Available: true})
	}
	return out
}

func unavailableCPU(err error) CPUMetric {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return CPUMetric{MetricReason: MetricReason{Available: false, Reason: ReasonUnavailable, Message: msg}}
}

func unavailableNet(err error) NetworkMetric {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return NetworkMetric{MetricReason: MetricReason{Available: false, Reason: ReasonUnavailable, Message: msg}}
}

func (h HostMetrics) Validate() error {
	if h.Timestamp.IsZero() {
		return fmt.Errorf("timestamp required")
	}
	return nil
}
