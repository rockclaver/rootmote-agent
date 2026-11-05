// Package process implements the Process Inspector module. It reads process
// summaries from procfs and performs guarded TERM/KILL operations.
package process

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SortCPU    = "cpu"
	SortMemory = "memory"
)

type Process struct {
	PID            int     `json:"pid"`
	User           string  `json:"user"`
	Command        string  `json:"command"`
	CPUPercent     float64 `json:"cpu_percent"`
	RSSBytes       uint64  `json:"rss_bytes"`
	StartTimeTicks uint64  `json:"start_time_ticks"`
	Protected      bool    `json:"protected"`
	ProtectReason  string  `json:"protect_reason,omitempty"`
	ExePath        string  `json:"exe_path,omitempty"`
	ExeDeleted     bool    `json:"exe_deleted,omitempty"`
	// KernelThread is true for kernel-scheduled threads (kworker,
	// kdevtmpfs, ksoftirqd, migration, rcu_gp, …): they have no argv
	// (empty /proc/<pid>/cmdline) and no backing executable (no
	// /proc/<pid>/exe symlink at all). They are never suspicious in the
	// userspace sense and cannot be signalled to exit — kill() is a no-op
	// against them, unlike a real process ignoring SIGTERM.
	KernelThread bool `json:"kernel_thread,omitempty"`
}

type FileReader interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]os.DirEntry, error)
	Readlink(name string) (string, error)
}

type osReader struct{}

func (osReader) ReadFile(name string) ([]byte, error)       { return os.ReadFile(name) }
func (osReader) ReadDir(name string) ([]os.DirEntry, error) { return os.ReadDir(name) }
func (osReader) Readlink(name string) (string, error)       { return os.Readlink(name) }

type Config struct {
	ProcRoot     string
	Reader       FileReader
	Platform     string
	Run          CommandRunner
	PageSize     uint64
	ClockTicks   float64
	NumCPU       int
	AgentPID     int
	TmuxPanePIDs func(context.Context) []int
	LookupUser   func(uid string) string
}

type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type Manager struct {
	procRoot     string
	reader       FileReader
	platform     string
	run          CommandRunner
	pageSize     uint64
	clockTicks   float64
	numCPU       int
	agentPID     int
	tmuxPanePIDs func(context.Context) []int
	lookupUser   func(string) string
}

func New(cfg Config) (*Manager, error) {
	procRootConfigured := cfg.ProcRoot != ""
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.Reader == nil {
		cfg.Reader = osReader{}
	}
	if cfg.Platform == "" {
		if procRootConfigured && cfg.ProcRoot != "/proc" {
			cfg.Platform = "linux"
		} else {
			cfg.Platform = runtime.GOOS
		}
	}
	if cfg.Run == nil {
		cfg.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = uint64(os.Getpagesize())
	}
	if cfg.ClockTicks <= 0 {
		cfg.ClockTicks = 100
	}
	if cfg.NumCPU <= 0 {
		cfg.NumCPU = 1
	}
	if cfg.AgentPID <= 0 {
		cfg.AgentPID = os.Getpid()
	}
	if cfg.TmuxPanePIDs == nil {
		cfg.TmuxPanePIDs = TmuxPanePIDs
	}
	if cfg.LookupUser == nil {
		cfg.LookupUser = lookupUser
	}
	return &Manager{
		procRoot:     cfg.ProcRoot,
		reader:       cfg.Reader,
		platform:     cfg.Platform,
		run:          cfg.Run,
		pageSize:     cfg.PageSize,
		clockTicks:   cfg.ClockTicks,
		numCPU:       cfg.NumCPU,
		agentPID:     cfg.AgentPID,
		tmuxPanePIDs: cfg.TmuxPanePIDs,
		lookupUser:   cfg.LookupUser,
	}, nil
}

func (m *Manager) List(ctx context.Context, sortBy string, limit int) ([]Process, error) {
	if sortBy == "" {
		sortBy = SortCPU
	}
	if sortBy != SortCPU && sortBy != SortMemory {
		return nil, fmt.Errorf("process: unsupported sort %q", sortBy)
	}
	if m.platform == "darwin" {
		return m.listDarwin(ctx, sortBy, limit)
	}
	if limit <= 0 {
		limit = 25
	}
	uptime, _ := parseUptime(m.read("uptime"))
	entries, err := m.reader.ReadDir(m.procRoot)
	if err != nil {
		return nil, err
	}
	protected := m.protected(ctx)
	out := make([]Process, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, err := m.readProcess(pid, uptime)
		if err != nil {
			continue
		}
		if reason, ok := protected[pid]; ok {
			p.Protected = true
			p.ProtectReason = reason
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sortBy == SortMemory {
			if out[i].RSSBytes == out[j].RSSBytes {
				return out[i].PID < out[j].PID
			}
			return out[i].RSSBytes > out[j].RSSBytes
		}
		if out[i].CPUPercent == out[j].CPUPercent {
			return out[i].PID < out[j].PID
		}
		return out[i].CPUPercent > out[j].CPUPercent
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) protected(ctx context.Context) map[int]string {
	out := map[int]string{
		1:          "pid 1/init must never be signalled",
		m.agentPID: "Rootmote agent supervises this request",
	}
	for _, pid := range m.sshdPIDs() {
		out[pid] = "SSH daemon is the transport into the agent"
	}
	for _, pid := range m.tmuxPanePIDs(ctx) {
		if pid > 0 {
			out[pid] = "tmux session pane backs an active agent session"
		}
	}
	return out
}

func (m *Manager) sshdPIDs() []int {
	if m.platform == "darwin" {
		return m.darwinPIDsByCommand("sshd")
	}
	entries, err := m.reader.ReadDir(m.procRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		comm, err := m.reader.ReadFile(filepath.Join(m.procRoot, entry.Name(), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == "sshd" {
			pids = append(pids, pid)
			continue
		}
		cmd, err := m.reader.ReadFile(filepath.Join(m.procRoot, entry.Name(), "cmdline"))
		if err == nil && strings.Contains(strings.ReplaceAll(string(cmd), "\x00", " "), "sshd") {
			pids = append(pids, pid)
		}
	}
	return pids
}

func (m *Manager) readProcess(pid int, uptime float64) (Process, error) {
	if m.platform == "darwin" {
		return m.readDarwinProcess(pid)
	}
	dir := filepath.Join(m.procRoot, strconv.Itoa(pid))
	stat, err := parseStat(mustString(m.reader.ReadFile(filepath.Join(dir, "stat"))))
	if err != nil {
		return Process{}, err
	}
	uid, err := parseUID(m.reader.ReadFile(filepath.Join(dir, "status")))
	if err != nil {
		return Process{}, err
	}
	rawCmd := parseCmdline(mustString(m.reader.ReadFile(filepath.Join(dir, "cmdline"))))
	cmd := rawCmd
	if cmd == "" {
		cmd = stat.command
	}
	rssBytes := uint64(0)
	if statm, err := parseStatm(m.reader.ReadFile(filepath.Join(dir, "statm"))); err == nil {
		rssBytes = statm * m.pageSize
	} else if stat.rssPages > 0 {
		rssBytes = uint64(stat.rssPages) * m.pageSize
	}
	exePath, exeDeleted := "", false
	exeResolved := false
	if target, err := m.reader.Readlink(filepath.Join(dir, "exe")); err == nil {
		exeResolved = true
		exePath, exeDeleted = strings.CutSuffix(target, " (deleted)")
	}
	return Process{
		PID:            pid,
		User:           m.lookupUser(uid),
		Command:        cmd,
		CPUPercent:     cpuPercent(stat, uptime, m.clockTicks, m.numCPU),
		RSSBytes:       rssBytes,
		StartTimeTicks: stat.startTicks,
		ExePath:        exePath,
		ExeDeleted:     exeDeleted,
		KernelThread:   rawCmd == "" && !exeResolved,
	}, nil
}

func (m *Manager) read(rel string) ([]byte, error) {
	return m.reader.ReadFile(filepath.Join(m.procRoot, rel))
}

type procStat struct {
	command    string
	utime      float64
	stime      float64
	startTicks uint64
	rssPages   int64
}

func parseStat(raw string) (procStat, error) {
	raw = strings.TrimSpace(raw)
	open := strings.Index(raw, "(")
	close := strings.LastIndex(raw, ")")
	if open < 0 || close <= open {
		return procStat{}, errors.New("process: malformed stat")
	}
	fields := strings.Fields(strings.TrimSpace(raw[close+1:]))
	if len(fields) < 22 {
		return procStat{}, errors.New("process: short stat")
	}
	utime, err := strconv.ParseFloat(fields[11], 64)
	if err != nil {
		return procStat{}, err
	}
	stime, err := strconv.ParseFloat(fields[12], 64)
	if err != nil {
		return procStat{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procStat{}, err
	}
	rss, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		rss = 0
	}
	return procStat{
		command:    strings.TrimSpace(raw[open+1 : close]),
		utime:      utime,
		stime:      stime,
		startTicks: start,
		rssPages:   rss,
	}, nil
}

func parseUID(raw []byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			return fields[1], nil
		}
	}
	return "", errors.New("process: uid not found")
}

func parseStatm(raw []byte, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, errors.New("process: malformed statm")
	}
	return strconv.ParseUint(fields[1], 10, 64)
}

func parseUptime(raw []byte, err error) (float64, error) {
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, errors.New("process: malformed uptime")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func parseCmdline(raw string) string {
	raw = strings.Trim(raw, "\x00")
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func cpuPercent(st procStat, uptime, clockTicks float64, numCPU int) float64 {
	if uptime <= 0 || clockTicks <= 0 {
		return 0
	}
	elapsed := uptime - (float64(st.startTicks) / clockTicks)
	if elapsed <= 0 {
		return 0
	}
	percent := ((st.utime + st.stime) / clockTicks) / elapsed * 100
	if numCPU > 0 {
		percent /= float64(numCPU)
	}
	if percent < 0 {
		return 0
	}
	return percent
}

func (m *Manager) listDarwin(ctx context.Context, sortBy string, limit int) ([]Process, error) {
	if limit <= 0 {
		limit = 25
	}
	out, err := m.darwinProcesses(ctx, sortBy)
	if err != nil {
		return nil, err
	}
	protected := m.protectedDarwin(ctx, out)
	for i := range out {
		if reason, ok := protected[out[i].PID]; ok {
			out[i].Protected = true
			out[i].ProtectReason = reason
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sortBy == SortMemory {
			if out[i].RSSBytes == out[j].RSSBytes {
				return out[i].PID < out[j].PID
			}
			return out[i].RSSBytes > out[j].RSSBytes
		}
		if out[i].CPUPercent == out[j].CPUPercent {
			return out[i].PID < out[j].PID
		}
		return out[i].CPUPercent > out[j].CPUPercent
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) protectedDarwin(ctx context.Context, procs []Process) map[int]string {
	out := map[int]string{
		1:          "pid 1/init must never be signalled",
		m.agentPID: "Rootmote agent supervises this request",
	}
	for _, p := range procs {
		if processCommandContains(p, "sshd") {
			out[p.PID] = "SSH daemon is the transport into the agent"
		}
	}
	for _, pid := range m.tmuxPanePIDs(ctx) {
		if pid > 0 {
			out[pid] = "tmux session pane backs an active agent session"
		}
	}
	return out
}

func (m *Manager) readDarwinProcess(pid int) (Process, error) {
	for _, p := range m.mustDarwinProcesses(context.Background(), SortCPU) {
		if p.PID == pid {
			return p, nil
		}
	}
	return Process{}, os.ErrNotExist
}

func (m *Manager) darwinPIDsByCommand(needle string) []int {
	var pids []int
	for _, p := range m.mustDarwinProcesses(context.Background(), SortCPU) {
		if processCommandContains(p, needle) {
			pids = append(pids, p.PID)
		}
	}
	return pids
}

func processCommandContains(p Process, needle string) bool {
	fields := strings.Fields(p.Command)
	base := ""
	if len(fields) > 0 {
		base = filepath.Base(fields[0])
	}
	return strings.Contains(base, needle) || strings.Contains(p.Command, needle)
}

func (m *Manager) mustDarwinProcesses(ctx context.Context, sortBy string) []Process {
	procs, err := m.darwinProcesses(ctx, sortBy)
	if err != nil {
		return nil
	}
	return procs
}

func (m *Manager) darwinProcesses(ctx context.Context, sortBy string) ([]Process, error) {
	format := "-arcxo"
	if sortBy == SortMemory {
		format = "-amcxo"
	}
	out, err := m.run(ctx, "ps", format, "pid=,user=,%cpu=,rss=,comm=")
	if err != nil {
		return nil, fmt.Errorf("process: ps: %w", err)
	}
	return parseDarwinPS(string(out)), nil
}

func parseDarwinPS(raw string) []Process {
	var out []Process
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		rssKB, _ := strconv.ParseUint(fields[3], 10, 64)
		start := uint64(pid)
		commandStart := 4
		if len(fields) >= 10 {
			if ts, err := time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(fields[4:9], " ")); err == nil {
				start = uint64(ts.Unix())
				commandStart = 9
			}
		}
		cmd := strings.Join(fields[commandStart:], " ")
		out = append(out, Process{
			PID:            pid,
			User:           fields[1],
			Command:        cmd,
			CPUPercent:     cpu,
			RSSBytes:       rssKB * 1024,
			StartTimeTicks: start,
		})
	}
	return out
}

func lookupUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil || u.Username == "" {
		return uid
	}
	return u.Username
}

func mustString(b []byte, _ error) string { return string(b) }

func TmuxPanePIDs(ctx context.Context) []int {
	out, err := exec.CommandContext(ctx, "tmux", "list-panes", "-a", "-F", "#{pane_pid}").Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}
