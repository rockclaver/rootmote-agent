package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestIssue43ProcessList_MapsProcFixturesAndSorts(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, "worker", "1000", "node\x00server.js\x00", 200, 100, 1000, 12)
	writeProc(t, root, 200, "postgres", "1001", "postgres\x00", 50, 50, 1000, 32)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")

	mgr, err := New(Config{
		ProcRoot:     root,
		PageSize:     1024,
		ClockTicks:   100,
		NumCPU:       1,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		LookupUser: func(uid string) string {
			return map[string]string{"1000": "app", "1001": "db"}[uid]
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	byCPU, err := mgr.List(context.Background(), SortCPU, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(byCPU) != 2 {
		t.Fatalf("len = %d", len(byCPU))
	}
	if byCPU[0].PID != 100 || byCPU[0].User != "app" || byCPU[0].Command != "node server.js" || byCPU[0].StartTimeTicks != 1000 {
		t.Fatalf("bad cpu first: %+v", byCPU[0])
	}
	if byCPU[0].CPUPercent <= byCPU[1].CPUPercent {
		t.Fatalf("cpu sort failed: %+v", byCPU)
	}

	byMem, err := mgr.List(context.Background(), SortMemory, 10)
	if err != nil {
		t.Fatal(err)
	}
	if byMem[0].PID != 200 || byMem[0].RSSBytes != 32*1024 {
		t.Fatalf("memory sort failed: %+v", byMem)
	}
}

func TestReadProcess_CapturesExePathAndDeletedFlag(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, "worker", "1000", "worker\x00", 10, 10, 1000, 12)
	writeProc(t, root, 200, "miner", "1000", "miner\x00", 10, 10, 1000, 12)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	if err := os.Symlink("/usr/bin/worker", filepath.Join(root, "100", "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/.hidden/miner (deleted)", filepath.Join(root, "200", "exe")); err != nil {
		t.Fatal(err)
	}

	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	procs, err := mgr.List(context.Background(), SortCPU, 10)
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]Process{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	if got := byPID[100]; got.ExePath != "/usr/bin/worker" || got.ExeDeleted {
		t.Fatalf("worker exe = %+v", got)
	}
	if got := byPID[200]; got.ExePath != "/tmp/.hidden/miner" || !got.ExeDeleted {
		t.Fatalf("miner exe = %+v", got)
	}
}

func TestReadProcess_DetectsKernelThreadsWithNoArgvOrExe(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 39, "kdevtmpfs", "0", "", 1, 1, 1, 1)
	writeProc(t, root, 100, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	// pid 100 gets a resolvable exe symlink like a real userspace process;
	// pid 39 (the kernel thread) gets none, matching real /proc behavior.
	if err := os.Symlink("/usr/bin/worker", filepath.Join(root, "100", "exe")); err != nil {
		t.Fatal(err)
	}

	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	procs, err := mgr.List(context.Background(), SortCPU, 10)
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]Process{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	if got := byPID[39]; !got.KernelThread || got.Command != "kdevtmpfs" {
		t.Fatalf("kdevtmpfs kernel thread = %+v", got)
	}
	if got := byPID[100]; got.KernelThread {
		t.Fatalf("worker with resolvable exe misclassified as kernel thread: %+v", got)
	}
}

func TestKill_RefusesKernelThreadWithoutSignalling(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 39, "kdevtmpfs", "0", "", 1, 1, 1, 1)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var signalled bool
	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Signal: func(context.Context, int, syscall.Signal) error {
			signalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.Kill(context.Background(), 39, 1, SignalTerm)
	if !errors.Is(err, ErrKernelThread) {
		t.Fatalf("err = %v, want ErrKernelThread", err)
	}
	if signalled {
		t.Fatal("kernel thread was signalled")
	}
}

func TestIssue43ProtectedPIDGuardRejectsBeforeSignal(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name string
		pid  int
		comm string
	}{
		{name: "pid1", pid: 1, comm: "init"},
		{name: "agent", pid: 44, comm: "claver-agent"},
		{name: "sshd", pid: 55, comm: "sshd"},
		{name: "tmux-pane", pid: 66, comm: "bash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeProc(t, root, tc.pid, tc.comm, "1000", tc.comm+"\x00", 1, 1, 1, 1)
			mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
			var signalled bool
			mgr, err := New(Config{
				ProcRoot: root,
				AgentPID: 44,
				TmuxPanePIDs: func(context.Context) []int {
					return []int{66}
				},
				Signal: func(_ context.Context, pid int, sig syscall.Signal) error {
					signalled = true
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = mgr.Kill(context.Background(), tc.pid, 1, SignalTerm)
			if !errors.Is(err, ErrProtectedPID) {
				t.Fatalf("err = %v, want protected", err)
			}
			if signalled {
				t.Fatal("signal called for protected pid")
			}
		})
	}
}

func TestIssue43ProcessKillUsesTermByDefaultAndKillEscalation(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var got []syscall.Signal
	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Sleep:        func(time.Duration) {},
		Signal: func(_ context.Context, pid int, sig syscall.Signal) error {
			if pid != 77 {
				t.Fatalf("pid = %d", pid)
			}
			got = append(got, sig)
			// Simulate the process actually exiting on this signal so Kill's
			// post-signal verification observes it gone instead of escalating.
			_ = os.RemoveAll(filepath.Join(root, "77"))
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Kill(context.Background(), 77, 1, ""); err != nil {
		t.Fatal(err)
	}
	writeProc(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	if err := mgr.Kill(context.Background(), 77, 1, SignalKill); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != syscall.SIGTERM || got[1] != syscall.SIGKILL {
		t.Fatalf("signals = %v", got)
	}
}

func TestKill_EscalatesToSigkillWhenSigtermIsIgnored(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var got []syscall.Signal
	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Sleep:        func(time.Duration) {},
		KillGrace:    time.Millisecond,
		Signal: func(_ context.Context, pid int, sig syscall.Signal) error {
			got = append(got, sig)
			if sig == syscall.SIGKILL {
				// Only SIGKILL actually terminates it, mimicking a process
				// that installed a handler ignoring SIGTERM.
				_ = os.RemoveAll(filepath.Join(root, "77"))
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Kill(context.Background(), 77, 1, SignalTerm); err != nil {
		t.Fatalf("expected escalation to SIGKILL to succeed, got %v", err)
	}
	if len(got) != 2 || got[0] != syscall.SIGTERM || got[1] != syscall.SIGKILL {
		t.Fatalf("signals = %v, want [TERM, KILL]", got)
	}
}

func TestKill_ReturnsTerminationFailedWhenProcessSurvivesSigkill(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Sleep:        func(time.Duration) {},
		KillGrace:    time.Millisecond,
		Signal: func(context.Context, int, syscall.Signal) error {
			// Process never actually exits, e.g. stuck in an uninterruptible
			// kernel wait (D state).
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.Kill(context.Background(), 77, 1, SignalTerm)
	if !errors.Is(err, ErrTerminationFailed) {
		t.Fatalf("err = %v, want ErrTerminationFailed", err)
	}
}

func TestIssue43ProcessKillRejectsPIDReuseBeforeSignal(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1000, 1)
	mustWrite(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var signalled bool
	mgr, err := New(Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Signal: func(_ context.Context, pid int, sig syscall.Signal) error {
			signalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeProc(t, root, 77, "other", "1000", "other\x00", 1, 1, 2000, 1)
	err = mgr.Kill(context.Background(), 77, 1000, SignalTerm)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("err = %v, want identity mismatch", err)
	}
	if signalled {
		t.Fatal("signal called for reused pid")
	}
}

func TestSignalFlag_MapsTermAndKillToKillCLIFlags(t *testing.T) {
	if got := signalFlag(syscall.SIGTERM); got != "-TERM" {
		t.Fatalf("SIGTERM flag = %q", got)
	}
	if got := signalFlag(syscall.SIGKILL); got != "-KILL" {
		t.Fatalf("SIGKILL flag = %q", got)
	}
	if got := signalFlag(syscall.SIGHUP); got != "-1" {
		t.Fatalf("SIGHUP flag = %q", got)
	}
}

func TestDarwinProcessList_UsesPSWhenProcfsIsUnavailable(t *testing.T) {
	ps := `  10 root      0.0    512 Wed Jul  1 22:49:42 2026 /sbin/launchd
 100 claver   12.5  2048 Wed Jul  1 22:50:10 2026 /Applications/Foo.app/Contents/MacOS/Foo --flag
 200 claver    1.0  8192 Wed Jul  1 22:51:10 2026 /usr/sbin/sshd -i
`
	mgr, err := New(Config{
		Platform: "darwin",
		AgentPID: 999,
		TmuxPanePIDs: func(context.Context) []int {
			return []int{10}
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "ps" {
				t.Fatalf("unexpected command %s %v", name, args)
			}
			return []byte(ps), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := mgr.List(context.Background(), SortMemory, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d got=%+v", len(got), got)
	}
	if got[0].PID != 200 || got[0].RSSBytes != 8192*1024 || !got[0].Protected {
		t.Fatalf("memory/protection mapping failed: %+v", got[0])
	}
	if got[1].Command != "/Applications/Foo.app/Contents/MacOS/Foo --flag" || got[1].CPUPercent != 12.5 || got[1].StartTimeTicks == 0 {
		t.Fatalf("process fields failed: %+v", got[1])
	}
}

func TestSudoKillArgs_FormatsNoPromptSignalAndPID(t *testing.T) {
	if got, want := sudoKillArgs(1234, syscall.SIGTERM), []string{"-n", "kill", "-TERM", "1234"}; !equalStrings(got, want) {
		t.Fatalf("sudoKillArgs(SIGTERM) = %v, want %v", got, want)
	}
	if got, want := sudoKillArgs(1234, syscall.SIGKILL), []string{"-n", "kill", "-KILL", "1234"}; !equalStrings(got, want) {
		t.Fatalf("sudoKillArgs(SIGKILL) = %v, want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeProc(t *testing.T, root string, pid int, comm, uid, cmdline string, utime, stime, start, rss int) {
	t.Helper()
	dir := filepath.Join(root, intString(pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := []string{
		"S", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		intString(utime), intString(stime), "0", "0", "20", "0", "1", "0", intString(start), "0", intString(rss),
	}
	mustWrite(t, filepath.Join(dir, "stat"), intString(pid)+" ("+comm+") "+join(fields, " ")+"\n")
	mustWrite(t, filepath.Join(dir, "status"), "Name:\t"+comm+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n")
	mustWrite(t, filepath.Join(dir, "cmdline"), cmdline)
	mustWrite(t, filepath.Join(dir, "statm"), "100 "+intString(rss)+" 0 0 0 0 0\n")
	mustWrite(t, filepath.Join(dir, "comm"), comm+"\n")
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func intString(v int) string { return strconv.Itoa(v) }

func join(in []string, sep string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
