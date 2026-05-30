package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
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
	if byCPU[0].PID != 100 || byCPU[0].User != "app" || byCPU[0].Command != "node server.js" {
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
				Signal: func(pid int, sig syscall.Signal) error {
					signalled = true
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = mgr.Kill(context.Background(), tc.pid, SignalTerm)
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
		Signal: func(pid int, sig syscall.Signal) error {
			if pid != 77 {
				t.Fatalf("pid = %d", pid)
			}
			got = append(got, sig)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Kill(context.Background(), 77, ""); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Kill(context.Background(), 77, SignalKill); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != syscall.SIGTERM || got[1] != syscall.SIGKILL {
		t.Fatalf("signals = %v", got)
	}
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
