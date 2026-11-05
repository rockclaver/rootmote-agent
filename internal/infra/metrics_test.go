package infra

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeReader struct {
	files map[string][]byte
}

func (f fakeReader) ReadFile(name string) ([]byte, error) {
	b, ok := f.files[filepath.Base(name)]
	if !ok {
		return nil, errors.New("missing " + name)
	}
	return b, nil
}

type fakeCommand map[string][]byte

func (f fakeCommand) run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key += " " + strings.Join(args, " ")
	}
	b, ok := f[key]
	if !ok {
		return nil, errors.New("missing command " + key)
	}
	return b, nil
}

func TestIssue41MetricsCollector_GoldenProcSysStatfsFixtures(t *testing.T) {
	now := time.Unix(100, 0)
	reader := fakeReader{files: map[string][]byte{
		"stat":      []byte("cpu  100 0 50 850 0 0 0 0 0 0\n"),
		"loadavg":   []byte("0.25 0.50 0.75 1/100 1234\n"),
		"meminfo":   []byte("MemTotal:       1000 kB\nMemAvailable:    250 kB\nSwapTotal:       400 kB\nSwapFree:        100 kB\n"),
		"dev":       []byte("Inter-|   Receive                                                |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"),
		"mounts":    []byte("/dev/vda1 / ext4 rw 0 0\n"),
		"operstate": []byte("up\n"),
	}}
	mgr, err := New(Config{
		Platform: "linux",
		Reader:   reader,
		Now:      func() time.Time { return now },
		ProcRoot: "/proc",
		StatFS: func(path string) (syscall.Statfs_t, error) {
			if path != "/" {
				t.Fatalf("statfs path = %q", path)
			}
			return syscall.Statfs_t{Blocks: 100, Bavail: 25, Bsize: 4096}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// First sample seeds delta state; CPU/net correctly report a typed pending
	// reason instead of lying with zero usage.
	first := mgr.Sample(context.Background())
	if first.CPU.Available {
		t.Fatalf("first CPU should require a delta")
	}
	if first.CPU.Reason == "" {
		t.Fatalf("first CPU missing typed reason")
	}

	now = now.Add(2 * time.Second)
	reader.files["stat"] = []byte("cpu  130 0 70 900 0 0 0 0 0 0\n")
	reader.files["dev"] = []byte("Inter-|   Receive                                                |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 3000 0 0 0 0 0 0 0 5000 0 0 0 0 0 0 0\n")

	got := mgr.Sample(context.Background())
	if !got.CPU.Available {
		t.Fatalf("CPU unavailable: %+v", got.CPU.MetricReason)
	}
	if got.CPU.Percent != 50 {
		t.Fatalf("cpu percent = %.2f, want 50", got.CPU.Percent)
	}
	if got.Load.One != 0.25 || got.Load.Five != 0.50 || got.Load.Fifteen != 0.75 {
		t.Fatalf("load = %+v", got.Load)
	}
	if got.Memory.TotalBytes != 1024000 || got.Memory.AvailableBytes != 256000 || got.Memory.Percent != 75 {
		t.Fatalf("memory = %+v", got.Memory)
	}
	if got.Swap.TotalBytes != 409600 || got.Swap.AvailableBytes != 102400 || got.Swap.Percent != 75 {
		t.Fatalf("swap = %+v", got.Swap)
	}
	if len(got.Disks) != 1 {
		t.Fatalf("disks = %+v", got.Disks)
	}
	if got.Disks[0].Mountpoint != "/" || got.Disks[0].TotalBytes != 409600 || got.Disks[0].AvailableBytes != 102400 || got.Disks[0].Percent != 75 {
		t.Fatalf("disk = %+v", got.Disks[0])
	}
	if got.Network.RxBytesPerSec != 1000 || got.Network.TxBytesPerSec != 1500 {
		t.Fatalf("net = %+v", got.Network)
	}
}

func TestMetricsCollector_DarwinOverviewUsesNativeCommands(t *testing.T) {
	now := time.Unix(100, 0)
	cmds := fakeCommand{
		"ps -A -o %cpu=":         []byte("10.0\n20.0\n"),
		"sysctl -n vm.loadavg":   []byte("{ 1.25 1.50 1.75 }\n"),
		"sysctl -n hw.memsize":   []byte("17179869184\n"),
		"vm_stat":                []byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1000.\nPages inactive: 2000.\nPages speculative: 500.\n"),
		"sysctl -n vm.swapusage": []byte("total = 2048.00M  used = 512.00M  free = 1536.00M  (encrypted)\n"),
		"netstat -ibn":           []byte("Name  Mtu   Network     Address            Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n en0   1500  <Link#4>    aa:bb:cc           10    0     1000   20    0     2000   0\n"),
	}
	mgr, err := New(Config{
		Platform: "darwin",
		Command:  cmds.run,
		Now:      func() time.Time { return now },
		StatFS: func(path string) (syscall.Statfs_t, error) {
			if path != "/" {
				t.Fatalf("statfs path = %q", path)
			}
			return syscall.Statfs_t{Blocks: 100, Bavail: 25, Bsize: 4096}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	first := mgr.Sample(context.Background())
	if !first.CPU.Available {
		t.Fatalf("darwin CPU unavailable: %+v", first.CPU)
	}
	wantCPU := 30.0 / float64(runtime.NumCPU())
	if first.CPU.Percent != wantCPU {
		t.Fatalf("darwin CPU = %.4f, want %.4f", first.CPU.Percent, wantCPU)
	}
	if first.Load.One != 1.25 || first.Load.Five != 1.50 || first.Load.Fifteen != 1.75 {
		t.Fatalf("darwin load = %+v", first.Load)
	}
	if !first.Memory.Available || first.Memory.TotalBytes != 17179869184 {
		t.Fatalf("darwin memory = %+v", first.Memory)
	}
	if !first.Swap.Available || first.Swap.UsedBytes != 512*1024*1024 {
		t.Fatalf("darwin swap = %+v", first.Swap)
	}
	if len(first.Disks) != 1 || !first.Disks[0].Available || first.Disks[0].Mountpoint != "/" {
		t.Fatalf("darwin disks = %+v", first.Disks)
	}
	if first.Network.Available {
		t.Fatalf("first network sample should require delta: %+v", first.Network)
	}

	now = now.Add(2 * time.Second)
	cmds["netstat -ibn"] = []byte("Name  Mtu   Network     Address            Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n en0   1500  <Link#4>    aa:bb:cc           10    0     3000   20    0     7000   0\n")
	second := mgr.Sample(context.Background())
	if !second.Network.Available || second.Network.RxBytesPerSec != 1000 || second.Network.TxBytesPerSec != 2500 {
		t.Fatalf("darwin net = %+v", second.Network)
	}
}

func TestIssue41MetricsCollector_UnavailableMetricHasTypedReason(t *testing.T) {
	mgr, err := New(Config{
		Platform: "linux",
		Reader: fakeReader{files: map[string][]byte{
			"stat":    []byte("cpu broken\n"),
			"loadavg": []byte("0.1 0.2 0.3 1/1 1\n"),
			"meminfo": []byte("MemTotal: 1 kB\nMemAvailable: 1 kB\n"),
			"dev":     []byte("bad\n"),
			"mounts":  []byte("/dev/vda1 / ext4 rw 0 0\n"),
		}},
		StatFS: func(path string) (syscall.Statfs_t, error) {
			return syscall.Statfs_t{}, errors.New("statfs denied")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mgr.Sample(context.Background())
	if got.CPU.Available || got.CPU.Reason == "" {
		t.Fatalf("CPU reason missing: %+v", got.CPU)
	}
	if got.Network.Available || got.Network.Reason == "" {
		t.Fatalf("network reason missing: %+v", got.Network)
	}
	if got.Disks[0].Available || got.Disks[0].Reason == "" {
		t.Fatalf("disk reason missing: %+v", got.Disks[0])
	}
}

func TestMetricsCollector_SkipsDockerAndPseudoMounts(t *testing.T) {
	reader := fakeReader{files: map[string][]byte{
		"stat":    []byte("cpu  1 0 1 8 0 0 0 0\n"),
		"loadavg": []byte("0.1 0.2 0.3 1/1 1\n"),
		"meminfo": []byte("MemTotal: 1 kB\nMemAvailable: 1 kB\n"),
		"dev":     []byte(" eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n"),
		"mounts": []byte(strings.Join([]string{
			"/dev/vda1 / ext4 rw 0 0",
			"nsfs /run/docker/netns/default nsfs rw 0 0",
			"/dev/vda1 /run/docker/containers/abc/shm ext4 rw 0 0",
			"udev /dev/null devtmpfs rw 0 0",
			// Snap packages are read-only images that always read 100% used.
			"/dev/loop3 /snap/core20/2922 squashfs ro,nodev,relatime 0 0",
			"snapfuse /snap/certbot/5893 fuse.snapfuse ro,nodev 0 0",
			"",
		}, "\n")),
	}}
	mgr, err := New(Config{
		Platform: "linux",
		Reader:   reader,
		StatFS: func(path string) (syscall.Statfs_t, error) {
			if strings.HasPrefix(path, "/run/") {
				return syscall.Statfs_t{}, errors.New("permission denied")
			}
			return syscall.Statfs_t{Blocks: 100, Bavail: 25, Bsize: 4096}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mgr.Sample(context.Background())
	if len(got.Disks) != 1 {
		t.Fatalf("disks = %+v, want only /", got.Disks)
	}
	if got.Disks[0].Mountpoint != "/" {
		t.Fatalf("disk mountpoint = %q, want /", got.Disks[0].Mountpoint)
	}
}

func TestIssue41MetricsSubscribe_EmitsAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mgr, err := New(Config{
		Platform: "linux",
		Cadence:  time.Millisecond,
		Reader: fakeReader{files: map[string][]byte{
			"stat":    []byte("cpu  1 0 1 8 0 0 0 0\n"),
			"loadavg": []byte("0.1 0.2 0.3 1/1 1\n"),
			"meminfo": []byte("MemTotal: 1 kB\nMemAvailable: 1 kB\n"),
			"dev":     []byte(" eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n"),
			"mounts":  []byte("/dev/vda1 / ext4 rw 0 0\n"),
		}},
		StatFS: func(path string) (syscall.Statfs_t, error) {
			return syscall.Statfs_t{Blocks: 1, Bavail: 1, Bsize: 4096}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan HostMetrics, 3)
	done := make(chan error, 1)
	go func() {
		done <- mgr.Subscribe(ctx, func(m HostMetrics) {
			select {
			case seen <- m:
			default:
			}
		})
	}()
	<-seen
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Subscribe err = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribe did not stop after cancel")
	}
}

func TestDiskMetric_InodeCapacityDerivedFromStatfs(t *testing.T) {
	got := (&Manager{statFS: func(path string) (syscall.Statfs_t, error) {
		return syscall.Statfs_t{Blocks: 100, Bavail: 25, Bsize: 4096, Files: 1000, Ffree: 250}, nil
	}}).collectDisks([]mount{{fs: "ext4", path: "/"}})
	if len(got) != 1 {
		t.Fatalf("disks = %+v", got)
	}
	d := got[0]
	if d.InodesTotal != 1000 || d.InodesFree != 250 || d.InodesUsed != 750 {
		t.Fatalf("inodes = %+v", d)
	}
	if d.InodePercent != 75 {
		t.Fatalf("inode percent = %v, want 75", d.InodePercent)
	}
}

func TestDiskMetric_InodeCapacityZeroFilesGuard(t *testing.T) {
	got := (&Manager{statFS: func(path string) (syscall.Statfs_t, error) {
		return syscall.Statfs_t{Blocks: 100, Bavail: 25, Bsize: 4096, Files: 0, Ffree: 0}, nil
	}}).collectDisks([]mount{{fs: "tmpfs", path: "/tmp"}})
	if len(got) != 1 {
		t.Fatalf("disks = %+v", got)
	}
	d := got[0]
	if d.InodesTotal != 0 || d.InodesFree != 0 || d.InodesUsed != 0 || d.InodePercent != 0 {
		t.Fatalf("expected zero inode stats when Files == 0, got %+v", d)
	}
	if !d.Available {
		t.Fatalf("disk should remain available when inode fields are zero")
	}
}

func TestParseOOMEvents_HostAndCgroupKillsWithTimestamps(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	raw := []byte(strings.Join([]string{
		"[Sat Aug  1 12:34:56 2026] Out of memory: Killed process 1234 (postgres) total-vm:1000kB",
		"not an oom line, should be ignored",
		"[Sat Aug  1 12:35:09 2026] oom-kill:task_memcg=/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"[Sat Aug  1 12:35:10 2026] Memory cgroup out of memory: Killed process 5678 (node) score 900",
		"garbage garbage garbage",
	}, "\n"))
	got := ParseOOMEvents(raw, now)
	if len(got) != 2 {
		t.Fatalf("events = %+v, want 2", got)
	}
	wantFirst := time.Date(2026, time.August, 1, 12, 34, 56, 0, time.UTC)
	if !got[0].At.Equal(wantFirst) || got[0].PID != 1234 || got[0].Process != "postgres" {
		t.Fatalf("event[0] = %+v", got[0])
	}
	wantSecond := time.Date(2026, time.August, 1, 12, 35, 10, 0, time.UTC)
	if !got[1].At.Equal(wantSecond) || got[1].PID != 5678 || got[1].Process != "node" ||
		got[1].ContainerID != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("event[1] = %+v", got[1])
	}
}

func TestParseOOMEvents_NoTimestampFallsBackToNow(t *testing.T) {
	now := time.Unix(999, 0)
	got := ParseOOMEvents([]byte("Out of memory: Killed process 42 (worker)\n"), now)
	if len(got) != 1 {
		t.Fatalf("events = %+v, want 1", got)
	}
	if !got[0].At.Equal(now) || got[0].PID != 42 || got[0].Process != "worker" {
		t.Fatalf("event = %+v", got[0])
	}
}

func TestManagerOOMEvents_UsesDmesgAndFiltersBySince(t *testing.T) {
	now := time.Unix(2000, 0)
	cmds := fakeCommand{
		"dmesg -T": []byte(strings.Join([]string{
			"[Sat Aug  1 10:00:00 2026] Out of memory: Killed process 1 (old)",
			"[Sat Aug  1 12:00:00 2026] Out of memory: Killed process 2 (recent)",
		}, "\n")),
	}
	mgr, err := New(Config{Platform: "linux", Command: cmds.run, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, time.August, 1, 11, 0, 0, 0, time.UTC)
	got, err := mgr.OOMEvents(context.Background(), since)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PID != 2 || got[0].Process != "recent" {
		t.Fatalf("OOMEvents = %+v, want only the recent kill", got)
	}
}

func TestManagerOOMEvents_DarwinReturnsNil(t *testing.T) {
	mgr, err := New(Config{Platform: "darwin", Command: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("darwin OOMEvents must not shell out")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := mgr.OOMEvents(context.Background(), time.Time{})
	if err != nil || got != nil {
		t.Fatalf("darwin OOMEvents = (%+v, %v), want (nil, nil)", got, err)
	}
}
