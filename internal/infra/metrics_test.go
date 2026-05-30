package infra

import (
	"context"
	"errors"
	"path/filepath"
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

func TestIssue41MetricsCollector_UnavailableMetricHasTypedReason(t *testing.T) {
	mgr, err := New(Config{
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

func TestIssue41MetricsSubscribe_EmitsAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mgr, err := New(Config{
		Cadence: time.Millisecond,
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
