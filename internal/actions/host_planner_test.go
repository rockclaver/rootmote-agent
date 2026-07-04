package actions

import (
	"context"
	"strings"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/infra"
)

type fakeMetrics struct {
	snap infra.HostMetrics
}

func (f fakeMetrics) Sample(context.Context) infra.HostMetrics { return f.snap }

func memSnap() infra.HostMetrics {
	return infra.HostMetrics{
		Memory: infra.MemoryMetric{
			MetricReason:   infra.MetricReason{Available: true},
			TotalBytes:     8 * 1024 * 1024 * 1024,
			AvailableBytes: 2 * 1024 * 1024 * 1024,
			UsedBytes:      6 * 1024 * 1024 * 1024,
			Percent:        75,
		},
	}
}

func TestHostQueryPlanner_Memory(t *testing.T) {
	p := HostQueryPlanner{Metrics: fakeMetrics{memSnap()}, Hostname: "Orivo"}
	res, err := p.Plan(context.Background(), Request{Text: "check how much of my RAM is left on the Orivo server"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if res.Status != StatusObserved {
		t.Fatalf("status = %q, want observed", res.Status)
	}
	if !strings.Contains(res.Summary, "Orivo:") {
		t.Errorf("summary missing hostname: %q", res.Summary)
	}
	if !strings.Contains(res.Summary, "2.0 GiB RAM free of 8.0 GiB") {
		t.Errorf("summary missing memory figures: %q", res.Summary)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(res.Events))
	}
}

func TestHostQueryPlanner_UnrecognisedReturnsNeedsTarget(t *testing.T) {
	p := HostQueryPlanner{Metrics: fakeMetrics{memSnap()}}
	res, err := p.Plan(context.Background(), Request{Text: "restart the ancient api container"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if res.Status != StatusNeedsTarget {
		t.Fatalf("status = %q, want needs_target", res.Status)
	}
}

func TestHostQueryPlanner_MultipleIntentsOrdered(t *testing.T) {
	snap := memSnap()
	snap.CPU = infra.CPUMetric{MetricReason: infra.MetricReason{Available: true}, Percent: 12}
	snap.Disks = []infra.DiskMetric{{
		Mountpoint: "/", Available: true,
		TotalBytes: 100 * 1024 * 1024 * 1024, AvailableBytes: 40 * 1024 * 1024 * 1024, Percent: 60,
	}}
	p := HostQueryPlanner{Metrics: fakeMetrics{snap}}
	res, err := p.Plan(context.Background(), Request{Text: "show cpu and disk and memory"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if res.Status != StatusObserved {
		t.Fatalf("status = %q, want observed", res.Status)
	}
	// Deterministic order: memory, disk, cpu.
	mem := strings.Index(res.Summary, "RAM")
	disk := strings.Index(res.Summary, "/ ")
	cpu := strings.Index(res.Summary, "CPU at")
	if !(mem >= 0 && disk > mem && cpu > disk) {
		t.Errorf("intents out of order: %q (mem=%d disk=%d cpu=%d)", res.Summary, mem, disk, cpu)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
}

func TestHostQueryPlanner_DiskSummaryIsUserReadable(t *testing.T) {
	snap := infra.HostMetrics{Disks: []infra.DiskMetric{
		{Mountpoint: "/", Available: true, TotalBytes: 144 * 1024 * 1024 * 1024, AvailableBytes: 102 * 1024 * 1024 * 1024, Percent: 29},
		{Mountpoint: "/boot", Available: true, TotalBytes: 880 * 1024 * 1024, AvailableBytes: 702 * 1024 * 1024, Percent: 20},
		{Mountpoint: "/boot/efi", Available: true, TotalBytes: 104 * 1024 * 1024, AvailableBytes: 98 * 1024 * 1024, Percent: 6},
	}}
	p := HostQueryPlanner{Metrics: fakeMetrics{snap}, Hostname: "Orivo"}
	res, err := p.Plan(context.Background(), Request{Text: "check disk space"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if res.Status != StatusObserved {
		t.Fatalf("status = %q, want observed", res.Status)
	}
	if strings.Contains(res.Summary, ", /boot") {
		t.Fatalf("summary still looks like raw mount dump: %q", res.Summary)
	}
	for _, want := range []string{"Orivo:", "Disk space looks OK", "/ has", "Checked 3 mountpoints"} {
		if !strings.Contains(res.Summary, want) {
			t.Fatalf("summary %q missing %q", res.Summary, want)
		}
	}
	if !strings.Contains(res.Events[0].Message, "/boot") {
		t.Fatalf("raw mount evidence should remain in event: %q", res.Events[0].Message)
	}
}

func TestHostQueryPlanner_MemoryUnavailable(t *testing.T) {
	snap := infra.HostMetrics{Memory: infra.MemoryMetric{
		MetricReason: infra.MetricReason{Available: false, Reason: infra.ReasonUnavailable, Message: "meminfo missing"},
	}}
	p := HostQueryPlanner{Metrics: fakeMetrics{snap}}
	res, err := p.Plan(context.Background(), Request{Text: "how much memory is free"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if res.Status != StatusObserved {
		t.Fatalf("status = %q, want observed", res.Status)
	}
	if !strings.Contains(res.Summary, "unavailable") {
		t.Errorf("expected unavailable note: %q", res.Summary)
	}
}
