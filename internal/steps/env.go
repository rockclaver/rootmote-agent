package steps

import (
	"context"
	"time"
)

// PrivCaller runs one privilege-helper action and returns its stdout. A
// deliberate refusal comes back as *RefusedError.
type PrivCaller interface {
	Call(ctx context.Context, action string, args ...string) ([]byte, error)
}

// UnitStatus is what the agent can read about a systemd unit without root.
type UnitStatus struct {
	LoadState   string
	ActiveState string
	SubState    string
	NRestarts   int
}

// Units reads and changes systemd units. Action runs start, stop, restart or
// reload; production wiring sends those through the privilege helper.
type Units interface {
	Action(ctx context.Context, unit, verb string) error
	Status(ctx context.Context, unit string) (UnitStatus, error)
}

// ContainerInfo is the subset of a Docker container the steps need.
type ContainerInfo struct {
	ID             string
	Name           string
	State          string
	Health         string
	RestartCount   int
	ComposeProject string
	ComposeService string
	Labels         map[string]string
}

// Docker is the agent's Docker access. It never touches volumes.
type Docker interface {
	Containers(ctx context.Context) ([]ContainerInfo, error)
	Restart(ctx context.Context, id string) error
	Start(ctx context.Context, id string) error
	// PruneDangling removes dangling images and unused build cache only.
	PruneDangling(ctx context.Context) (freedBytes int64, err error)
	// RootDir is Docker's data directory (from `docker info`), where images
	// and build cache live.
	RootDir(ctx context.Context) (string, error)
}

// ProcTable looks up a process by pid.
type ProcTable interface {
	// StartTime returns the process start time in clock ticks, or alive=false
	// when the pid does not exist (or is a zombie).
	StartTime(pid int) (ticks uint64, alive bool)
}

// HTTPGetter makes one GET request and returns the status code.
type HTTPGetter interface {
	Get(ctx context.Context, url string) (int, error)
}

// Env holds everything the agent-side step code needs. Nil members make the
// steps that need them fail with a plain message instead of panicking.
type Env struct {
	Priv   PrivCaller
	Units  Units
	Docker Docker
	Procs  ProcTable
	HTTP   HTTPGetter
	// AllowedURL reports whether a URL points at this host (from discovery
	// or configured monitors).
	AllowedURL func(url string) bool
	// DiskPercentAt returns the used percentage of the filesystem mount that
	// contains path. A disk step checks the mount of the folder it frees space
	// in, not always "/".
	DiskPercentAt func(ctx context.Context, path string) (float64, error)
	Now           func() time.Time
	// Sleep waits d or until ctx ends.
	Sleep func(ctx context.Context, d time.Duration)

	ServiceStable    time.Duration
	ContainerStable  time.Duration
	PM2Stable        time.Duration
	SupervisorStable time.Duration
	KillGrace        time.Duration
}

// DiskThresholdPercent is the "disk is fine again" line used by the disk
// steps. It matches the disk monitor's recovery value.
const DiskThresholdPercent = 85

// CertMinDays is how far away a renewed certificate's expiry must be.
const CertMinDays = 30

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) sleep(ctx context.Context, d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (e *Env) serviceStable() time.Duration    { return orDefault(e.ServiceStable, 30*time.Second) }
func (e *Env) containerStable() time.Duration  { return orDefault(e.ContainerStable, 60*time.Second) }
func (e *Env) pm2Stable() time.Duration        { return orDefault(e.PM2Stable, 60*time.Second) }
func (e *Env) supervisorStable() time.Duration { return orDefault(e.SupervisorStable, 30*time.Second) }
