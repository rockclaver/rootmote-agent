package monitor

import (
	"context"
	"runtime"

	"github.com/rockclaver/rootmote-agent/internal/firewall"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
)

// processListLimit is large enough to cover every process on a host:
// process.Manager.List truncates to its limit after sorting.
const processListLimit = 1 << 20

// processLister is the subset of *process.Manager the monitor adapter uses.
type processLister interface {
	List(ctx context.Context, sortBy string, limit int) ([]agentprocess.Process, error)
}

// processSource adapts the agent's process manager to ProcessSource.
type processSource struct{ lister processLister }

func (p processSource) Running(ctx context.Context) ([]ProcessInfo, error) {
	procs, err := p.lister.List(ctx, agentprocess.SortCPU, processListLimit)
	if err != nil {
		return nil, err
	}
	out := make([]ProcessInfo, 0, len(procs))
	for _, pr := range procs {
		out = append(out, ProcessInfo{Command: pr.Command, ExePath: pr.ExePath})
	}
	return out, nil
}

// defaultSocketSource mirrors the agent's own platform choice of socket
// reader (ss on Linux, netstat on macOS).
func defaultSocketSource() SocketSource {
	if runtime.GOOS == "darwin" {
		return firewall.NewNetstatSocketReader()
	}
	return firewall.NewSSCommandReader()
}

// defaultProcessSource builds a process source backed by a process.Manager,
// or nil if the manager cannot be constructed.
func defaultProcessSource() ProcessSource {
	mgr, err := agentprocess.New(agentprocess.Config{Platform: runtime.GOOS})
	if err != nil {
		return nil
	}
	return processSource{lister: mgr}
}
