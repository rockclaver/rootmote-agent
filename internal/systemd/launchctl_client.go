package systemd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// LaunchctlClient adapts macOS launchd jobs to the existing service snapshot
// model used by the mobile app. It is intentionally conservative: listing and
// status are supported, while unsupported lifecycle verbs return a clear error.
type LaunchctlClient struct {
	Binary  string
	Timeout time.Duration
	Run     func(context.Context, string, ...string) ([]byte, error)
	UID     string
}

func NewLaunchctlClient() *LaunchctlClient { return &LaunchctlClient{} }

func (c *LaunchctlClient) bin() string {
	if c.Binary != "" {
		return c.Binary
	}
	return "launchctl"
}

func (c *LaunchctlClient) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 8 * time.Second
}

func (c *LaunchctlClient) run(ctx context.Context, args ...string) ([]byte, error) {
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	return run(cctx, c.bin(), args...)
}

func (c *LaunchctlClient) Available(context.Context) error {
	if _, err := exec.LookPath(c.bin()); err != nil {
		return ErrNotSystemd
	}
	return nil
}

func (c *LaunchctlClient) List(ctx context.Context) ([]Unit, error) {
	out, err := c.run(ctx, "list")
	if err != nil {
		return nil, fmt.Errorf("launchctl list: %w", err)
	}
	return parseLaunchctlList(string(out)), nil
}

func (c *LaunchctlClient) Get(ctx context.Context, name string) (UnitDetail, error) {
	if strings.TrimSpace(name) == "" {
		return UnitDetail{}, errors.New("launchctl: service name required")
	}
	for _, u := range mustLaunchctlList(c, ctx) {
		if u.Name == name {
			return UnitDetail{Unit: u, FragmentPath: c.domain() + "/" + name}, nil
		}
	}
	return UnitDetail{}, fmt.Errorf("launchctl: unknown service %q", name)
}

func (c *LaunchctlClient) Action(ctx context.Context, name string, action Action) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("launchctl: service name required")
	}
	target := c.domain() + "/" + name
	var args []string
	switch action {
	case ActionStart:
		args = []string{"kickstart", target}
	case ActionRestart:
		args = []string{"kickstart", "-k", target}
	case ActionStop:
		args = []string{"kill", "TERM", target}
	default:
		return fmt.Errorf("launchctl: action %q is not supported on macOS", action)
	}
	out, err := c.run(ctx, args...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func (c *LaunchctlClient) Reboot(context.Context) error {
	return errors.New("launchctl: reboot is not supported by this agent")
}

func (c *LaunchctlClient) domain() string {
	uid := c.UID
	if uid == "" {
		if u, err := user.Current(); err == nil {
			uid = u.Uid
		}
	}
	if uid == "" {
		uid = "501"
	}
	return "gui/" + uid
}

func mustLaunchctlList(c *LaunchctlClient, ctx context.Context) []Unit {
	units, err := c.List(ctx)
	if err != nil {
		return nil
	}
	return units
}

func parseLaunchctlList(raw string) []Unit {
	var units []Unit
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		label := fields[2]
		pid := 0
		if fields[0] != "-" {
			pid, _ = strconv.Atoi(fields[0])
		}
		status := fields[1]
		active := "inactive"
		sub := "exited"
		if pid > 0 {
			active = "active"
			sub = "running"
		} else if status != "0" {
			active = "failed"
		}
		units = append(units, Unit{
			Name:          label,
			Description:   label,
			LoadState:     "loaded",
			ActiveState:   active,
			SubState:      sub,
			EnabledOnBoot: "loaded",
		})
	}
	return units
}
