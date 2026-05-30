package systemd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SystemctlClient is the production Client that shells out to systemctl. It is
// kept deliberately narrow: every method runs one systemctl invocation and
// parses tab/colon-delimited output, so the agent does not pull a full dbus
// dependency.
type SystemctlClient struct {
	// Binary overrides the systemctl path. Defaults to "systemctl".
	Binary string
	// Timeout caps each invocation. Defaults to 8s.
	Timeout time.Duration
}

// NewSystemctlClient returns a SystemctlClient with sane defaults.
func NewSystemctlClient() *SystemctlClient { return &SystemctlClient{} }

func (c *SystemctlClient) bin() string {
	if c.Binary != "" {
		return c.Binary
	}
	return "systemctl"
}

func (c *SystemctlClient) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 8 * time.Second
}

// Available probes for systemd by running `systemctl is-system-running`. Any
// state other than missing-binary / bus-not-found is treated as
// "systemd is here, however degraded".
func (c *SystemctlClient) Available(ctx context.Context) error {
	if _, err := exec.LookPath(c.bin()); err != nil {
		return ErrNotSystemd
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return ErrNotSystemd
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	out, err := exec.CommandContext(cctx, c.bin(), "is-system-running").CombinedOutput()
	state := strings.TrimSpace(string(out))
	// Any of running/degraded/maintenance/starting/stopping count as "systemd
	// is here". Only "offline" / missing means not-systemd.
	if state == "offline" {
		return ErrNotSystemd
	}
	if err != nil && state == "" {
		return fmt.Errorf("systemctl is-system-running: %w", err)
	}
	return nil
}

// List enumerates loaded units and decorates each with UnitFileState.
func (c *SystemctlClient) List(ctx context.Context) ([]Unit, error) {
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(),
		"list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	units := parseListUnits(string(out))

	enabled, err := c.unitFileStates(cctx)
	if err == nil {
		for i := range units {
			if state, ok := enabled[units[i].Name]; ok {
				units[i].EnabledOnBoot = state
			}
		}
	}
	return units, nil
}

func (c *SystemctlClient) unitFileStates(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, c.bin(),
		"list-unit-files", "--type=service", "--no-legend", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	states := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		states[fields[0]] = fields[1]
	}
	return states, nil
}

// Get returns a single unit's detail by parsing `systemctl show`.
func (c *SystemctlClient) Get(ctx context.Context, name string) (UnitDetail, error) {
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(), "show", name,
		"--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,Following")
	out, err := cmd.Output()
	if err != nil {
		return UnitDetail{}, fmt.Errorf("systemctl show %s: %w", name, err)
	}
	props := parseShowProperties(string(out))
	id := props["Id"]
	if id == "" {
		id = name
	}
	return UnitDetail{
		Unit: Unit{
			Name:          id,
			Description:   props["Description"],
			LoadState:     props["LoadState"],
			ActiveState:   props["ActiveState"],
			SubState:      props["SubState"],
			EnabledOnBoot: props["UnitFileState"],
		},
		FragmentPath: props["FragmentPath"],
		Following:    props["Following"],
	}, nil
}

// Action runs `systemctl <verb> <unit>`.
func (c *SystemctlClient) Action(ctx context.Context, name string, action Action) error {
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(), string(action), name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func parseListUnits(s string) []Unit {
	var units []Unit
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		load := fields[1]
		active := fields[2]
		sub := fields[3]
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		units = append(units, Unit{
			Name:        name,
			LoadState:   load,
			ActiveState: active,
			SubState:    sub,
			Description: desc,
		})
	}
	return units
}

func parseShowProperties(s string) map[string]string {
	props := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		props[line[:i]] = line[i+1:]
	}
	return props
}
