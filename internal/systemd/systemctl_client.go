package systemd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/steps"
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
	// Priv runs privilege-helper actions; defaults to steps.ExecPriv.
	Priv steps.PrivCaller
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
	types, err := c.unitTypes(cctx)
	if err == nil {
		for i := range units {
			units[i].Type = types[units[i].Name]
		}
	}
	return units, nil
}

// unitTypes returns Type= per service unit via one `systemctl show` call.
// Failure is non-fatal for callers: an unknown Type is simply not oneshot.
func (c *SystemctlClient) unitTypes(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, c.bin(), "show", "*.service", "--property=Id,Type", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseUnitTypes(string(out)), nil
}

// parseUnitTypes parses `systemctl show --property=Id,Type` output: one
// property block per unit, blocks separated by a blank line.
func parseUnitTypes(s string) map[string]string {
	types := map[string]string{}
	var id, typ string
	flush := func() {
		if id != "" {
			types[id] = typ
		}
		id, typ = "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Id="):
			id = strings.TrimPrefix(line, "Id=")
		case strings.HasPrefix(line, "Type="):
			typ = strings.TrimPrefix(line, "Type=")
		}
	}
	flush()
	return types
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
		"--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,Following,NRestarts")
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
		NRestarts:    atoiOr0(props["NRestarts"]),
	}, nil
}

// Action runs `systemctl <verb> <unit>`. The agent normally runs as the
// unprivileged `rootmote` user, which cannot change services, so start, stop,
// restart and reload go through the privilege helper
// (`sudo -n rootmote-agent priv service.<verb> <unit>`), which validates the
// unit name and refuses protected units as root. When the agent already runs
// as root it calls systemctl directly. Other verbs (enable, disable) run
// directly and need root.
func (c *SystemctlClient) Action(ctx context.Context, name string, action Action) error {
	switch action {
	case ActionStart, ActionStop, ActionRestart, ActionReload:
		if os.Geteuid() != 0 {
			priv := c.Priv
			if priv == nil {
				priv = steps.ExecPriv{}
			}
			_, err := priv.Call(ctx, "service."+string(action), name)
			return err
		}
	}
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

func atoiOr0(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
