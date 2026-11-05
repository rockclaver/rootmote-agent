package steps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HelperPath is where the installer puts the agent binary. The sudoers rule
// allows exactly `HelperPath priv *`.
const HelperPath = "/usr/local/bin/rootmote-agent"

// Helper exit codes (contract C2).
const (
	ExitOK      = 0
	ExitFailed  = 1
	ExitRefused = 2
)

// PrivCommand returns the command that runs one helper action: `sudo -n
// <helper> priv <action> <args...>` when the agent is not root, or the helper
// directly when it is.
func PrivCommand(action string, args ...string) (name string, argv []string) {
	argv = append([]string{"priv", action}, args...)
	if os.Geteuid() == 0 {
		return HelperPath, argv
	}
	return "sudo", append([]string{"-n", HelperPath}, argv...)
}

// ExecPriv is the production PrivCaller.
type ExecPriv struct {
	// Timeout caps one helper call. Defaults to 3 minutes (certbot can be slow).
	Timeout time.Duration
}

// Call implements PrivCaller.
func (e ExecPriv) Call(ctx context.Context, action string, args ...string) ([]byte, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	name, argv := PrivCommand(action, args...)
	cmd := exec.CommandContext(ctx, name, argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	msg := strings.TrimSpace(stderr.String())
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == ExitRefused && msg != "" {
		return nil, &RefusedError{Msg: msg}
	}
	if msg == "" {
		msg = err.Error()
	}
	return stdout.Bytes(), fmt.Errorf("%s", msg)
}
