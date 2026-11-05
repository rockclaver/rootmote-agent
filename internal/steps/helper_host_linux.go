//go:build linux

package steps

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// pidfd pins one process. Once it is open, the pid can no longer be reused by
// another program: signals sent through it reach the process it was opened
// for, or fail with ESRCH when that process has ended.
type pidfd struct{ fd int }

// OpenProcess opens a pidfd for pid.
func (o *OSHost) OpenProcess(pid int) (Process, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	return &pidfd{fd: fd}, nil
}

func (p *pidfd) Signal(sig syscall.Signal) error {
	return unix.PidfdSendSignal(p.fd, unix.Signal(sig), nil, 0)
}

func (p *pidfd) Close() error { return unix.Close(p.fd) }
