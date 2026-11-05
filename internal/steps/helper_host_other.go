//go:build !linux

package steps

import "syscall"

// Systems without pidfd (the helper only runs on Linux in production) signal
// by pid.
type pidSignal struct{ pid int }

// OpenProcess returns a handle that signals by pid.
func (o *OSHost) OpenProcess(pid int) (Process, error) { return pidSignal{pid: pid}, nil }

func (p pidSignal) Signal(sig syscall.Signal) error { return syscall.Kill(p.pid, sig) }
func (p pidSignal) Close() error                    { return nil }
