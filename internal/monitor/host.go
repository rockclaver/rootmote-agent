package monitor

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Host is the monitor engine's narrow view of the local machine for the
// evaluators that touch the filesystem, run helper commands, or dial TLS
// endpoints. OSHost is the production implementation; tests pass a fake.
type Host interface {
	// Stat returns file info for path (following symlinks).
	Stat(path string) (fs.FileInfo, error)
	// Glob expands a filepath.Match pattern.
	Glob(pattern string) ([]string, error)
	// ReadFile reads a whole (small) file.
	ReadFile(path string) ([]byte, error)
	// ReadFrom reads path from byte offset to EOF, returning at most
	// maxBytes (the newest bytes when more are available) plus the size
	// observed, which the caller passes back as the next offset. A file
	// shorter than offset (rotated/truncated) is re-read from zero.
	ReadFrom(path string, offset int64, maxBytes int64) (data []byte, size int64, err error)
	// Run executes a helper command and returns stdout.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// BootID returns a value that changes on every boot of the host.
	BootID(ctx context.Context) (string, error)
	// CertNotAfter dials addr over TLS and returns the leaf certificate's
	// expiry. serverName overrides SNI (and defaults to addr's host).
	CertNotAfter(ctx context.Context, addr, serverName string) (time.Time, error)
}

// OSHost implements Host against the real machine.
type OSHost struct{}

const (
	hostCommandTimeout = 20 * time.Second
	tlsDialTimeout     = 10 * time.Second
)

func (OSHost) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }
func (OSHost) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }
func (OSHost) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }

func (OSHost) ReadFrom(path string, offset, maxBytes int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if size < offset {
		offset = 0
	}
	if size-offset > maxBytes {
		offset = size - maxBytes
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(f, size-offset))
	return data, size, err
}

func (OSHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, hostCommandTimeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

var bootTimeSec = regexp.MustCompile(`sec\s*=\s*(\d+)`)

func (h OSHost) BootID(ctx context.Context) (string, error) {
	if runtime.GOOS == "darwin" {
		out, err := h.Run(ctx, "sysctl", "-n", "kern.boottime")
		if err != nil {
			return "", err
		}
		return parseDarwinBootTime(string(out))
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("empty boot_id")
	}
	return id, nil
}

// parseDarwinBootTime extracts the boot epoch from `sysctl -n kern.boottime`
// ("{ sec = 1700000000, usec = 0 } ...").
func parseDarwinBootTime(out string) (string, error) {
	m := bootTimeSec.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("unrecognised kern.boottime %q", strings.TrimSpace(out))
	}
	if _, err := strconv.ParseInt(m[1], 10, 64); err != nil {
		return "", err
	}
	return "boottime-" + m[1], nil
}

func (OSHost) CertNotAfter(ctx context.Context, addr, serverName string) (time.Time, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return time.Time{}, err
	}
	if serverName == "" {
		serverName = host
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: tlsDialTimeout},
		// Expiry is judged by the evaluator, not the handshake: an expired
		// or self-signed certificate must still be readable so it can be
		// reported with its real NotAfter.
		Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true}, //nolint:gosec
	}
	ctx, cancel := context.WithTimeout(ctx, tlsDialTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return time.Time{}, errors.New("no peer certificate presented")
	}
	return state.PeerCertificates[0].NotAfter, nil
}
