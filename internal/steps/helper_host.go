package steps

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/firewall"
)

// hostNSEnv marks the second run of the helper, inside PID 1's mount
// namespace, so it never re-enters again.
const hostNSEnv = "ROOTMOTE_PRIV_HOSTNS"

// safePath is the PATH the helper uses for every command it runs.
const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

// OSHost is the production Host.
type OSHost struct {
	ProcRoot string
	// ClockTicks is not needed: start times stay in the kernel's own units.
}

// NewOSHost returns a Host for the real machine and fixes PATH so commands
// are found in the standard system directories only.
func NewOSHost() *OSHost {
	_ = os.Setenv("PATH", safePath)
	return &OSHost{ProcRoot: "/proc"}
}

func (o *OSHost) proc() string {
	if o.ProcRoot != "" {
		return o.ProcRoot
	}
	return "/proc"
}

func (o *OSHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + safePath, "LANG=C", "LC_ALL=C", "HOME=/root"}
	return cmd.CombinedOutput()
}

func (o *OSHost) LookPath(name string) (string, error)    { return exec.LookPath(name) }
func (o *OSHost) ReadFile(p string) ([]byte, error)       { return os.ReadFile(p) }
func (o *OSHost) ReadDir(p string) ([]fs.DirEntry, error) { return os.ReadDir(p) }
func (o *OSHost) Stat(p string) (fs.FileInfo, error)      { return os.Stat(p) }
func (o *OSHost) Lstat(p string) (fs.FileInfo, error)     { return os.Lstat(p) }
func (o *OSHost) Self() int                               { return os.Getpid() }
func (o *OSHost) Chdir(dir string) error                  { return os.Chdir(dir) }
func (o *OSHost) Now() time.Time                          { return time.Now() }

// ReadTail implements Host.ReadTail. The file is opened with O_NOFOLLOW and
// checked after opening, so it cannot be swapped for a link or a device
// between the check and the read.
func (o *OSHost) ReadTail(p string, max int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	start := int64(0)
	if fi.Size() > max {
		start = fi.Size() - max
	}
	buf := make([]byte, fi.Size()-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

func (o *OSHost) FileUID(p string) (int, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("owner not available")
	}
	return int(st.Uid), nil
}

func (o *OSHost) LookupUser(name string) (UserInfo, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return UserInfo{}, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return UserInfo{}, errors.New("bad user ids")
	}
	return UserInfo{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir, Shell: passwdShell(name)}, nil
}

// passwdShell reads the login shell of a user from /etc/passwd.
func passwdShell(name string) string {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == name {
			return f[6]
		}
	}
	return ""
}

func (o *OSHost) PIDs() []int {
	entries, err := os.ReadDir(o.proc())
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if n, err := strconv.Atoi(e.Name()); err == nil && n > 0 {
			pids = append(pids, n)
		}
	}
	return pids
}

// statFields parses /proc/<pid>/stat into (comm, state, ppid, starttime).
func (o *OSHost) statFields(pid int) (comm, state string, ppid int, start uint64, ok bool) {
	raw, err := os.ReadFile(filepath.Join(o.proc(), strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", "", 0, 0, false
	}
	return ParseProcStat(string(raw))
}

// ParseProcStat reads one /proc/<pid>/stat line. The command name sits in
// parentheses and may itself contain spaces or parentheses, so fields are
// counted from the last ')'.
func ParseProcStat(s string) (comm, state string, ppid int, start uint64, ok bool) {
	l := strings.IndexByte(s, '(')
	r := strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return "", "", 0, 0, false
	}
	comm = s[l+1 : r]
	f := strings.Fields(s[r+1:])
	// f[0]=state f[1]=ppid ... f[19]=starttime
	if len(f) < 20 {
		return "", "", 0, 0, false
	}
	pp, err1 := strconv.Atoi(f[1])
	st, err2 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return "", "", 0, 0, false
	}
	return comm, f[0], pp, st, true
}

func (o *OSHost) ParentPID(pid int) int {
	_, _, pp, _, ok := o.statFields(pid)
	if !ok {
		return 0
	}
	return pp
}

func (o *OSHost) Comm(pid int) string {
	c, _, _, _, _ := o.statFields(pid)
	return c
}

func (o *OSHost) StartTime(pid int) (uint64, bool) {
	_, state, _, st, ok := o.statFields(pid)
	if !ok || state == "Z" || state == "X" {
		return 0, false
	}
	return st, true
}

func (o *OSHost) Sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (o *OSHost) Firewall() *firewall.Manager {
	reader := firewall.NewSSCommandReader()
	m, err := firewall.New(firewall.Config{
		Backends: []firewall.Backend{firewall.NewUFWBackend(), firewall.NewFirewalldBackend()},
		Sockets:  reader,
		SSH:      firewall.SSHFromHost{Reader: reader, ReadFile: os.ReadFile, ReadDir: os.ReadDir},
	})
	if err != nil {
		return nil
	}
	return m
}

func (o *OSHost) InHostNS() bool {
	if os.Getenv(hostNSEnv) != "" {
		return true
	}
	self, err1 := os.Readlink("/proc/self/ns/mnt")
	init, err2 := os.Readlink("/proc/1/ns/mnt")
	if err1 != nil || err2 != nil {
		// Cannot tell (not Linux, or no access): run in place.
		return true
	}
	return self == init
}

func (o *OSHost) RunInHostNS(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	exe, err := os.Executable()
	if err != nil {
		exe = HelperPath
	}
	argv := append([]string{"--mount=/proc/1/ns/mnt", "--", exe, "priv"}, args...)
	cmd := exec.CommandContext(ctx, "nsenter", argv...)
	cmd.Env = []string{"PATH=" + safePath, "LANG=C", hostNSEnv + "=1"}
	var errBuf bytes.Buffer
	cmd.Stdout = stdout
	cmd.Stderr = io.MultiWriter(stderr, &errBuf)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		_, _ = stderr.Write([]byte("Could not enter the host's mount namespace: " + err.Error() + "\n"))
		return ExitFailed
	}
	return ExitOK
}
