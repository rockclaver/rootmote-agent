package steps

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/firewall"
)

// LetsEncryptLive is where certbot keeps one directory per certificate name.
const LetsEncryptLive = "/etc/letsencrypt/live"

// LetsEncryptRenewal is where certbot keeps one renewal settings file per certificate name.
const LetsEncryptRenewal = "/etc/letsencrypt/renewal"

// UserInfo is a looked-up login user.
type UserInfo struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// Host is everything the privilege helper touches. The production
// implementation is OSHost; tests use a fake.
type Host interface {
	// Run executes one command with an exact argv (no shell) and returns its
	// combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath(name string) (string, error)
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	// ReadTail returns at most max bytes from the end of a regular file. It
	// refuses a symlink at the final path component and anything that is not
	// a regular file.
	ReadTail(path string, max int64) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
	Lstat(path string) (fs.FileInfo, error)
	// FileUID returns the owner of a file.
	FileUID(path string) (int, error)
	LookupUser(name string) (UserInfo, error)

	// Process table.
	Self() int
	PIDs() []int
	ParentPID(pid int) int
	Comm(pid int) string
	// StartTime returns the start time in clock ticks, alive=false when the
	// process does not exist or is a zombie.
	StartTime(pid int) (ticks uint64, alive bool)
	// OpenProcess pins a process (pidfd on Linux) so a signal can never
	// reach a different program that reuses the pid.
	OpenProcess(pid int) (Process, error)
	// Chdir changes the helper's working directory.
	Chdir(dir string) error

	Sleep(ctx context.Context, d time.Duration)
	Now() time.Time
	Firewall() *firewall.Manager

	// InHostNS reports whether this process already runs in PID 1's mount
	// namespace. RunInHostNS runs the helper again there (through
	// `nsenter --mount=/proc/1/ns/mnt`) and returns its exit code.
	InHostNS() bool
	RunInHostNS(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

// Process is a pinned process opened with Host.OpenProcess.
type Process interface {
	Signal(sig syscall.Signal) error
	Close() error
}

type privAction struct {
	// hostNS actions need the real (unsandboxed) mount namespace: they write
	// outside the agent's sandbox or read /home.
	hostNS bool
	run    func(ctx context.Context, h Host, args []string, out io.Writer) error
}

func privActions() map[string]privAction {
	return map[string]privAction{
		"service.restart":     {run: serviceAction("restart")},
		"service.start":       {run: serviceAction("start")},
		"service.stop":        {run: serviceAction("stop")},
		"service.reload":      {run: serviceAction("reload")},
		"phpfpm.restart":      {run: phpfpmRestart},
		"nginx.reload":        {hostNS: true, run: nginxReload},
		"nginx-test":          {hostNS: true, run: nginxTest},
		"supervisor.restart":  {run: supervisorRestart},
		"supervisor-status":   {run: supervisorStatus},
		"disk.journal_vacuum": {hostNS: true, run: journalVacuum},
		"disk.apt_clean":      {hostNS: true, run: aptClean},
		"cert.renew":          {hostNS: true, run: certRenew},
		"certs-list":          {run: certsList},
		"web-errors":          {run: webErrors},
		"pm2.restart":         {hostNS: true, run: pm2Restart},
		"pm2-list":            {hostNS: true, run: pm2ListAction},
		"process.stop":        {run: processStop},
		"firewall.allow":      {hostNS: true, run: firewallChange(true)},
		"firewall.remove":     {hostNS: true, run: firewallChange(false)},
		"firewall-rules":      {hostNS: true, run: firewallRules},
	}
}

// PrivActionNames lists every action the helper accepts, sorted.
func PrivActionNames() []string {
	var names []string
	for n := range privActions() {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RunPriv implements `rootmote-agent priv <action> <args...>`. args starts at
// the action. It returns the exit code: 0 ok, 2 refused (stderr holds one
// plain-English sentence), 1 failed.
func RunPriv(ctx context.Context, h Host, args []string, stdout, stderr io.Writer) int {
	// The caller picks the working directory under sudo. Programs the helper
	// starts must not look for files in a directory the caller controls.
	if err := h.Chdir("/"); err != nil {
		fmt.Fprintln(stderr, "Could not leave the caller's folder.")
		return ExitFailed
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "No action was given.")
		return ExitRefused
	}
	act, ok := privActions()[args[0]]
	if !ok {
		fmt.Fprintln(stderr, "That action is not allowed.")
		return ExitRefused
	}
	if act.hostNS && !h.InHostNS() {
		return h.RunInHostNS(ctx, args, stdout, stderr)
	}
	if err := act.run(ctx, h, args[1:], stdout); err != nil {
		fmt.Fprintln(stderr, oneLine(err.Error()))
		if IsRefused(err) {
			return ExitRefused
		}
		return ExitFailed
	}
	return ExitOK
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 800 {
		s = s[len(s)-800:]
	}
	return strings.Join(strings.Fields(s), " ")
}

func wantArgs(args []string, n int) error {
	if len(args) != n {
		return refuse("The wrong number of arguments was given.")
	}
	return nil
}

func run(ctx context.Context, h Host, name string, args ...string) (string, error) {
	out, err := h.Run(ctx, name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return string(out), fmt.Errorf("%s %s failed: %s", name, args[0], msg)
	}
	return string(out), nil
}

// ---- services --------------------------------------------------------------

// unitFacts reads the canonical unit id and load state as root.
func unitFacts(ctx context.Context, h Host, unit string) (id, load string, err error) {
	out, err := h.Run(ctx, "systemctl", "show", "--property=Id,LoadState", unit)
	if err != nil {
		return "", "", refuse("There is no service called %s on this server.", unit)
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			id = v
		case "LoadState":
			load = v
		}
	}
	return id, load, nil
}

// checkUnit validates a unit name, refuses protected units (also through an
// alias) and requires the unit to exist right now.
func checkUnit(ctx context.Context, h Host, unit string) error {
	if err := CheckUnitAllowed(unit); err != nil {
		return err
	}
	id, load, err := unitFacts(ctx, h, unit)
	if err != nil {
		return err
	}
	if load != "loaded" {
		return refuse("There is no service called %s on this server.", unit)
	}
	if !strings.HasSuffix(id, ".service") {
		return refuse("%s is not a service. Rootmote only changes services.", unit)
	}
	return CheckUnitAllowed(id)
}

func serviceAction(verb string) func(context.Context, Host, []string, io.Writer) error {
	return func(ctx context.Context, h Host, args []string, out io.Writer) error {
		if err := wantArgs(args, 1); err != nil {
			return err
		}
		if err := checkUnit(ctx, h, args[0]); err != nil {
			return err
		}
		if _, err := run(ctx, h, "systemctl", verb, args[0]); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s %s done.\n", verb, args[0])
		return nil
	}
}

func phpfpmRestart(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 1); err != nil {
		return err
	}
	if err := ValidatePHPUnit(args[0]); err != nil {
		return err
	}
	return serviceAction("restart")(ctx, h, args, out)
}

// ---- nginx -----------------------------------------------------------------

func nginxTest(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	if _, err := h.LookPath("nginx"); err != nil {
		return refuse("nginx is not installed on this server.")
	}
	o, err := h.Run(ctx, "nginx", "-t")
	if err != nil {
		return fmt.Errorf("The nginx settings test failed: %s", oneLine(string(o)))
	}
	fmt.Fprintln(out, "nginx settings test passed.")
	return nil
}

func nginxReload(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	return reloadNginx(ctx, h, out)
}

// reloadNginx runs `nginx -t` first and reloads only if it passes.
func reloadNginx(ctx context.Context, h Host, out io.Writer) error {
	if _, err := h.LookPath("nginx"); err != nil {
		return refuse("nginx is not installed on this server.")
	}
	id, load, err := unitFacts(ctx, h, "nginx.service")
	if err != nil || load != "loaded" || id == "" {
		return refuse("nginx is not installed on this server.")
	}
	o, err := h.Run(ctx, "nginx", "-t")
	if err != nil {
		return fmt.Errorf("The nginx settings test failed, so nginx was not reloaded: %s", oneLine(string(o)))
	}
	if _, err := run(ctx, h, "systemctl", "reload", "nginx"); err != nil {
		return err
	}
	fmt.Fprintln(out, "nginx settings test passed and nginx was reloaded.")
	return nil
}

// ---- supervisor ------------------------------------------------------------

// supervisorConfigs are the places a system Supervisor keeps its main file.
var supervisorConfigs = []string{"/etc/supervisor/supervisord.conf", "/etc/supervisord.conf", "/etc/supervisord/supervisord.conf"}

// supervisorConfig returns the main Supervisor file. It must be owned by root
// and not writable by anyone else, because supervisorctl runs as root and
// loads plugins named in it.
func supervisorConfig(h Host) (string, error) {
	for _, c := range supervisorConfigs {
		fi, err := h.Stat(c)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if uid, err := h.FileUID(c); err != nil || uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return "", refuse("The Supervisor settings file %s is not owned by root, so Rootmote will not use it.", c)
		}
		return c, nil
	}
	return "", refuse("Rootmote could not find the Supervisor settings file.")
}

func supervisorPrograms(ctx context.Context, h Host) ([]supervisorProgram, error) {
	if _, err := h.LookPath("supervisorctl"); err != nil {
		return nil, refuse("Supervisor is not installed on this server.")
	}
	conf, err := supervisorConfig(h)
	if err != nil {
		return nil, err
	}
	// supervisorctl exits non-zero when any program is not RUNNING, so the
	// output is parsed whatever the exit status.
	out, _ := h.Run(ctx, "supervisorctl", "-c", conf, "status")
	list := parseSupervisorStatus(string(out))
	if len(list) == 0 && strings.TrimSpace(string(out)) != "" && !strings.Contains(string(out), "no such") {
		low := strings.ToLower(string(out))
		if strings.Contains(low, "refused") || strings.Contains(low, "error") || strings.Contains(low, "no such file") {
			return nil, fmt.Errorf("Could not talk to Supervisor: %s", oneLine(string(out)))
		}
	}
	return list, nil
}

func parseSupervisorStatus(s string) []supervisorProgram {
	list := []supervisorProgram{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !isUpper(f[1]) {
			continue
		}
		list = append(list, supervisorProgram{Name: f[0], State: f[1]})
	}
	return list
}

func isUpper(s string) bool {
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return s != ""
}

func supervisorStatus(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	list, err := supervisorPrograms(ctx, h)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(list)
}

func supervisorRestart(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 1); err != nil {
		return err
	}
	if err := ValidateName("program", args[0]); err != nil {
		return err
	}
	list, err := supervisorPrograms(ctx, h)
	if err != nil {
		return err
	}
	if len(MatchSupervisor(list, args[0])) == 0 {
		return refuse("There is no Supervisor program called %s.", args[0])
	}
	conf, err := supervisorConfig(h)
	if err != nil {
		return err
	}
	o, err := run(ctx, h, "supervisorctl", "-c", conf, "restart", args[0])
	if err != nil {
		return err
	}
	fmt.Fprint(out, o)
	return nil
}

// ---- disk ------------------------------------------------------------------

func journalVacuum(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 1); err != nil {
		return err
	}
	if _, ok := journalSizes[args[0]]; !ok {
		return refuse("The size must be 100M, 200M or 500M.")
	}
	o, err := run(ctx, h, "journalctl", "--vacuum-size="+args[0])
	if err != nil {
		return err
	}
	fmt.Fprint(out, o)
	return nil
}

func aptClean(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	if _, err := h.LookPath("apt-get"); err != nil {
		return refuse("This server does not use apt.")
	}
	if _, err := run(ctx, h, "apt-get", "clean"); err != nil {
		return err
	}
	fmt.Fprintln(out, "The package cache was cleared.")
	return nil
}

// ---- certificates ------------------------------------------------------------

func certRenew(ctx context.Context, h Host, args []string, out io.Writer) error {
	dry := false
	switch {
	case len(args) == 1:
	case len(args) == 2 && args[1] == "--dry-run":
		dry = true
	default:
		return refuse("The wrong number of arguments was given.")
	}
	name := args[0]
	if err := ValidateCertName(name); err != nil {
		return err
	}
	dir := path.Join(LetsEncryptLive, name)
	fi, err := h.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return refuse("There is no certificate called %s on this server.", name)
	}
	if _, err := h.Stat(path.Join(LetsEncryptRenewal, name+".conf")); err != nil {
		return refuse("The certificate %s has no renewal settings, so certbot cannot renew it. It was probably not issued by certbot.", name)
	}
	if _, err := h.LookPath("certbot"); err != nil {
		return refuse("certbot is not installed on this server.")
	}
	argv := []string{"renew", "--cert-name", name}
	if dry {
		argv = append(argv, "--dry-run")
	}
	o, err := h.Run(ctx, "certbot", argv...)
	if err != nil {
		return fmt.Errorf("certbot failed: %s", oneLine(string(o)))
	}
	fmt.Fprintln(out, oneLine(string(o)))
	if dry {
		return nil
	}
	if _, load, ferr := unitFacts(ctx, h, "nginx.service"); ferr == nil && load == "loaded" {
		if err := reloadNginx(ctx, h, out); err != nil {
			return err
		}
	}
	return nil
}

type certEntry struct {
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
}

func certsList(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	list := []certEntry{}
	entries, err := h.ReadDir(LetsEncryptLive)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() || ValidateCertName(e.Name()) != nil {
				continue
			}
			raw, err := h.ReadFile(path.Join(LetsEncryptLive, e.Name(), "fullchain.pem"))
			if err != nil {
				continue
			}
			block, _ := pem.Decode(raw)
			if block == nil {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			list = append(list, certEntry{Name: e.Name(), ExpiresAt: cert.NotAfter.UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return json.NewEncoder(out).Encode(list)
}

// ---- pm2 ---------------------------------------------------------------------

// pm2User validates a pm2 user: an existing non-root login user.
func pm2User(h Host, name string) (UserInfo, error) {
	if err := ValidateUser(name); err != nil {
		return UserInfo{}, err
	}
	u, err := h.LookupUser(name)
	if err != nil {
		return UserInfo{}, refuse("There is no user called %s.", name)
	}
	if u.UID == 0 || !filepath.IsAbs(u.Home) {
		return UserInfo{}, refuse("PM2 steps do not run as root.")
	}
	if strings.HasSuffix(u.Shell, "nologin") || strings.HasSuffix(u.Shell, "false") {
		return UserInfo{}, refuse("%s is not a login user.", name)
	}
	return u, nil
}

func pm2Home(h Host, u UserInfo) (string, bool) {
	home := path.Join(u.Home, ".pm2")
	fi, err := h.Stat(home)
	if err != nil || !fi.IsDir() {
		return home, false
	}
	if uid, err := h.FileUID(home); err != nil || uid != u.UID {
		return home, false
	}
	return home, true
}

func findPM2(h Host, u UserInfo) (string, error) {
	cands := []string{"/usr/local/bin/pm2", "/usr/bin/pm2",
		path.Join(u.Home, ".local/bin/pm2"), path.Join(u.Home, ".npm-global/bin/pm2"),
		path.Join(u.Home, ".volta/bin/pm2"), path.Join(u.Home, ".yarn/bin/pm2")}
	if vs, err := h.ReadDir(path.Join(u.Home, ".nvm/versions/node")); err == nil {
		var names []string
		for _, v := range vs {
			names = append(names, v.Name())
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, n := range names {
			cands = append(cands, path.Join(u.Home, ".nvm/versions/node", n, "bin/pm2"))
		}
	}
	for _, c := range cands {
		if fi, err := h.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", refuse("PM2 is not installed for user %s.", u.Name)
}

// PM2Argv builds the argv that runs pm2 as a user: setpriv drops to the
// user, env sets a clean HOME and PATH. No shell is involved.
func PM2Argv(u UserInfo, pm2 string, args ...string) (name string, argv []string) {
	p := path.Dir(pm2) + ":/usr/local/bin:/usr/bin:/bin"
	argv = []string{
		"--reuid=" + strconv.Itoa(u.UID), "--regid=" + strconv.Itoa(u.GID), "--init-groups", "--",
		"/usr/bin/env", "HOME=" + u.Home, "USER=" + u.Name, "LOGNAME=" + u.Name, "PATH=" + p, pm2,
	}
	argv = append(argv, args...)
	return "setpriv", argv
}

func pm2Apps(ctx context.Context, h Host, u UserInfo) ([]pm2App, error) {
	pm2, err := findPM2(h, u)
	if err != nil {
		return nil, err
	}
	name, argv := PM2Argv(u, pm2, "jlist")
	out, err := h.Run(ctx, name, argv...)
	if err != nil {
		return nil, fmt.Errorf("pm2 jlist failed: %s", oneLine(string(out)))
	}
	return parsePM2JList(out)
}

// parsePM2JList reads `pm2 jlist` output. pm2 may print banner lines before
// the JSON array, so the first '[' that starts a valid array is used.
func parsePM2JList(out []byte) ([]pm2App, error) {
	type raw struct {
		Name string `json:"name"`
		Env  struct {
			Status      string `json:"status"`
			RestartTime int    `json:"restart_time"`
		} `json:"pm2_env"`
	}
	s := string(out)
	for i := 0; i < len(s); i++ {
		if s[i] != '[' {
			continue
		}
		var list []raw
		dec := json.NewDecoder(strings.NewReader(s[i:]))
		if err := dec.Decode(&list); err != nil {
			continue
		}
		apps := make([]pm2App, 0, len(list))
		for _, r := range list {
			apps = append(apps, pm2App{App: r.Name, Status: r.Env.Status, Restarts: r.Env.RestartTime})
		}
		return apps, nil
	}
	return nil, errors.New("Could not read the PM2 app list.")
}

func pm2ListAction(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 1); err != nil {
		return err
	}
	u, err := pm2User(h, args[0])
	if err != nil {
		return err
	}
	if _, ok := pm2Home(h, u); !ok {
		_, err := fmt.Fprintln(out, "[]")
		return err
	}
	apps, err := pm2Apps(ctx, h, u)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(apps)
}

func pm2Restart(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 2); err != nil {
		return err
	}
	u, err := pm2User(h, args[0])
	if err != nil {
		return err
	}
	if err := ValidateName("app", args[1]); err != nil {
		return err
	}
	if _, ok := pm2Home(h, u); !ok {
		return refuse("User %s has no PM2 apps.", u.Name)
	}
	apps, err := pm2Apps(ctx, h, u)
	if err != nil {
		return err
	}
	found := false
	for _, a := range apps {
		if a.App == args[1] {
			found = true
		}
	}
	if !found {
		return refuse("There is no PM2 app called %s for user %s.", args[1], u.Name)
	}
	pm2, err := findPM2(h, u)
	if err != nil {
		return err
	}
	name, argv := PM2Argv(u, pm2, "restart", args[1])
	o, err := h.Run(ctx, name, argv...)
	if err != nil {
		return fmt.Errorf("pm2 restart failed: %s", oneLine(string(o)))
	}
	fmt.Fprintf(out, "Restarted %s.\n", args[1])
	return nil
}

// ---- process -----------------------------------------------------------------

var protectedComms = map[string]string{
	"sshd":           "the SSH daemon",
	"sshd-session":   "an SSH session",
	"rootmote-agent": "the Rootmote agent",
	"dockerd":        "the Docker daemon",
	"containerd":     "the container runtime",
	"dbus-daemon":    "the system message bus",
	"systemd":        "the init system",
}

// protectedPID explains why a pid may never be stopped, or "" when it may.
func protectedPID(h Host, pid int) string {
	if pid <= 1 || pid == h.Self() {
		return "that process"
	}
	if pid == 2 || h.ParentPID(pid) == 2 {
		return "a kernel thread"
	}
	comm := h.Comm(pid)
	if why, ok := protectedComms[comm]; ok {
		return why
	}
	if strings.HasPrefix(comm, "systemd-") {
		return "a core system service"
	}
	if strings.HasPrefix(comm, "sshd") {
		return "the SSH daemon"
	}
	// The helper's own ancestors, and everything under the agent that called it.
	var agentRoot int
	for p, n := h.Self(), 0; p > 1 && n < 64; p, n = h.ParentPID(p), n+1 {
		if p == pid {
			return "part of the Rootmote agent"
		}
		if h.Comm(p) == "rootmote-agent" {
			agentRoot = p
		}
	}
	if agentRoot != 0 {
		children := map[int][]int{}
		for _, p := range h.PIDs() {
			pp := h.ParentPID(p)
			children[pp] = append(children[pp], p)
		}
		queue := []int{agentRoot}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if cur == pid {
				return "part of the Rootmote agent"
			}
			queue = append(queue, children[cur]...)
		}
	}
	return ""
}

func processStop(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 2); err != nil {
		return err
	}
	pid, err := ParsePID(args[0])
	if err != nil {
		return err
	}
	start, err := ParseStartTime(args[1])
	if err != nil {
		return err
	}
	// Pin the process first. From here on a signal can only reach the
	// process that was opened, even if its pid is reused.
	proc, err := h.OpenProcess(pid)
	if err != nil {
		return refuse("Process %d is not running.", pid)
	}
	defer proc.Close()
	ticks, alive := h.StartTime(pid)
	if !alive {
		return refuse("Process %d is not running.", pid)
	}
	if ticks != start {
		return refuse("Process %d is no longer the same program, so it was not stopped.", pid)
	}
	if why := protectedPID(h, pid); why != "" {
		return refuse("Process %d is %s. Rootmote will not stop it.", pid, why)
	}
	gone := func() bool {
		t, a := h.StartTime(pid)
		return !a || t != start
	}
	wait := func(total time.Duration) bool {
		for el := time.Duration(0); el < total; el += 250 * time.Millisecond {
			if gone() {
				return true
			}
			h.Sleep(ctx, 250*time.Millisecond)
			if ctx.Err() != nil {
				return gone()
			}
		}
		return gone()
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil && !gone() {
		return fmt.Errorf("Could not stop process %d: %v", pid, err)
	}
	if wait(10 * time.Second) {
		fmt.Fprintf(out, "Process %d stopped.\n", pid)
		return nil
	}
	if t, a := h.StartTime(pid); a && t == start {
		if err := proc.Signal(syscall.SIGKILL); err != nil && !gone() {
			return fmt.Errorf("Could not force process %d to end: %v", pid, err)
		}
	}
	if wait(3 * time.Second) {
		fmt.Fprintf(out, "Process %d was forced to end.\n", pid)
		return nil
	}
	return fmt.Errorf("Process %d is still running after it was forced to end.", pid)
}

// ---- firewall ----------------------------------------------------------------

func firewallChange(allow bool) func(context.Context, Host, []string, io.Writer) error {
	return func(ctx context.Context, h Host, args []string, out io.Writer) error {
		if err := wantArgs(args, 2); err != nil {
			return err
		}
		port, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil || !digitRe.MatchString(args[0]) {
			return refuse("The port must be between 1 and 65535.")
		}
		if err := ValidatePort(port); err != nil {
			return err
		}
		if err := ValidateProto(args[1]); err != nil {
			return err
		}
		rule := firewall.Rule{Action: firewall.ActionAllow, Protocol: firewall.Protocol(args[1]), Port: int(port)}
		m := h.Firewall()
		if m == nil {
			return refuse("No firewall (ufw or firewalld) is available on this server.")
		}
		if allow {
			err = m.RuleAdd(ctx, rule)
		} else {
			err = m.RuleRemove(ctx, rule)
		}
		if err != nil {
			return mapFirewallErr(err)
		}
		if allow {
			fmt.Fprintf(out, "Port %d/%s is now open.\n", port, args[1])
		} else {
			fmt.Fprintf(out, "Port %d/%s is now closed.\n", port, args[1])
		}
		return nil
	}
}

func mapFirewallErr(err error) error {
	switch {
	case errors.Is(err, firewall.ErrAntiLockout):
		return refuse("That port is used for SSH. Rootmote will not close it, because you could lose access to this server.")
	case errors.Is(err, firewall.ErrReadOnly):
		return refuse("No firewall (ufw or firewalld) is active on this server.")
	case errors.Is(err, firewall.ErrUnsupportedAction):
		return refuse("That firewall change is not allowed.")
	}
	return err
}

func firewallRules(ctx context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	m := h.Firewall()
	if m == nil {
		return refuse("No firewall (ufw or firewalld) is available on this server.")
	}
	st, err := m.Status(ctx)
	if err != nil {
		return err
	}
	if !st.Available {
		return refuse("No firewall (ufw or firewalld) is active on this server.")
	}
	rules := []firewallRule{}
	for _, r := range st.Rules {
		if r.Action != firewall.ActionAllow {
			continue
		}
		switch r.Protocol {
		case firewall.ProtoTCP, firewall.ProtoUDP:
			rules = append(rules, firewallRule{Port: r.Port, Proto: string(r.Protocol)})
		default:
			rules = append(rules, firewallRule{Port: r.Port, Proto: "tcp"}, firewallRule{Port: r.Port, Proto: "udp"})
		}
	}
	return json.NewEncoder(out).Encode(rules)
}
