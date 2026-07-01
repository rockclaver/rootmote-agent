package firewall

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// runner is the narrow interface used by the real backends so tests can
// swap exec.CommandContext for a fake.
type runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// UFWBackend wraps the `ufw` CLI. When Sudo is true, commands are run via
// `sudo -n ufw …` so the unprivileged agent user can call into a binary
// that requires root. The packaged install ships a /etc/sudoers.d
// fragment granting passwordless NOPASSWD access to ufw and firewall-cmd.
type UFWBackend struct {
	Run     runner
	LookBin func(string) (string, error)
	Sudo    bool
}

// NewUFWBackend returns a ufw Backend using exec.CommandContext. Sudo is
// auto-enabled when the agent is not running as root, matching the
// packaged install where the agent runs as `claver`.
func NewUFWBackend() *UFWBackend {
	return &UFWBackend{Run: defaultRunner, LookBin: exec.LookPath, Sudo: needsSudo()}
}

func (u *UFWBackend) Kind() BackendKind { return BackendUFW }

func (u *UFWBackend) run(ctx context.Context, args ...string) ([]byte, error) {
	run := u.Run
	if run == nil {
		run = defaultRunner
	}
	name := "ufw"
	if u.Sudo {
		name = "sudo"
		args = append([]string{"-n", "ufw"}, args...)
	}
	return run(ctx, name, args...)
}

func (u *UFWBackend) Available(ctx context.Context) error {
	lookup := u.LookBin
	if lookup == nil {
		lookup = exec.LookPath
	}
	if _, err := lookup("ufw"); err != nil {
		return fmt.Errorf("ufw not installed: %w", err)
	}
	if u.Sudo {
		if _, err := lookup("sudo"); err != nil {
			return fmt.Errorf("sudo required to manage ufw as non-root: %w", err)
		}
	}
	if _, err := u.run(ctx, "status"); err != nil {
		return fmt.Errorf("ufw status: %w", err)
	}
	return nil
}

func (u *UFWBackend) Rules(ctx context.Context) ([]Rule, error) {
	out, err := u.run(ctx, "status", "numbered")
	if err != nil {
		return nil, fmt.Errorf("ufw status: %w", err)
	}
	return parseUFWRules(string(out)), nil
}

func (u *UFWBackend) Add(ctx context.Context, r Rule) error {
	args := []string{string(r.Action), strconv.Itoa(r.Port)}
	if r.Protocol == ProtoTCP || r.Protocol == ProtoUDP {
		args[1] = fmt.Sprintf("%d/%s", r.Port, r.Protocol)
	}
	if _, err := u.run(ctx, args...); err != nil {
		return fmt.Errorf("ufw add: %w", err)
	}
	return nil
}

func (u *UFWBackend) Remove(ctx context.Context, r Rule) error {
	port := strconv.Itoa(r.Port)
	if r.Protocol == ProtoTCP || r.Protocol == ProtoUDP {
		port = fmt.Sprintf("%d/%s", r.Port, r.Protocol)
	}
	if _, err := u.run(ctx, "delete", string(r.Action), port); err != nil {
		return fmt.Errorf("ufw delete: %w", err)
	}
	return nil
}

// parseUFWRules parses output of `ufw status numbered`. The line format is
// roughly: `[ 1] 22/tcp                     ALLOW IN    Anywhere`.
func parseUFWRules(raw string) []Rule {
	var rules []Rule
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Status:") || strings.HasPrefix(line, "To") || strings.HasPrefix(line, "--") {
			continue
		}
		// Strip leading "[ N]".
		if i := strings.Index(line, "]"); strings.HasPrefix(line, "[") && i > 0 {
			line = strings.TrimSpace(line[i+1:])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		port, proto, ok := splitPortProto(fields[0])
		if !ok {
			continue
		}
		var action Action
		switch strings.ToUpper(fields[1]) {
		case "ALLOW":
			action = ActionAllow
		case "DENY", "REJECT":
			action = ActionDeny
		default:
			continue
		}
		rules = append(rules, Rule{Action: action, Protocol: proto, Port: port})
	}
	return rules
}

func splitPortProto(tok string) (int, Protocol, bool) {
	proto := ProtoAny
	if i := strings.IndexByte(tok, '/'); i > 0 {
		switch strings.ToLower(tok[i+1:]) {
		case "tcp":
			proto = ProtoTCP
		case "udp":
			proto = ProtoUDP
		}
		tok = tok[:i]
	}
	port, err := strconv.Atoi(tok)
	if err != nil || port <= 0 {
		return 0, "", false
	}
	return port, proto, true
}

// FirewalldBackend wraps the `firewall-cmd` CLI. When Sudo is true,
// commands are run via `sudo -n firewall-cmd …`.
type FirewalldBackend struct {
	Run     runner
	LookBin func(string) (string, error)
	Sudo    bool
	// Zone is the firewalld zone the agent operates in; defaults to "public".
	Zone string
}

// NewFirewalldBackend returns a firewalld Backend using
// exec.CommandContext. Sudo is auto-enabled when the agent is not
// running as root.
func NewFirewalldBackend() *FirewalldBackend {
	return &FirewalldBackend{Run: defaultRunner, LookBin: exec.LookPath, Sudo: needsSudo()}
}

func (f *FirewalldBackend) Kind() BackendKind { return BackendFirewalld }

func (f *FirewalldBackend) zone() string {
	if f.Zone == "" {
		return "public"
	}
	return f.Zone
}

func (f *FirewalldBackend) run(ctx context.Context, args ...string) ([]byte, error) {
	run := f.Run
	if run == nil {
		run = defaultRunner
	}
	name := "firewall-cmd"
	if f.Sudo {
		name = "sudo"
		args = append([]string{"-n", "firewall-cmd"}, args...)
	}
	return run(ctx, name, args...)
}

func (f *FirewalldBackend) Available(ctx context.Context) error {
	lookup := f.LookBin
	if lookup == nil {
		lookup = exec.LookPath
	}
	if _, err := lookup("firewall-cmd"); err != nil {
		return fmt.Errorf("firewall-cmd not installed: %w", err)
	}
	if f.Sudo {
		if _, err := lookup("sudo"); err != nil {
			return fmt.Errorf("sudo required to manage firewalld as non-root: %w", err)
		}
	}
	out, err := f.run(ctx, "--state")
	if err != nil {
		return fmt.Errorf("firewalld not running: %w", err)
	}
	if !strings.Contains(string(out), "running") {
		return errors.New("firewalld not running")
	}
	return nil
}

func (f *FirewalldBackend) Rules(ctx context.Context) ([]Rule, error) {
	out, err := f.run(ctx, "--zone="+f.zone(), "--list-ports")
	if err != nil {
		return nil, fmt.Errorf("firewalld list-ports: %w", err)
	}
	var rules []Rule
	for _, tok := range strings.Fields(string(out)) {
		port, proto, ok := splitPortProto(tok)
		if !ok {
			continue
		}
		rules = append(rules, Rule{Action: ActionAllow, Protocol: proto, Port: port})
	}
	return rules, nil
}

func (f *FirewalldBackend) Add(ctx context.Context, r Rule) error {
	if r.Action != ActionAllow {
		// firewalld models exposed ports as allow-list entries; deny is
		// implicit. Reject explicit deny rules to keep the model honest.
		return fmt.Errorf("firewalld: deny rules are implicit; use allow rules only")
	}
	proto := strings.ToLower(string(r.Protocol))
	if proto == string(ProtoAny) {
		proto = "tcp"
	}
	port := fmt.Sprintf("%d/%s", r.Port, proto)
	if _, err := f.run(ctx, "--zone="+f.zone(), "--add-port="+port, "--permanent"); err != nil {
		return fmt.Errorf("firewalld add-port: %w", err)
	}
	_, _ = f.run(ctx, "--reload")
	return nil
}

func (f *FirewalldBackend) Remove(ctx context.Context, r Rule) error {
	proto := strings.ToLower(string(r.Protocol))
	if proto == string(ProtoAny) {
		proto = "tcp"
	}
	port := fmt.Sprintf("%d/%s", r.Port, proto)
	if _, err := f.run(ctx, "--zone="+f.zone(), "--remove-port="+port, "--permanent"); err != nil {
		return fmt.Errorf("firewalld remove-port: %w", err)
	}
	_, _ = f.run(ctx, "--reload")
	return nil
}

// needsSudo returns true when the current process is not running as
// root. The packaged install runs the agent as `claver`, and ufw /
// firewall-cmd require root, so we wrap with `sudo -n` via a
// /etc/sudoers.d fragment shipped by the installer.
func needsSudo() bool {
	return os.Geteuid() != 0
}

// SSCommandReader is a SocketReader backed by `ss -tulnp`.
type SSCommandReader struct {
	Run runner
}

// NewSSCommandReader returns a SocketReader using exec.CommandContext.
func NewSSCommandReader() *SSCommandReader {
	return &SSCommandReader{Run: defaultRunner}
}

func (s *SSCommandReader) Listening(ctx context.Context) ([]Socket, error) {
	run := s.Run
	if run == nil {
		run = defaultRunner
	}
	out, err := run(ctx, "ss", "-tulnpH")
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	return parseSS(string(out)), nil
}

// parseSS parses `ss -tulnpH` output. Each line is:
// Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
// We only need protocol (Netid), Local Address:Port, and the optional
// process descriptor like users:(("sshd",pid=123,fd=3)).
func parseSS(raw string) []Socket {
	var out []Socket
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := Protocol(strings.ToLower(fields[0]))
		if proto != ProtoTCP && proto != ProtoUDP {
			continue
		}
		addr, port, ok := splitAddrPort(fields[4])
		if !ok {
			continue
		}
		process, pid := parseSSProcess(strings.Join(fields[6:], " "))
		out = append(out, Socket{Protocol: proto, Address: addr, Port: port, Process: process, PID: pid})
	}
	return out
}

func splitAddrPort(tok string) (string, int, bool) {
	i := strings.LastIndex(tok, ":")
	if i < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(tok[i+1:])
	if err != nil || port <= 0 {
		return "", 0, false
	}
	return tok[:i], port, true
}

func parseSSProcess(tok string) (string, int) {
	// Format: users:(("sshd",pid=123,fd=3),...)
	i := strings.Index(tok, `(("`)
	if i < 0 {
		return "", 0
	}
	rest := tok[i+3:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", 0
	}
	name := rest[:j]
	pid := 0
	if k := strings.Index(rest, "pid="); k >= 0 {
		end := k + 4
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		pid, _ = strconv.Atoi(rest[k+4 : end])
	}
	return name, pid
}

// LsofSocketReader is the macOS/BSD SocketReader backed by lsof. Darwin does
// not ship Linux `ss`, but lsof is present on stock macOS and reports owning
// PIDs for listening sockets.
type LsofSocketReader struct {
	Run runner
}

func NewLsofSocketReader() *LsofSocketReader {
	return &LsofSocketReader{Run: defaultRunner}
}

func (l *LsofSocketReader) Listening(ctx context.Context) ([]Socket, error) {
	run := l.Run
	if run == nil {
		run = defaultRunner
	}
	tcpOut, tcpErr := run(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	udpOut, udpErr := run(ctx, "lsof", "-nP", "-iUDP")
	if tcpErr != nil && udpErr != nil {
		return nil, fmt.Errorf("lsof: tcp: %v; udp: %v", tcpErr, udpErr)
	}
	var out []Socket
	if tcpErr == nil {
		out = append(out, parseLsof(string(tcpOut), ProtoTCP)...)
	}
	if udpErr == nil {
		out = append(out, parseLsof(string(udpOut), ProtoUDP)...)
	}
	return dedupeSockets(out), nil
}

var lsofPortRE = regexp.MustCompile(`:(\d+)(?:\s|\(|$)`)

func parseLsof(raw string, defaultProto Protocol) []Socket {
	var out []Socket
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "COMMAND ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		nameIdx := -1
		proto := defaultProto
		for i, f := range fields {
			switch f {
			case "TCP":
				nameIdx = i + 1
				proto = ProtoTCP
			case "UDP":
				nameIdx = i + 1
				proto = ProtoUDP
			}
			if nameIdx >= 0 {
				break
			}
		}
		if nameIdx < 0 || nameIdx >= len(fields) {
			continue
		}
		name := strings.Join(fields[nameIdx:], " ")
		m := lsofPortRE.FindStringSubmatch(name)
		if len(m) < 2 {
			continue
		}
		port, err := strconv.Atoi(m[1])
		if err != nil || port <= 0 {
			continue
		}
		address := "*"
		if i := strings.LastIndex(name, ":"+m[1]); i > 0 {
			address = strings.TrimSpace(name[:i])
			address = strings.TrimPrefix(address, "TCP ")
			address = strings.TrimPrefix(address, "UDP ")
			if address == "" {
				address = "*"
			}
		}
		out = append(out, Socket{Protocol: proto, Address: address, Port: port, Process: fields[0], PID: pid})
	}
	return out
}

func dedupeSockets(in []Socket) []Socket {
	seen := map[string]bool{}
	var out []Socket
	for _, s := range in {
		key := fmt.Sprintf("%s/%s/%d/%s/%d", s.Protocol, s.Address, s.Port, s.Process, s.PID)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// SSHFromSockets resolves SSH ports by inspecting listening sockets whose
// owning process name is "sshd". Falls back to 22 only if the reader
// returned no sockets at all.
type SSHFromSockets struct {
	Reader SocketReader
}

func (s SSHFromSockets) SSHPorts(ctx context.Context) []int {
	if s.Reader == nil {
		return []int{22}
	}
	sockets, err := s.Reader.Listening(ctx)
	if err != nil || len(sockets) == 0 {
		return []int{22}
	}
	seen := map[int]bool{}
	var out []int
	for _, sock := range sockets {
		if sock.Process == "sshd" {
			if !seen[sock.Port] {
				seen[sock.Port] = true
				out = append(out, sock.Port)
			}
		}
	}
	if len(out) == 0 {
		return []int{22}
	}
	return out
}
