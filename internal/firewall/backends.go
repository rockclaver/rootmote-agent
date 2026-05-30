package firewall

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// runner is the narrow interface used by the real backends so tests can
// swap exec.CommandContext for a fake.
type runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// UFWBackend wraps the `ufw` CLI.
type UFWBackend struct {
	Run     runner
	LookBin func(string) (string, error)
}

// NewUFWBackend returns a ufw Backend using exec.CommandContext.
func NewUFWBackend() *UFWBackend {
	return &UFWBackend{Run: defaultRunner, LookBin: exec.LookPath}
}

func (u *UFWBackend) Kind() BackendKind { return BackendUFW }

func (u *UFWBackend) Available(ctx context.Context) error {
	lookup := u.LookBin
	if lookup == nil {
		lookup = exec.LookPath
	}
	if _, err := lookup("ufw"); err != nil {
		return fmt.Errorf("ufw not installed: %w", err)
	}
	run := u.Run
	if run == nil {
		run = defaultRunner
	}
	if _, err := run(ctx, "ufw", "status"); err != nil {
		return fmt.Errorf("ufw status: %w", err)
	}
	return nil
}

func (u *UFWBackend) Rules(ctx context.Context) ([]Rule, error) {
	run := u.Run
	if run == nil {
		run = defaultRunner
	}
	out, err := run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil, fmt.Errorf("ufw status: %w", err)
	}
	return parseUFWRules(string(out)), nil
}

func (u *UFWBackend) Add(ctx context.Context, r Rule) error {
	run := u.Run
	if run == nil {
		run = defaultRunner
	}
	args := []string{string(r.Action), strconv.Itoa(r.Port)}
	if r.Protocol == ProtoTCP || r.Protocol == ProtoUDP {
		args[1] = fmt.Sprintf("%d/%s", r.Port, r.Protocol)
	}
	if _, err := run(ctx, "ufw", args...); err != nil {
		return fmt.Errorf("ufw add: %w", err)
	}
	return nil
}

func (u *UFWBackend) Remove(ctx context.Context, r Rule) error {
	run := u.Run
	if run == nil {
		run = defaultRunner
	}
	port := strconv.Itoa(r.Port)
	if r.Protocol == ProtoTCP || r.Protocol == ProtoUDP {
		port = fmt.Sprintf("%d/%s", r.Port, r.Protocol)
	}
	if _, err := run(ctx, "ufw", "delete", string(r.Action), port); err != nil {
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

// FirewalldBackend wraps the `firewall-cmd` CLI.
type FirewalldBackend struct {
	Run     runner
	LookBin func(string) (string, error)
	// Zone is the firewalld zone the agent operates in; defaults to "public".
	Zone string
}

func NewFirewalldBackend() *FirewalldBackend {
	return &FirewalldBackend{Run: defaultRunner, LookBin: exec.LookPath}
}

func (f *FirewalldBackend) Kind() BackendKind { return BackendFirewalld }

func (f *FirewalldBackend) zone() string {
	if f.Zone == "" {
		return "public"
	}
	return f.Zone
}

func (f *FirewalldBackend) Available(ctx context.Context) error {
	lookup := f.LookBin
	if lookup == nil {
		lookup = exec.LookPath
	}
	if _, err := lookup("firewall-cmd"); err != nil {
		return fmt.Errorf("firewall-cmd not installed: %w", err)
	}
	run := f.Run
	if run == nil {
		run = defaultRunner
	}
	out, err := run(ctx, "firewall-cmd", "--state")
	if err != nil {
		return fmt.Errorf("firewalld not running: %w", err)
	}
	if !strings.Contains(string(out), "running") {
		return errors.New("firewalld not running")
	}
	return nil
}

func (f *FirewalldBackend) Rules(ctx context.Context) ([]Rule, error) {
	run := f.Run
	if run == nil {
		run = defaultRunner
	}
	out, err := run(ctx, "firewall-cmd", "--zone="+f.zone(), "--list-ports")
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
	run := f.Run
	if run == nil {
		run = defaultRunner
	}
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
	if _, err := run(ctx, "firewall-cmd", "--zone="+f.zone(), "--add-port="+port, "--permanent"); err != nil {
		return fmt.Errorf("firewalld add-port: %w", err)
	}
	_, _ = run(ctx, "firewall-cmd", "--reload")
	return nil
}

func (f *FirewalldBackend) Remove(ctx context.Context, r Rule) error {
	run := f.Run
	if run == nil {
		run = defaultRunner
	}
	proto := strings.ToLower(string(r.Protocol))
	if proto == string(ProtoAny) {
		proto = "tcp"
	}
	port := fmt.Sprintf("%d/%s", r.Port, proto)
	if _, err := run(ctx, "firewall-cmd", "--zone="+f.zone(), "--remove-port="+port, "--permanent"); err != nil {
		return fmt.Errorf("firewalld remove-port: %w", err)
	}
	_, _ = run(ctx, "firewall-cmd", "--reload")
	return nil
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
