// Package security implements the Server Security Audit module. It performs
// defensive host checks only: exposed risky services, SSH hardening posture,
// suspicious process indicators, basic logging/brute-force controls, and
// account hygiene. Mutations are deliberately narrow and typed.
package security

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rockclaver/claver-agent/internal/firewall"
	agentprocess "github.com/rockclaver/claver-agent/internal/process"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FixKind string

const (
	FixClosePort    FixKind = "close_port"
	FixKillProcess  FixKind = "kill_process"
	FixEnableAuditd FixKind = "enable_auditd"
	// FixRunScript executes an AI-authored POSIX sh script as root. It exists
	// for findings with no narrow typed fix (e.g. correcting ownership or
	// permissions on /etc/shadow) where the alternative is refusing to
	// propose any remediation at all. Safety is enforced procedurally rather
	// than by restricting the command surface: the script is bound
	// byte-for-byte into the confirmation token's action hash (see
	// securityFixTokenBinding / tokenBindingForKind), so approving one
	// script can never execute a different one, and runbook.materialise
	// forces Risk=high whenever a run_script step is present so the mobile
	// client requires a fresh biometric per step instead of one-tap
	// "approve all".
	FixRunScript FixKind = "run_script"
)

// MaxScriptBytes caps an AI-proposed run_script payload. Generous enough for
// any realistic single-finding remediation while keeping the audit log and
// mobile approval card readable.
const MaxScriptBytes = 16 * 1024

type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation"`
	Fix            *Fix     `json:"fix,omitempty"`
}

type Fix struct {
	Kind           FixKind `json:"kind"`
	Label          string  `json:"label"`
	Target         string  `json:"target"`
	Port           int     `json:"port,omitempty"`
	Protocol       string  `json:"protocol,omitempty"`
	PID            int     `json:"pid,omitempty"`
	StartTimeTicks uint64  `json:"start_time_ticks,omitempty"`
	Signal         string  `json:"signal,omitempty"`
	Destructive    bool    `json:"destructive"`
}

type Audit struct {
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Finding `json:"findings"`
	Summary     Summary   `json:"summary"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
	Fixable  int `json:"fixable"`
}

type FixRequest struct {
	Kind           FixKind
	Port           int
	Protocol       string
	PID            int
	StartTimeTicks uint64
	Signal         string
	Script         string
}

type FixResult struct {
	Kind    FixKind `json:"kind"`
	Target  string  `json:"target"`
	Summary string  `json:"summary"`
}

type Firewall interface {
	Status(context.Context) (firewall.Status, error)
	RuleAdd(context.Context, firewall.Rule) error
	RuleRemove(context.Context, firewall.Rule) error
}

type Processes interface {
	List(context.Context, string, int) ([]agentprocess.Process, error)
	Kill(context.Context, int, uint64, string) error
}

type Config struct {
	Firewall  Firewall
	Processes Processes
	ReadFile  func(string) ([]byte, error)
	Glob      func(string) ([]string, error)
	Run       func(context.Context, string, ...string) ([]byte, error)
	Stat      func(string) (fs.FileMode, error)
	Now       func() time.Time
}

type Manager struct {
	cfg Config
}

func New(cfg Config) (*Manager, error) {
	if cfg.ReadFile == nil {
		cfg.ReadFile = os.ReadFile
	}
	if cfg.Glob == nil {
		cfg.Glob = filepath.Glob
	}
	if cfg.Run == nil {
		cfg.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	if cfg.Stat == nil {
		cfg.Stat = func(path string) (fs.FileMode, error) {
			fi, err := os.Stat(path)
			if err != nil {
				return 0, err
			}
			return fi.Mode(), nil
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{cfg: cfg}, nil
}

func (m *Manager) Audit(ctx context.Context) (Audit, error) {
	var findings []Finding

	var fwStatus *firewall.Status
	if m.cfg.Firewall != nil {
		st, err := m.cfg.Firewall.Status(ctx)
		if err != nil {
			findings = append(findings, Finding{
				ID:             "firewall_status_unavailable",
				Severity:       SeverityMedium,
				Category:       "firewall",
				Title:          "Firewall status could not be read",
				Summary:        "The agent could not inspect firewall rules or listening sockets.",
				Evidence:       []string{err.Error()},
				Recommendation: "Fix firewall inspection permissions so exposed services can be judged against active rules.",
			})
		} else {
			fwStatus = &st
			findings = append(findings, firewallFindings(st)...)
		}
	}

	findings = append(findings, m.sshFindings(ctx, fwStatus)...)
	findings = append(findings, m.processFindings(ctx)...)
	findings = append(findings, m.controlFindings(ctx, fwStatus)...)
	findings = append(findings, m.accountFindings()...)
	findings = append(findings, m.dockerFindings()...)
	findings = append(findings, m.filePermissionFindings()...)
	findings = append(findings, m.ldPreloadFindings()...)
	findings = append(findings, m.shadowFindings()...)
	findings = append(findings, m.cronFindings()...)
	findings = append(findings, m.sysctlFindings()...)
	findings = append(findings, m.patchAutomationFindings(ctx)...)
	findings = append(findings, m.macFindings(ctx)...)

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	audit := Audit{GeneratedAt: m.cfg.Now(), Findings: findings}
	for _, f := range findings {
		audit.Summary.Total++
		if f.Fix != nil {
			audit.Summary.Fixable++
		}
		switch f.Severity {
		case SeverityCritical:
			audit.Summary.Critical++
		case SeverityHigh:
			audit.Summary.High++
		case SeverityMedium:
			audit.Summary.Medium++
		case SeverityLow:
			audit.Summary.Low++
		default:
			audit.Summary.Info++
		}
	}
	return audit, nil
}

func (m *Manager) Fix(ctx context.Context, req FixRequest) (FixResult, error) {
	switch req.Kind {
	case FixClosePort:
		if m.cfg.Firewall == nil {
			return FixResult{}, errors.New("security: firewall subsystem not configured")
		}
		proto := firewall.Protocol(strings.ToLower(req.Protocol))
		if proto == "" {
			proto = firewall.ProtoTCP
		}
		st, err := m.cfg.Firewall.Status(ctx)
		if err != nil {
			return FixResult{}, err
		}
		rule := firewall.Rule{Action: firewall.ActionDeny, Protocol: proto, Port: req.Port, Comment: "Claver security audit"}
		if st.Backend == firewall.BackendFirewalld {
			rule.Action = firewall.ActionAllow
			err = m.cfg.Firewall.RuleRemove(ctx, rule)
		} else {
			err = m.cfg.Firewall.RuleAdd(ctx, rule)
		}
		if err != nil {
			return FixResult{}, err
		}
		target := fmt.Sprintf("%s/%d", proto, req.Port)
		return FixResult{Kind: req.Kind, Target: target, Summary: "closed firewall access for " + target}, nil
	case FixKillProcess:
		if m.cfg.Processes == nil {
			return FixResult{}, errors.New("security: process subsystem not configured")
		}
		signal := req.Signal
		if signal == "" {
			signal = agentprocess.SignalTerm
		}
		if err := m.cfg.Processes.Kill(ctx, req.PID, req.StartTimeTicks, signal); err != nil {
			return FixResult{}, err
		}
		target := strconv.Itoa(req.PID)
		return FixResult{Kind: req.Kind, Target: target, Summary: "sent " + signal + " to suspicious process " + target}, nil
	case FixEnableAuditd:
		return m.enableAuditd(ctx)
	case FixRunScript:
		return m.runScript(ctx, req.Script)
	default:
		return FixResult{}, fmt.Errorf("security: unsupported fix %q", req.Kind)
	}
}

// runScript executes an AI-proposed remediation script as root via the same
// nsenter+sudo escalation path (and sudoers.d allowlist) every other
// privileged mutation in this package uses. The operator has already
// biometrically approved this exact script text (the confirmation token's
// action hash is bound to it) before this is ever reached.
func (m *Manager) runScript(ctx context.Context, script string) (FixResult, error) {
	script = strings.TrimSpace(script)
	if script == "" {
		return FixResult{}, errors.New("security: script is empty")
	}
	if len(script) > MaxScriptBytes {
		return FixResult{}, fmt.Errorf("security: script exceeds %d bytes", MaxScriptBytes)
	}
	out, err := m.runPrivileged(ctx, "sh", "-c", script)
	if err != nil {
		return FixResult{}, fmt.Errorf("security: run script: %w: %s", err, strings.TrimSpace(string(out)))
	}
	summary := strings.TrimSpace(string(out))
	if summary == "" {
		summary = "script completed with no output"
	}
	return FixResult{Kind: FixRunScript, Target: "script", Summary: truncateOutput(summary, 500)}, nil
}

func truncateOutput(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}

func (m *Manager) enableAuditd(ctx context.Context) (FixResult, error) {
	if m.systemdActive(ctx, "auditd") {
		return FixResult{Kind: FixEnableAuditd, Target: "auditd", Summary: "auditd is already active"}, nil
	}
	if err := m.installAuditdPackage(ctx); err != nil {
		return FixResult{}, err
	}
	if _, err := m.runPrivileged(ctx, "systemctl", "enable", "--now", "auditd"); err != nil {
		return FixResult{}, fmt.Errorf("security: enable auditd: %w", err)
	}
	return FixResult{Kind: FixEnableAuditd, Target: "auditd", Summary: "installed and enabled auditd"}, nil
}

func (m *Manager) installAuditdPackage(ctx context.Context) error {
	if _, err := m.cfg.ReadFile("/etc/debian_version"); err == nil {
		if _, err := m.runPrivileged(ctx, "apt-get", "install", "-y", "auditd"); err != nil {
			return fmt.Errorf("security: install auditd with apt-get: %w", err)
		}
		return nil
	}
	if _, err := m.cfg.ReadFile("/etc/redhat-release"); err == nil {
		if _, err := m.runPrivileged(ctx, "dnf", "install", "-y", "audit"); err == nil {
			return nil
		}
		if _, err := m.runPrivileged(ctx, "yum", "install", "-y", "audit"); err != nil {
			return fmt.Errorf("security: install audit with yum: %w", err)
		}
		return nil
	}
	if _, err := m.cfg.ReadFile("/etc/alpine-release"); err == nil {
		if _, err := m.runPrivileged(ctx, "apk", "add", "audit"); err != nil {
			return fmt.Errorf("security: install audit with apk: %w", err)
		}
		return nil
	}
	return errors.New("security: cannot install auditd automatically on this OS family")
}

func (m *Manager) runPrivileged(ctx context.Context, name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return m.cfg.Run(ctx, name, args...)
	}
	nsenterPath := privilegedCommandPath("nsenter")
	commandPath := privilegedCommandPath(name)
	sudoArgs := append([]string{"-n", nsenterPath, "--mount=/proc/1/ns/mnt", "--", commandPath}, args...)
	return m.cfg.Run(ctx, "sudo", sudoArgs...)
}

func privilegedCommandPath(name string) string {
	switch name {
	case "apt-get":
		return "/usr/bin/apt-get"
	case "dnf":
		return "/usr/bin/dnf"
	case "yum":
		return "/usr/bin/yum"
	case "apk":
		return "/sbin/apk"
	case "systemctl":
		return "/usr/bin/systemctl"
	case "nsenter":
		return "/usr/bin/nsenter"
	case "sh":
		return "/bin/sh"
	default:
		return name
	}
}

type riskyPort struct {
	name           string
	severity       Severity
	recommendation string
}

var riskyPorts = map[int]riskyPort{
	21:    {"FTP", SeverityHigh, "Use SFTP/SSH or restrict FTP to a private network."},
	23:    {"Telnet", SeverityCritical, "Disable Telnet and use SSH with key-based authentication."},
	69:    {"TFTP", SeverityHigh, "TFTP has no authentication; restrict it to trusted provisioning networks or disable it."},
	111:   {"rpcbind", SeverityHigh, "Restrict rpcbind/NFS helper services to private networks."},
	135:   {"MS RPC", SeverityHigh, "Do not expose RPC services to the public internet."},
	137:   {"NetBIOS", SeverityHigh, "Keep NetBIOS reachable only on trusted private networks."},
	138:   {"NetBIOS", SeverityHigh, "Keep NetBIOS reachable only on trusted private networks."},
	139:   {"SMB/NetBIOS", SeverityHigh, "Keep SMB reachable only on trusted private networks or VPN."},
	445:   {"SMB", SeverityHigh, "Do not expose SMB to the public internet."},
	512:   {"rexec", SeverityCritical, "rexec sends credentials and commands in cleartext; disable it in favor of SSH."},
	513:   {"rlogin", SeverityCritical, "rlogin trusts source IP/host and has no encryption; disable it in favor of SSH."},
	514:   {"rsh", SeverityCritical, "rsh has no authentication or encryption; disable it in favor of SSH."},
	1099:  {"Java RMI/JMX registry", SeverityCritical, "Unauthenticated RMI/JMX allows remote deserialization code execution; bind to localhost or require authentication."},
	1433:  {"Microsoft SQL Server", SeverityHigh, "Bind databases to localhost/private networks and require VPN access."},
	1434:  {"Microsoft SQL Server Browser", SeverityMedium, "Restrict the SQL Server Browser (UDP) to private networks."},
	1521:  {"Oracle database", SeverityHigh, "Bind databases to localhost/private networks and require VPN access."},
	1883:  {"MQTT broker", SeverityHigh, "Require authentication and TLS on the MQTT broker or restrict it to a private network."},
	2049:  {"NFS", SeverityHigh, "Restrict NFS to trusted private networks."},
	2181:  {"ZooKeeper", SeverityHigh, "ZooKeeper has no authentication by default; restrict it to the cluster's private network."},
	2375:  {"Docker API without TLS", SeverityCritical, "Disable unauthenticated Docker TCP or block the port immediately."},
	2376:  {"Docker API", SeverityHigh, "Expose Docker API only through authenticated private access."},
	2379:  {"etcd client", SeverityCritical, "Unauthenticated etcd exposes the full cluster key/value store, including secrets; restrict it to the cluster network and enable client auth."},
	2380:  {"etcd peer", SeverityHigh, "Restrict etcd peer traffic to the cluster's private network."},
	3128:  {"Squid proxy", SeverityHigh, "An open proxy can be abused for anonymized attacks; require authentication or restrict source IPs."},
	3306:  {"MySQL/MariaDB", SeverityHigh, "Bind databases to localhost/private networks and require VPN access."},
	3389:  {"RDP", SeverityHigh, "Put RDP behind VPN or a zero-trust access layer."},
	5432:  {"PostgreSQL", SeverityHigh, "Bind databases to localhost/private networks and require VPN access."},
	5601:  {"Kibana", SeverityHigh, "Put Kibana behind authentication and a private network or VPN."},
	5672:  {"RabbitMQ (AMQP)", SeverityHigh, "Restrict the AMQP port to trusted networks and require authentication."},
	5900:  {"VNC", SeverityHigh, "Do not expose VNC directly; require VPN or SSH tunneling."},
	5901:  {"VNC", SeverityHigh, "Do not expose VNC directly; require VPN or SSH tunneling."},
	6000:  {"X11", SeverityHigh, "Unauthenticated X11 exposes keystrokes and screen contents; tunnel X11 over SSH instead of exposing the display server port."},
	5984:  {"CouchDB", SeverityCritical, "Older CouchDB releases allow unauthenticated admin-party access and have known remote code execution CVEs; patch and require authentication."},
	6379:  {"Redis", SeverityCritical, "Bind Redis to localhost/private networks and require authentication."},
	6443:  {"Kubernetes API", SeverityHigh, "Restrict Kubernetes API to trusted management networks."},
	7000:  {"Cassandra (inter-node)", SeverityHigh, "Restrict Cassandra inter-node traffic to the cluster's private network."},
	7199:  {"Cassandra JMX", SeverityHigh, "Cassandra JMX has no authentication by default; restrict it to the cluster's private network."},
	8086:  {"InfluxDB", SeverityHigh, "Bind InfluxDB privately and enforce authentication."},
	8500:  {"Consul", SeverityCritical, "Unauthenticated Consul exposes service discovery and the KV store; restrict it to the cluster network and enable ACLs."},
	8983:  {"Solr", SeverityCritical, "Solr has a history of unauthenticated remote code execution; patch it and restrict it to a private network."},
	9042:  {"Cassandra (CQL)", SeverityHigh, "Bind Cassandra privately and enforce authentication."},
	9092:  {"Kafka", SeverityHigh, "Restrict the Kafka broker to trusted networks and require SASL/TLS."},
	9100:  {"Prometheus node_exporter", SeverityMedium, "Host metrics can leak sensitive operational detail; restrict node_exporter to the monitoring network."},
	9200:  {"Elasticsearch", SeverityHigh, "Bind Elasticsearch privately and enforce authentication."},
	9300:  {"Elasticsearch transport", SeverityHigh, "Do not expose Elasticsearch transport ports publicly."},
	11211: {"Memcached", SeverityCritical, "Bind Memcached to localhost/private networks; never expose it publicly."},
	15672: {"RabbitMQ management", SeverityHigh, "Put the RabbitMQ management UI behind authentication and a private network or VPN."},
	27017: {"MongoDB", SeverityHigh, "Bind MongoDB privately and enforce authentication."},
	27018: {"MongoDB (shard)", SeverityHigh, "Bind MongoDB privately and enforce authentication."},
	27019: {"MongoDB (config server)", SeverityHigh, "Bind MongoDB privately and enforce authentication."},
}

func firewallFindings(st firewall.Status) []Finding {
	var findings []Finding
	if !st.Available {
		findings = append(findings, Finding{
			ID:             "firewall_missing_or_unmanaged",
			Severity:       SeverityHigh,
			Category:       "firewall",
			Title:          "No managed firewall is active",
			Summary:        "The agent can read listening sockets, but cannot enforce deny/allow rules through ufw or firewalld.",
			Evidence:       compactEvidence(st.UnavailableMessage),
			Recommendation: "Install and enable ufw or firewalld with default-deny inbound policy, while explicitly allowing the active SSH port.",
		})
	}
	sshPorts := map[int]bool{}
	for _, p := range st.SSHPorts {
		sshPorts[p] = true
	}
	for _, sock := range st.Sockets {
		if !isPublicListenAddress(sock.Address) {
			continue
		}
		cat, ok := riskyPorts[sock.Port]
		if !ok {
			continue
		}
		if st.Available && portClosedByFirewall(st, sock) {
			// FixClosePort (typed fix or AI-runbook step of the same kind)
			// deliberately blocks reachability at the firewall without
			// stopping the service, so it keeps listening on the same
			// public address. Re-scanning Sockets alone would re-flag this
			// finding on every audit forever, making the fix look like it
			// never took effect. Recognise the exact rule state the fix
			// produces so a remediated port actually clears.
			continue
		}
		target := fmt.Sprintf("%s/%d", sock.Protocol, sock.Port)
		finding := Finding{
			ID:             fmt.Sprintf("public_%s_%d", sock.Protocol, sock.Port),
			Severity:       cat.severity,
			Category:       "exposed_ports",
			Title:          cat.name + " is listening on a public interface",
			Summary:        fmt.Sprintf("%s is bound to %s:%d and may be reachable outside the host.", cat.name, sock.Address, sock.Port),
			Evidence:       []string{socketEvidence(sock)},
			Recommendation: cat.recommendation,
		}
		if st.Available && !sshPorts[sock.Port] {
			finding.Fix = &Fix{
				Kind:        FixClosePort,
				Label:       "Block port",
				Target:      target,
				Port:        sock.Port,
				Protocol:    string(sock.Protocol),
				Destructive: false,
			}
		}
		findings = append(findings, finding)
	}
	return findings
}

// portClosedByFirewall reports whether st.Rules already blocks external
// access to sock's port, mirroring exactly what Manager.Fix's FixClosePort
// case does for st.Backend: adds an explicit deny rule on ufw/iptables-style
// backends (default-allow), or removes the allow rule on firewalld
// (default-deny once no allow rule remains).
func portClosedByFirewall(st firewall.Status, sock firewall.Socket) bool {
	if st.Backend == firewall.BackendFirewalld {
		// FixClosePort removes the allow rule punching the hole; once none
		// remains, firewalld's own default-deny policy blocks the port.
		for _, r := range st.Rules {
			if r.Action == firewall.ActionAllow && r.Port == sock.Port &&
				(r.Protocol == sock.Protocol || r.Protocol == firewall.ProtoAny) {
				return false
			}
		}
		return true
	}
	// ufw/iptables-style backends default-allow; only an explicit deny
	// rule (what FixClosePort adds) actually blocks the port.
	for _, r := range st.Rules {
		if r.Action == firewall.ActionDeny && r.Port == sock.Port &&
			(r.Protocol == sock.Protocol || r.Protocol == firewall.ProtoAny) {
			return true
		}
	}
	return false
}

func (m *Manager) sshFindings(ctx context.Context, st *firewall.Status) []Finding {
	publicSSH := false
	if st != nil {
		sshPorts := map[int]bool{}
		for _, p := range st.SSHPorts {
			sshPorts[p] = true
		}
		for _, sock := range st.Sockets {
			if sshPorts[sock.Port] && isPublicListenAddress(sock.Address) {
				publicSSH = true
				break
			}
		}
	}
	settings := m.effectiveSSHD(ctx)
	var findings []Finding
	if strings.EqualFold(settings["passwordauthentication"], "yes") {
		sev := SeverityMedium
		if publicSSH {
			sev = SeverityHigh
		}
		findings = append(findings, Finding{
			ID:             "ssh_password_auth_enabled",
			Severity:       sev,
			Category:       "ssh",
			Title:          "SSH password authentication is enabled",
			Summary:        "Password-based SSH increases brute-force and credential-stuffing risk, especially on internet-facing hosts.",
			Evidence:       []string{"PasswordAuthentication yes"},
			Recommendation: "Move operators to key-based SSH, verify key login works, then disable password authentication and reload sshd.",
		})
	}
	if strings.EqualFold(settings["permitrootlogin"], "yes") {
		findings = append(findings, Finding{
			ID:             "ssh_root_login_enabled",
			Severity:       SeverityHigh,
			Category:       "ssh",
			Title:          "Direct root SSH login is enabled",
			Summary:        "Allowing root to log in directly removes user-level accountability and makes brute-force attempts more valuable.",
			Evidence:       []string{"PermitRootLogin yes"},
			Recommendation: "Create a sudo-capable admin user, verify access, then set PermitRootLogin no or prohibit-password.",
		})
	}
	if strings.EqualFold(settings["permitemptypasswords"], "yes") {
		findings = append(findings, Finding{
			ID:             "ssh_empty_passwords_enabled",
			Severity:       SeverityCritical,
			Category:       "ssh",
			Title:          "SSH permits empty passwords",
			Summary:        "Accounts with blank passwords may be able to authenticate over SSH.",
			Evidence:       []string{"PermitEmptyPasswords yes"},
			Recommendation: "Set PermitEmptyPasswords no, lock blank-password accounts, test sshd configuration, and reload sshd.",
		})
	}
	return findings
}

func (m *Manager) processFindings(ctx context.Context) []Finding {
	if m.cfg.Processes == nil {
		return nil
	}
	procs, err := m.cfg.Processes.List(ctx, agentprocess.SortCPU, 5000)
	if err != nil {
		return []Finding{{
			ID:             "process_scan_unavailable",
			Severity:       SeverityLow,
			Category:       "processes",
			Title:          "Process scan could not be completed",
			Summary:        "The agent could not inspect running processes for suspicious launch patterns.",
			Evidence:       []string{err.Error()},
			Recommendation: "Fix process inspection permissions and rerun the audit.",
		}}
	}
	var findings []Finding
	for _, p := range procs {
		if p.KernelThread {
			// Kernel-scheduled threads (kworker, kdevtmpfs, ksoftirqd,
			// migration, rcu_gp, …) have no argv and no backing executable.
			// They can look alarming by name and cannot be terminated by a
			// signal (kill() is a no-op against them), so they are excluded
			// from every check below rather than misreported as suspicious.
			continue
		}
		if name, ok := knownMalwareMatch(p.Command); ok {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("known_malware_process_%d", p.PID),
				Severity:       SeverityCritical,
				Category:       "processes",
				Title:          "Known malware process name detected",
				Summary:        fmt.Sprintf("The running command matches %q, a name used by known Linux cryptomining/botnet malware families (e.g. the Kinsing/xmrig Redis-Docker worm, perfctl).", name),
				Evidence:       []string{fmt.Sprintf("pid=%d user=%s command=%s", p.PID, p.User, abbreviate(p.Command, 220))},
				Recommendation: "Isolate the host from the network, capture the binary and memory for forensics, then terminate the process and rotate any credentials the host could reach.",
				Fix:            killFixFor(p),
			})
			continue
		}
		if p.ExePath != "" && execFromWorldWritableDir(p.ExePath) {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("process_exec_world_writable_dir_%d", p.PID),
				Severity:       SeverityHigh,
				Category:       "processes",
				Title:          "Process is running from a world-writable directory",
				Summary:        "Legitimate long-running services do not execute from /tmp, /var/tmp, or /dev/shm. This pattern is common for malware dropped through a prior compromise.",
				Evidence:       []string{fmt.Sprintf("pid=%d user=%s exe=%s", p.PID, p.User, p.ExePath)},
				Recommendation: "Identify how the binary got there, capture a copy for analysis, then terminate and remove it.",
				Fix:            killFixFor(p),
			})
			continue
		}
		if p.ExeDeleted {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("process_exe_deleted_%d", p.PID),
				Severity:       SeverityMedium,
				Category:       "processes",
				Title:          "Process is running from a deleted or replaced binary",
				Summary:        "The on-disk file backing this running process no longer exists. This is often a routine package upgrade awaiting a service restart, but the same signature is used to hide an in-memory backdoor from disk scans.",
				Evidence:       []string{fmt.Sprintf("pid=%d user=%s exe=%s (deleted)", p.PID, p.User, p.ExePath)},
				Recommendation: "If this follows a recent update, restart the service (or run needrestart). If unexpected, treat it as a possible live compromise and investigate before restarting.",
			})
			continue
		}
		reason, ok := suspiciousCommand(p.Command)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("suspicious_process_%d", p.PID),
			Severity:       SeverityHigh,
			Category:       "processes",
			Title:          "Suspicious process launch pattern",
			Summary:        reason,
			Evidence:       []string{fmt.Sprintf("pid=%d user=%s command=%s", p.PID, p.User, abbreviate(p.Command, 220))},
			Recommendation: "Investigate the process owner, parent process, recent deployments, and network connections before terminating it.",
			Fix:            killFixFor(p),
		})
	}
	return findings
}

func killFixFor(p agentprocess.Process) *Fix {
	if p.Protected {
		return nil
	}
	return &Fix{
		Kind:           FixKillProcess,
		Label:          "Terminate process",
		Target:         strconv.Itoa(p.PID),
		PID:            p.PID,
		StartTimeTicks: p.StartTimeTicks,
		Signal:         agentprocess.SignalTerm,
		Destructive:    true,
	}
}

// knownMalwareNames intentionally does NOT include "kdevtmpfs" — that is a
// real Linux kernel thread (devtmpfs housekeeping). The malware family it is
// impersonating appends an extra "i" ("kdevtmpfsi") specifically so casual
// process-list inspection mistakes it for the legitimate thread; matching
// only the impersonated spelling keeps that distinction intact. The
// KernelThread check above additionally excludes every real kernel thread
// from this match regardless of name.
var knownMalwareNames = []string{
	"xmrig", "kinsing", "kdevtmpfsi", "sysrv", "sysrv-hello",
	"ddgs", "networkxm", "perfctl", "diicot", "watchdogs", "moneroocean",
	"skidmap",
}

// knownMalwareMatch matches process command lines against names published by
// public incident-response writeups for widely propagated Linux
// cryptomining/botnet campaigns (Kinsing, DDG, perfctl, Diicot, Skidmap).
// It is a low-noise, high-confidence signal distinct from the generic
// suspiciousCommand heuristics below.
func knownMalwareMatch(command string) (string, bool) {
	c := strings.ToLower(command)
	for _, name := range knownMalwareNames {
		if strings.Contains(c, name) {
			return name, true
		}
	}
	return "", false
}

var worldWritableExecDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

func execFromWorldWritableDir(exePath string) bool {
	for _, dir := range worldWritableExecDirs {
		if strings.HasPrefix(exePath, dir) {
			return true
		}
	}
	return false
}

func (m *Manager) controlFindings(ctx context.Context, st *firewall.Status) []Finding {
	var findings []Finding
	if st != nil {
		publicSSH := false
		sshPorts := map[int]bool{}
		for _, p := range st.SSHPorts {
			sshPorts[p] = true
		}
		for _, sock := range st.Sockets {
			if sshPorts[sock.Port] && isPublicListenAddress(sock.Address) {
				publicSSH = true
				break
			}
		}
		if publicSSH && !m.systemdActive(ctx, "fail2ban") {
			findings = append(findings, Finding{
				ID:             "fail2ban_inactive_for_public_ssh",
				Severity:       SeverityMedium,
				Category:       "bruteforce",
				Title:          "Fail2ban is not active for a public SSH service",
				Summary:        "The host exposes SSH but the common brute-force banning service is not active.",
				Evidence:       []string{"systemctl is-active fail2ban did not report active"},
				Recommendation: "Install and enable fail2ban or an equivalent SSH rate-limit control.",
			})
		}
	}
	if !m.systemdActive(ctx, "auditd") {
		findings = append(findings, Finding{
			ID:             "auditd_inactive",
			Severity:       SeverityLow,
			Category:       "logging",
			Title:          "Linux audit daemon is not active",
			Summary:        "Host-level security events may not be captured in a durable audit trail.",
			Evidence:       []string{"systemctl is-active auditd did not report active"},
			Recommendation: "Enable auditd with a non-empty ruleset appropriate for the server role.",
			Fix: &Fix{
				Kind:        FixEnableAuditd,
				Label:       "Install and enable auditd",
				Target:      "auditd",
				Destructive: false,
			},
		})
	}
	if _, err := m.cfg.ReadFile("/var/run/reboot-required"); err == nil {
		findings = append(findings, Finding{
			ID:             "reboot_required_after_updates",
			Severity:       SeverityMedium,
			Category:       "patching",
			Title:          "Server reboot is required to finish updates",
			Summary:        "Some security updates may not be fully applied until the host reboots.",
			Evidence:       []string{"/var/run/reboot-required exists"},
			Recommendation: "Schedule a reboot through the existing server action after confirming workloads can restart safely.",
		})
	}
	return findings
}

func (m *Manager) accountFindings() []Finding {
	passwd, err := m.cfg.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var uid0 []string
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == "0" {
			uid0 = append(uid0, fields[0])
		}
	}
	if len(uid0) <= 1 {
		return nil
	}
	return []Finding{{
		ID:             "multiple_uid0_accounts",
		Severity:       SeverityCritical,
		Category:       "accounts",
		Title:          "Multiple UID 0 accounts exist",
		Summary:        "More than one account has root-equivalent UID 0 privileges.",
		Evidence:       []string{"uid=0 accounts: " + strings.Join(uid0, ", ")},
		Recommendation: "Disable or reassign unexpected UID 0 accounts after confirming they are not required by the OS image.",
	}}
}

func (m *Manager) dockerFindings() []Finding {
	mode, err := m.cfg.Stat("/var/run/docker.sock")
	if err != nil {
		return nil
	}
	var findings []Finding
	if mode.Perm()&0o002 != 0 {
		findings = append(findings, Finding{
			ID:             "docker_socket_world_writable",
			Severity:       SeverityCritical,
			Category:       "docker",
			Title:          "Docker socket is world-writable",
			Summary:        "Anyone on the host can talk to the Docker daemon and launch a privileged container to gain root, bypassing every other access control.",
			Evidence:       []string{fmt.Sprintf("/var/run/docker.sock permissions %#o", mode.Perm())},
			Recommendation: "Restrict /var/run/docker.sock to root:docker with mode 0660 and remove world access immediately.",
		})
	}
	if raw, err := m.cfg.ReadFile("/etc/group"); err == nil {
		if members := groupMembers(string(raw), "docker"); len(members) > 0 {
			findings = append(findings, Finding{
				ID:             "docker_group_membership",
				Severity:       SeverityLow,
				Category:       "docker",
				Title:          "Accounts hold root-equivalent docker group access",
				Summary:        "Membership in the docker group is equivalent to root: a member can mount the host filesystem through a container and read or modify anything on it.",
				Evidence:       []string{"docker group members: " + strings.Join(members, ", ")},
				Recommendation: "Limit docker group membership to operators who need host-root-equivalent access.",
			})
		}
	}
	return findings
}

func groupMembers(etcGroup, name string) []string {
	for _, line := range strings.Split(etcGroup, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[0] == name {
			var members []string
			for _, u := range strings.Split(fields[3], ",") {
				if u = strings.TrimSpace(u); u != "" {
					members = append(members, u)
				}
			}
			return members
		}
	}
	return nil
}

type criticalFile struct {
	path      string
	maxPerm   fs.FileMode
	checkRead bool
}

var criticalFiles = []criticalFile{
	{path: "/etc/passwd", maxPerm: 0o022},
	// maxPerm only gates group/other WRITE access here (matches the other
	// entries below) — NOT read. /etc/shadow's recommended fixed state is
	// mode 0640 owned by root:shadow (see filePermissionFindings' generated
	// recommendation), which intentionally leaves the group-read bit set for
	// the shadow group. A maxPerm that also covered read (e.g. 0o077) would
	// make that recommended, fully-remediated state permanently non-compliant
	// — the "world_writable_etc_shadow" finding would never clear even after
	// applying the exact fix the recommendation asks for. World-readability
	// (the "other" bit) is already checked separately below via checkRead.
	{path: "/etc/shadow", maxPerm: 0o022, checkRead: true},
	{path: "/etc/gshadow", maxPerm: 0o022, checkRead: true},
	{path: "/etc/sudoers", maxPerm: 0o022},
	{path: "/etc/crontab", maxPerm: 0o022},
}

func (m *Manager) filePermissionFindings() []Finding {
	var findings []Finding
	for _, cf := range criticalFiles {
		mode, err := m.cfg.Stat(cf.path)
		if err != nil {
			continue
		}
		perm := mode.Perm()
		if perm&cf.maxPerm != 0 {
			findings = append(findings, Finding{
				ID:             "world_writable_" + sanitizeID(cf.path),
				Severity:       SeverityCritical,
				Category:       "files",
				Title:          cf.path + " is writable beyond its owner",
				Summary:        fmt.Sprintf("%s allows group or other write access, which lets any account in that scope escalate privileges by rewriting a security-critical file.", cf.path),
				Evidence:       []string{fmt.Sprintf("%s permissions %#o", cf.path, perm)},
				Recommendation: "Remove group and other write access; " + cf.path + " must only be writable by root.",
			})
		}
		if cf.checkRead && perm&0o004 != 0 {
			findings = append(findings, Finding{
				ID:             "world_readable_" + sanitizeID(cf.path),
				Severity:       SeverityHigh,
				Category:       "files",
				Title:          cf.path + " is world-readable",
				Summary:        "Password hashes in this file can be copied by any local account and cracked offline.",
				Evidence:       []string{fmt.Sprintf("%s permissions %#o", cf.path, perm)},
				Recommendation: "Set " + cf.path + " to mode 0640 or stricter, owned by root and the shadow group.",
			})
		}
	}
	return findings
}

func sanitizeID(path string) string {
	return strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
}

func (m *Manager) ldPreloadFindings() []Finding {
	raw, err := m.cfg.ReadFile("/etc/ld.so.preload")
	if err != nil {
		return nil
	}
	content := strings.TrimSpace(string(raw))
	if content == "" {
		return nil
	}
	return []Finding{{
		ID:             "ld_preload_configured",
		Severity:       SeverityCritical,
		Category:       "persistence",
		Title:          "A library is force-loaded into every process via ld.so.preload",
		Summary:        "This mechanism is rarely used legitimately and is the classic persistence technique for userland rootkits (e.g. Diamorphine, Azazel) that hide files, processes, and network connections from tools that use standard libc calls.",
		Evidence:       []string{"/etc/ld.so.preload: " + abbreviate(content, 200)},
		Recommendation: "Confirm every listed library is an intentional, trusted install. If not, remove the entry and audit the host for a rootkit.",
	}}
}

func (m *Manager) shadowFindings() []Finding {
	raw, err := m.cfg.ReadFile("/etc/shadow")
	if err != nil {
		return nil
	}
	var empty []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 2 && fields[0] != "" && fields[1] == "" {
			empty = append(empty, fields[0])
		}
	}
	if len(empty) == 0 {
		return nil
	}
	return []Finding{{
		ID:             "accounts_with_empty_password",
		Severity:       SeverityCritical,
		Category:       "accounts",
		Title:          "Accounts have no password set",
		Summary:        "These accounts can authenticate with a blank password wherever PAM allows it: console login, su, or SSH if PermitEmptyPasswords is enabled.",
		Evidence:       []string{"accounts: " + strings.Join(empty, ", ")},
		Recommendation: "Set a strong password or lock the account (passwd -l) for every account listed.",
	}}
}

func (m *Manager) cronFindings() []Finding {
	var files []string
	if _, err := m.cfg.ReadFile("/etc/crontab"); err == nil {
		files = append(files, "/etc/crontab")
	}
	for _, pattern := range []string{"/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"} {
		matches, err := m.cfg.Glob(pattern)
		if err != nil {
			continue
		}
		files = append(files, matches...)
	}
	var findings []Finding
	seen := map[string]bool{}
	for _, path := range files {
		if seen[path] {
			continue
		}
		seen[path] = true
		raw, err := m.cfg.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			reason, ok := suspiciousCommand(line)
			if !ok {
				continue
			}
			findings = append(findings, Finding{
				ID:             "suspicious_cron_" + sanitizeID(path),
				Severity:       SeverityHigh,
				Category:       "persistence",
				Title:          "Suspicious scheduled task",
				Summary:        reason,
				Evidence:       []string{fmt.Sprintf("%s: %s", path, abbreviate(line, 220))},
				Recommendation: "Review who added this cron entry and what it targets; remove it if it is not a known deployment task.",
			})
			break
		}
	}
	return findings
}

func (m *Manager) sysctlFindings() []Finding {
	var findings []Finding
	if v, ok := m.sysctlValue("/proc/sys/net/ipv4/tcp_syncookies"); ok && v == "0" {
		findings = append(findings, Finding{
			ID:             "sysctl_syncookies_disabled",
			Severity:       SeverityMedium,
			Category:       "kernel",
			Title:          "SYN flood protection is disabled",
			Summary:        "net.ipv4.tcp_syncookies is 0, so the kernel cannot fall back to SYN cookies under a SYN flood, making the host easier to knock offline.",
			Evidence:       []string{"net.ipv4.tcp_syncookies = 0"},
			Recommendation: "Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d and apply with sysctl --system.",
		})
	}
	if v, ok := m.sysctlValue("/proc/sys/net/ipv4/conf/all/rp_filter"); ok && v == "0" {
		findings = append(findings, Finding{
			ID:             "sysctl_rp_filter_disabled",
			Severity:       SeverityMedium,
			Category:       "kernel",
			Title:          "Reverse path filtering is disabled",
			Summary:        "net.ipv4.conf.all.rp_filter is 0, allowing spoofed-source packets to be routed, which weakens anti-spoofing and can enable the host to be used in amplification or relay abuse.",
			Evidence:       []string{"net.ipv4.conf.all.rp_filter = 0"},
			Recommendation: "Set net.ipv4.conf.all.rp_filter = 1 (or 2 on hosts with asymmetric routing) via sysctl.",
		})
	}
	if v, ok := m.sysctlValue("/proc/sys/fs/suid_dumpable"); ok && v != "0" {
		findings = append(findings, Finding{
			ID:             "sysctl_suid_dumpable_enabled",
			Severity:       SeverityMedium,
			Category:       "kernel",
			Title:          "Core dumps are enabled for setuid programs",
			Summary:        "fs.suid_dumpable is not 0, so a crashing setuid binary can write a core dump that leaks secrets from its memory to any local reader of the dump.",
			Evidence:       []string{"fs.suid_dumpable = " + v},
			Recommendation: "Set fs.suid_dumpable = 0 via sysctl.",
		})
	}
	if v, ok := m.sysctlValue("/proc/sys/kernel/kptr_restrict"); ok && v == "0" {
		findings = append(findings, Finding{
			ID:             "sysctl_kptr_restrict_disabled",
			Severity:       SeverityLow,
			Category:       "kernel",
			Title:          "Kernel pointers are exposed to unprivileged users",
			Summary:        "kernel.kptr_restrict is 0, which leaks kernel addresses through /proc and can help an attacker bypass KASLR during local privilege escalation.",
			Evidence:       []string{"kernel.kptr_restrict = 0"},
			Recommendation: "Set kernel.kptr_restrict = 1 (or 2) via sysctl.",
		})
	}
	return findings
}

func (m *Manager) sysctlValue(path string) (string, bool) {
	raw, err := m.cfg.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

func (m *Manager) patchAutomationFindings(ctx context.Context) []Finding {
	finding := Finding{
		ID:             "automatic_security_updates_disabled",
		Severity:       SeverityMedium,
		Category:       "patching",
		Title:          "Automatic security updates are not enabled",
		Summary:        "Without unattended security patching, known vulnerabilities can sit unpatched between manual maintenance windows.",
		Recommendation: "Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic/yum-cron (RHEL family) for security-only updates.",
	}
	if _, err := m.cfg.ReadFile("/etc/debian_version"); err == nil {
		raw, confErr := m.cfg.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
		if confErr == nil && strings.Contains(string(raw), `Unattended-Upgrade "1"`) {
			return nil
		}
		finding.Evidence = []string{"/etc/apt/apt.conf.d/20auto-upgrades is missing or does not enable Unattended-Upgrade"}
		return []Finding{finding}
	}
	if _, err := m.cfg.ReadFile("/etc/redhat-release"); err == nil {
		if m.systemdActive(ctx, "dnf-automatic.timer") || m.systemdActive(ctx, "yum-cron") {
			return nil
		}
		finding.Evidence = []string{"neither dnf-automatic.timer nor yum-cron is active"}
		return []Finding{finding}
	}
	return nil
}

func (m *Manager) macFindings(ctx context.Context) []Finding {
	if raw, err := m.cfg.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(raw)) == "Y" {
			return nil
		}
	}
	if out, err := m.cfg.Run(ctx, "getenforce"); err == nil {
		status := strings.TrimSpace(string(out))
		if strings.EqualFold(status, "Enforcing") {
			return nil
		}
		if strings.EqualFold(status, "Permissive") {
			return []Finding{{
				ID:             "selinux_permissive",
				Severity:       SeverityLow,
				Category:       "mac",
				Title:          "SELinux is in permissive mode",
				Summary:        "Policy violations are logged but not blocked, so SELinux is not actually containing a compromised process.",
				Evidence:       []string{"getenforce: Permissive"},
				Recommendation: "Switch to enforcing mode once the current policy is verified not to break legitimate workloads.",
			}}
		}
	}
	return []Finding{{
		ID:             "mac_framework_inactive",
		Severity:       SeverityLow,
		Category:       "mac",
		Title:          "No mandatory access control framework is active",
		Summary:        "Neither AppArmor nor SELinux is enforcing, so a compromised process is limited only by discretionary Unix permissions.",
		Evidence:       []string{"apparmor and selinux both report inactive or absent"},
		Recommendation: "Enable AppArmor (Debian/Ubuntu default) or SELinux (RHEL family default) in enforcing mode.",
	}}
}

func (m *Manager) effectiveSSHD(ctx context.Context) map[string]string {
	settings := map[string]string{}
	if out, err := m.cfg.Run(ctx, "sshd", "-T"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				settings[strings.ToLower(fields[0])] = strings.ToLower(fields[1])
			}
		}
		if len(settings) > 0 {
			return settings
		}
	}
	m.readSSHDFile("/etc/ssh/sshd_config", settings)
	if matches, err := m.cfg.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		sort.Strings(matches)
		for _, path := range matches {
			m.readSSHDFile(path, settings)
		}
	}
	return settings
}

func (m *Manager) readSSHDFile(path string, out map[string]string) {
	raw, err := m.cfg.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[strings.ToLower(fields[0])] = strings.ToLower(fields[1])
		}
	}
}

func (m *Manager) systemdActive(ctx context.Context, unit string) bool {
	out, err := m.cfg.Run(ctx, "systemctl", "is-active", unit)
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func suspiciousCommand(command string) (string, bool) {
	c := strings.ToLower(command)
	patterns := []struct {
		needle string
		reason string
	}{
		{"/dev/tcp/", "A process command references shell TCP redirection, a common reverse-shell indicator."},
		{"bash -i", "A process was launched as an interactive shell from a command line."},
		{"sh -i", "A process was launched as an interactive shell from a command line."},
		{"nc -e", "Netcat is running with command execution flags."},
		{"ncat -e", "Ncat is running with command execution flags."},
		{"socat exec:", "Socat is running with an exec bridge."},
		{"socket.socket", "A script command creates raw sockets from the command line."},
		{"subprocess.call", "A script command combines subprocess execution with inline code."},
		{"curl ", "A command-line download is running; investigate if it pipes into a shell."},
		{"wget ", "A command-line download is running; investigate if it pipes into a shell."},
	}
	for _, p := range patterns {
		if strings.Contains(c, p.needle) {
			if (p.needle == "curl " || p.needle == "wget ") && !(strings.Contains(c, "| sh") || strings.Contains(c, "| bash")) {
				continue
			}
			return p.reason, true
		}
	}
	return "", false
}

func isPublicListenAddress(addr string) bool {
	addr = strings.Trim(addr, "[]")
	switch addr {
	case "", "*", "0.0.0.0", "::", ":::":
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func socketEvidence(sock firewall.Socket) string {
	owner := sock.Process
	if sock.PID > 0 {
		owner = fmt.Sprintf("%s pid=%d", owner, sock.PID)
	}
	if owner == "" {
		owner = "unknown process"
	}
	return fmt.Sprintf("%s %s:%d owned by %s", sock.Protocol, sock.Address, sock.Port, owner)
}

func compactEvidence(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return []string{s}
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

func abbreviate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
