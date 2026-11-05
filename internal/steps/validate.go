package steps

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	nameRe  = regexp.MustCompile(namePattern)
	certRe  = regexp.MustCompile(certPattern)
	phpRe   = regexp.MustCompile(phpPattern)
	userRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)
	digitRe = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// RefusedError means a step was refused on purpose (bad input, protected
// target, safety rule). The message is one plain-English sentence. The helper
// exits with status 2 for it.
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return e.Msg }

func refuse(format string, args ...any) error {
	return &RefusedError{Msg: fmt.Sprintf(format, args...)}
}

// IsRefused reports whether err is a deliberate refusal.
func IsRefused(err error) bool {
	var r *RefusedError
	return errors.As(err, &r)
}

// ValidateName checks a unit, container, program or app name. what is used
// in the message ("service", "container", ...).
func ValidateName(what, s string) error {
	if !nameRe.MatchString(s) {
		return refuse("That %s name is not allowed.", what)
	}
	if strings.HasPrefix(s, "-") {
		return refuse("That %s name is not allowed.", what)
	}
	return nil
}

// ValidateUser checks a login user name for pm2 steps.
func ValidateUser(s string) error {
	if !userRe.MatchString(s) {
		return refuse("That user name is not allowed.")
	}
	return nil
}

// ValidateCertName checks a Let's Encrypt certificate name. It refuses path
// separators and dot segments so the name can never leave
// /etc/letsencrypt/live/.
func ValidateCertName(s string) error {
	if !certRe.MatchString(s) || strings.Contains(s, "..") {
		return refuse("That certificate name is not allowed.")
	}
	return nil
}

// ValidatePHPUnit checks that a unit looks like php8.3-fpm.service.
func ValidatePHPUnit(s string) error {
	if err := ValidateName("service", s); err != nil {
		return err
	}
	if !phpRe.MatchString(s) {
		return refuse("That is not a PHP-FPM service.")
	}
	return nil
}

// ValidatePort checks a TCP/UDP port number.
func ValidatePort(p int64) error {
	if p < 1 || p > 65535 {
		return refuse("The port must be between 1 and 65535.")
	}
	return nil
}

// ValidateProto checks the firewall protocol.
func ValidateProto(s string) error {
	if s != "tcp" && s != "udp" {
		return refuse("The protocol must be tcp or udp.")
	}
	return nil
}

// ParsePID parses a process id from helper argv. Only plain digits are
// accepted, so "-1", "+5" and "0x1" are all refused. PID 0 and 1 are refused.
func ParsePID(s string) (int, error) {
	if !digitRe.MatchString(s) {
		return 0, refuse("The process number is not valid.")
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, refuse("The process number is not valid.")
	}
	if n <= 1 {
		return 0, refuse("That process cannot be stopped.")
	}
	return int(n), nil
}

// ParseStartTime parses a process start time (clock ticks since boot).
func ParseStartTime(s string) (uint64, error) {
	if !digitRe.MatchString(s) {
		return 0, refuse("The process start time is not valid.")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, refuse("The process start time is not valid.")
	}
	return n, nil
}

// unitSuffixes are the systemd unit types. Only .service units may be
// changed; every other type is refused.
var unitSuffixes = []string{".service", ".socket", ".target", ".timer", ".path", ".mount", ".automount", ".slice", ".scope", ".swap", ".device", ".snapshot"}

// unitBase strips a known unit-type suffix.
func unitBase(name string) string {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(name, s) {
			return strings.TrimSuffix(name, s)
		}
	}
	return name
}

var protectedExact = map[string]bool{
	"ssh": true, "sshd": true, "networking": true, "network": true, "NetworkManager": true,
	"systemd-networkd": true, "systemd-resolved": true,
	"wpa_supplicant": true, "ufw": true, "firewalld": true, "nftables": true,
	"iptables": true, "ip6tables": true, "netfilter-persistent": true,
	"rootmote-agent": true, "docker": true, "containerd": true,
}

var protectedPrefix = []string{"systemd-", "dbus", "getty@", "serial-getty@", "ssh@", "sshd@", "sshd-", "sshd-session", "NetworkManager", "ifup@", "user@"}

// IsServiceName reports whether name is a bare unit name or ends in
// .service. Units of any other type are never accepted.
func IsServiceName(name string) bool {
	for _, s := range unitSuffixes {
		if s != ".service" && strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

// IsProtectedUnit reports whether restarting or stopping a unit is always
// refused. Restarting ssh would cut the connection; restarting docker stops
// every container; the others would break the server or this agent.
func IsProtectedUnit(name string) bool {
	base := unitBase(name)
	if protectedExact[base] {
		return true
	}
	for _, p := range protectedPrefix {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return false
}

// CheckUnitAllowed validates a service name and refuses protected units.
func CheckUnitAllowed(name string) error {
	if err := ValidateName("service", name); err != nil {
		return err
	}
	if !IsServiceName(name) {
		return refuse("%s is not a service. Rootmote only changes services.", name)
	}
	if IsProtectedUnit(name) {
		return refuse("%s is a protected system service. Rootmote will not change it. You can do it yourself if you are sure.", unitBase(name))
	}
	return nil
}
