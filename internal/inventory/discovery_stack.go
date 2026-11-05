package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PM2AppInfo is one PM2 application owned by a human user.
type PM2AppInfo struct {
	User   string `json:"user"`
	App    string `json:"app"`
	Status string `json:"status"`
}

// SupervisorProgramInfo is one supervisord program and its state.
type SupervisorProgramInfo struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// DatabaseUnitInfo is one database systemd unit. Kind is mysql, mariadb,
// postgresql or redis.
type DatabaseUnitInfo struct {
	Kind string `json:"kind"`
	Unit string `json:"unit"`
}

// CertInfo is one Let's Encrypt certificate: name and expiry only.
type CertInfo struct {
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
}

const (
	maxPM2Users      = 20
	letsEncryptLive  = "/etc/letsencrypt/live/"
	passwdPath       = "/etc/passwd"
	minHumanUID      = 1000
	maxHumanUIDLimit = 65534
)

var (
	phpFPMUnitRe = regexp.MustCompile(`^php[0-9.]*-fpm\.service$`)
	dbUnitRes    = []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"mysql", regexp.MustCompile(`^mysql(d)?\.service$`)},
		{"mariadb", regexp.MustCompile(`^mariadb\.service$`)},
		{"postgresql", regexp.MustCompile(`^postgresql(@[0-9.]+-[A-Za-z0-9_.-]+)?\.service$`)},
		{"redis", regexp.MustCompile(`^redis(-server)?\.service$`)},
	}
)

// discoverStack fills the PM2, PHP-FPM, supervisor and database-unit
// sections. It must run after discoverSystemd.
func (d *Discoverer) discoverStack(ctx context.Context, report *DiscoveryReport) {
	d.discoverStackUnits(report)
	d.discoverPM2(ctx, report)
	d.discoverSupervisor(ctx, report)
}

func (d *Discoverer) discoverStackUnits(report *DiscoveryReport) {
	php := []string{}
	dbSeen := map[DatabaseUnitInfo]bool{}
	dbs := []DatabaseUnitInfo{}
	for _, u := range report.SystemdUnits {
		if phpFPMUnitRe.MatchString(u.Name) {
			php = append(php, u.Name)
		}
		for _, p := range dbUnitRes {
			if p.re.MatchString(u.Name) {
				e := DatabaseUnitInfo{Kind: p.kind, Unit: u.Name}
				if !dbSeen[e] {
					dbSeen[e] = true
					dbs = append(dbs, e)
				}
				break
			}
		}
	}
	sort.Strings(php)
	sort.Slice(dbs, func(i, j int) bool {
		if dbs[i].Kind != dbs[j].Kind {
			return dbs[i].Kind < dbs[j].Kind
		}
		return dbs[i].Unit < dbs[j].Unit
	})
	report.PHPFPMUnits = dedupeSorted(php)
	report.DatabaseUnits = dbs
}

func dedupeSorted(in []string) []string {
	out := make([]string, 0, len(in))
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// humanUsers returns up to maxPM2Users login users from /etc/passwd, sorted
// by name.
func (d *Discoverer) humanUsers() []string {
	raw, err := d.cfg.ReadFile(passwdPath)
	if err != nil {
		return nil
	}
	var users []string
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 7 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || uid < minHumanUID || uid >= maxHumanUIDLimit {
			continue
		}
		shell := f[6]
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		if f[5] == "" {
			continue
		}
		users = append(users, f[0])
	}
	sort.Strings(users)
	users = dedupeSorted(users)
	if len(users) > maxPM2Users {
		users = users[:maxPM2Users]
	}
	return users
}

func (d *Discoverer) discoverPM2(ctx context.Context, report *DiscoveryReport) {
	users := d.humanUsers()
	if len(users) == 0 {
		return
	}
	if d.cfg.Priv == nil {
		if runtime.GOOS == "linux" {
			d.warn(report, "PM2 apps could not be listed: the privileged helper is not available")
		}
		return
	}
	apps := []PM2AppInfo{}
	for _, user := range users {
		out, err := d.cfg.Priv(ctx, "pm2-list", user)
		if err != nil {
			d.warn(report, "PM2 apps for user %s could not be listed: %v", user, err)
			continue
		}
		var rows []struct {
			App    string `json:"app"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(out, &rows); err != nil {
			d.warn(report, "PM2 apps for user %s could not be read: %v", user, err)
			continue
		}
		for _, r := range rows {
			apps = append(apps, PM2AppInfo{User: user, App: r.App, Status: r.Status})
		}
	}
	report.PM2Apps = apps
}

func (d *Discoverer) discoverSupervisor(ctx context.Context, report *DiscoveryReport) {
	found := false
	for _, u := range report.SystemdUnits {
		if u.Name == "supervisor.service" || u.Name == "supervisord.service" {
			found = true
			break
		}
	}
	if !found {
		return
	}
	if d.cfg.Priv == nil {
		d.warn(report, "supervisor programs could not be listed: the privileged helper is not available")
		return
	}
	out, err := d.cfg.Priv(ctx, "supervisor-status")
	if err != nil {
		d.warn(report, "supervisor programs could not be listed: %v", err)
		return
	}
	var rows []SupervisorProgramInfo
	if err := json.Unmarshal(out, &rows); err != nil {
		d.warn(report, "supervisor programs could not be read: %v", err)
		return
	}
	if rows != nil {
		report.SupervisorPrograms = rows
	}
}

// discoverLetsEncrypt reads certificate names and expiry through the
// privileged helper (the live directory is root-only) and returns the
// matching legacy tlsCertificates entries.
func (d *Discoverer) discoverLetsEncrypt(ctx context.Context, report *DiscoveryReport) []TLSCertificateInfo {
	if d.cfg.Priv == nil {
		d.warn(report, "Let's Encrypt certificates could not be read: the privileged helper is not available")
		return nil
	}
	out, err := d.cfg.Priv(ctx, "certs-list")
	if err != nil {
		d.warn(report, "Let's Encrypt certificates could not be read: %v", err)
		return nil
	}
	var rows []CertInfo
	if err := json.Unmarshal(out, &rows); err != nil {
		d.warn(report, "Let's Encrypt certificates could not be read: %v", err)
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	now := d.cfg.Now()
	legacy := make([]TLSCertificateInfo, 0, len(rows))
	for _, r := range rows {
		exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil {
			d.warn(report, "Let's Encrypt certificate %s has an unreadable expiry %q", r.Name, r.ExpiresAt)
			continue
		}
		exp = exp.UTC()
		report.Certs = append(report.Certs, CertInfo{Name: r.Name, ExpiresAt: exp.Format(time.RFC3339)})
		info := TLSCertificateInfo{
			Domain:        r.Name,
			NotAfter:      exp,
			DaysRemaining: int(exp.Sub(now).Hours() / 24),
			Path:          fmt.Sprintf("%s%s/fullchain.pem", letsEncryptLive, r.Name),
		}
		if now.After(exp) {
			info.ChainError = "certificate expired"
		}
		legacy = append(legacy, info)
	}
	return legacy
}
