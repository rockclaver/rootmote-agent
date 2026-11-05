package diagnose

import (
	"context"
	"fmt"
	"math"
	"strings"
)

// certExpiringDays is how far ahead a certificate counts as expiring. It
// matches the renewal check: a renewed certificate must be further away.
const certExpiringDays = 30

// largestDirCount is how many directories a disk incident lists.
const largestDirCount = 5

// --- disk ---

// collectDisk lists the biggest directories on the failing mount point, so
// the playbook can tell the user where the space went.
func (c *Collector) collectDisk(ctx context.Context, t Target, b *Bundle, ids *idAllocator) {
	if c.disk == nil {
		b.Warnings = append(b.Warnings, "disk usage by directory unavailable: no disk source configured")
		return
	}
	mount := t.Target
	if mount == "" {
		mount = "/"
	}
	rctx, cancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	dirs, err := c.disk.LargestDirs(rctx, mount, largestDirCount)
	cancel()
	if err != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("disk usage by directory for %q unavailable: %s", mount, err))
	}
	for _, d := range dirs {
		if !c.itemBudgetOK(b) {
			break
		}
		path, rep := c.redactor.Text(d.Path)
		b.Redaction.Merge(rep)
		b.Signals = append(b.Signals, Signal{
			ID:      ids.id("sig_large_directory"),
			Type:    "large_directory",
			Value:   math.Round(d.SizeMB),
			Detail:  fmt.Sprintf("%s uses %.0f MB", path, d.SizeMB),
			Subject: path,
		})
	}
}

// --- pm2 ---

// collectPM2 adds one component per PM2 app that is stopped or crashed. For a
// pm2_app monitor (target "<user>/<app>") it adds only that app: an app that
// is online but restarting over and over is reported as "restarting".
func (c *Collector) collectPM2(ctx context.Context, t Target, b *Bundle, ids *idAllocator) {
	if c.stack == nil {
		b.Warnings = append(b.Warnings, "pm2 evidence unavailable: no stack source configured")
		return
	}
	for _, app := range c.stack.Stack(ctx).PM2Apps {
		state := strings.ToLower(app.Status)
		if t.MonitorKind == "pm2_app" {
			if t.Target != app.User+"/"+app.App {
				continue
			}
			if !isStoppedPM2(state) {
				state = "restarting"
			}
		} else if !isStoppedPM2(state) {
			continue
		}
		if !c.itemBudgetOK(b) {
			break
		}
		b.Components = append(b.Components, Component{
			ID:     ids.id("cmp_pm2_" + sanitize(app.User+"_"+app.App)),
			Kind:   "pm2_app",
			Name:   app.App,
			State:  state,
			Owner:  app.User,
			Detail: fmt.Sprintf("PM2 app %s (user %s) is %s", app.App, app.User, state),
		})
	}
}

// --- certificates ---

// collectCerts adds one component per certificate that expires soon or has
// expired. When some certificates match the incident's target, only those are
// listed.
func (c *Collector) collectCerts(ctx context.Context, t Target, b *Bundle, ids *idAllocator) {
	if c.stack == nil {
		b.Warnings = append(b.Warnings, "certificate evidence unavailable: no stack source configured")
		return
	}
	certs := c.stack.Stack(ctx).Certs
	host := hostFromTarget(t.Target)
	name := certNameFromPath(t.Target)
	var matched []Cert
	for _, cert := range certs {
		switch {
		case name != "" && cert.Name == name:
			matched = append(matched, cert)
		case host != "" && (strings.EqualFold(cert.Name, host) || strings.HasSuffix(host, "."+strings.ToLower(cert.Name))):
			matched = append(matched, cert)
		}
	}
	if len(matched) > 0 {
		certs = matched
	}
	now := c.now()
	for _, cert := range certs {
		days := cert.ExpiresAt.Sub(now).Hours() / 24
		var state, detail string
		switch {
		case days < 0:
			state, detail = "expired", fmt.Sprintf("%s expired %.0f days ago", cert.Name, -days)
		case days <= certExpiringDays:
			state, detail = "expiring", fmt.Sprintf("%s expires in %.0f days", cert.Name, days)
		default:
			continue
		}
		if !c.itemBudgetOK(b) {
			break
		}
		b.Components = append(b.Components, Component{
			ID:     ids.id("cmp_cert_" + sanitize(cert.Name)),
			Kind:   "certificate",
			Name:   cert.Name,
			State:  state,
			Detail: detail,
		})
	}
}

// certNameFromPath returns the certificate name in a Let's Encrypt file path
// such as /etc/letsencrypt/live/<name>/fullchain.pem, or "" for anything else.
func certNameFromPath(target string) string {
	const marker = "/letsencrypt/live/"
	i := strings.Index(target, marker)
	if i < 0 {
		return ""
	}
	name, _, _ := strings.Cut(target[i+len(marker):], "/")
	return name
}

func hostFromTarget(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, ":"); i >= 0 && !strings.Contains(t[i:], "]") {
		t = t[:i]
	}
	return strings.ToLower(t)
}

// --- reverse proxy ---

// collectProxy gathers the proxy side of a failing web address: the monitor's
// own summary, the proxy's error log and the backends behind the address.
func (c *Collector) collectProxy(ctx context.Context, t Target, b *Bundle, ids *idAllocator) {
	if strings.TrimSpace(t.Summary) != "" && c.itemBudgetOK(b) {
		excerpt, rep, dropped := c.buildLog(ids, MonitorSummarySource, []string{t.Summary})
		b.Redaction.Merge(rep)
		b.DroppedItems += dropped
		b.Logs = append(b.Logs, excerpt)
	}
	if c.proxy == nil {
		b.Warnings = append(b.Warnings, "proxy evidence unavailable: no proxy source configured")
		return
	}
	lctx, lcancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	raw, err := c.proxy.ErrorLog(lctx, c.budget.MaxLogLines)
	lcancel()
	if err != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("proxy error log unavailable: %s", err))
	} else if strings.TrimSpace(raw) != "" && c.itemBudgetOK(b) {
		excerpt, rep, dropped := c.buildLog(ids, "proxy:error.log", strings.Split(strings.TrimRight(raw, "\n"), "\n"))
		b.Redaction.Merge(rep)
		b.DroppedItems += dropped
		b.Logs = append(b.Logs, excerpt)
	}
	uctx, ucancel := context.WithTimeout(ctx, c.budget.ReadTimeout)
	ups, err := c.proxy.Upstreams(uctx, t.Target)
	ucancel()
	if err != nil {
		b.Warnings = append(b.Warnings, fmt.Sprintf("proxy backends for %q unavailable: %s", t.Target, err))
		return
	}
	for _, up := range ups {
		if !c.itemBudgetOK(b) {
			break
		}
		kind := "upstream_address"
		name := up.Address
		if up.Kind == "unit" || up.Kind == "container" {
			kind = "upstream_" + up.Kind
			name = up.Name
		}
		detail, rep := c.redactor.Text("backend " + up.Address)
		b.Redaction.Merge(rep)
		b.Components = append(b.Components, Component{
			ID:     ids.id("cmp_" + kind + "_" + sanitize(name)),
			Kind:   kind,
			Name:   name,
			State:  "unknown",
			Detail: detail,
		})
	}
}
