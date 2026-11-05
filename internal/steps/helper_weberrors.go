package steps

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// Limits for the web-errors action.
const (
	webErrorLines = 200
	webErrorBytes = 64 * 1024
	webLogRoot    = "/var/log"
)

// webLogDefaults are tried after the paths named in the web server configs.
var webLogDefaults = []string{
	"/var/log/nginx/error.log",
	"/var/log/apache2/error.log",
	"/var/log/httpd/error_log",
}

// webMainConfigs hold the error_log (nginx) and ErrorLog (Apache) directives
// the action follows. Only these fixed files are read.
var webMainConfigs = []string{
	"/etc/nginx/nginx.conf",
	"/etc/apache2/apache2.conf",
	"/etc/httpd/conf/httpd.conf",
}

var (
	nginxErrorLog  = regexp.MustCompile(`(?m)^\s*error_log\s+("[^"]+"|'[^']+'|[^\s;]+)`)
	apacheErrorLog = regexp.MustCompile(`(?mi)^\s*ErrorLog\s+("[^"]+"|'[^']+'|\S+)`)
)

type webErrorLog struct {
	Path string `json:"path"`
	Text string `json:"text"`
}

// webErrors prints the end of the web server error logs as JSON: a list of
// {path, text}. It is read-only. Only regular files below /var/log are read,
// and no folder on the way may be a symlink, so the action cannot be pointed
// at another file. The auth log and every other log stay out of reach.
func webErrors(_ context.Context, h Host, args []string, out io.Writer) error {
	if err := wantArgs(args, 0); err != nil {
		return err
	}
	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		p = path.Clean(p)
		if !seen[p] && strings.HasPrefix(p, webLogRoot+"/") {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for _, conf := range webMainConfigs {
		raw, err := h.ReadFile(conf)
		if err != nil {
			continue
		}
		for _, re := range []*regexp.Regexp{nginxErrorLog, apacheErrorLog} {
			for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
				p := strings.Trim(m[1], `"'`)
				p = strings.ReplaceAll(p, "${APACHE_LOG_DIR}", "/var/log/apache2")
				if strings.HasPrefix(p, "/") {
					add(p)
				}
			}
		}
	}
	for _, p := range webLogDefaults {
		add(p)
	}

	logs := []webErrorLog{}
	budget := int64(webErrorBytes)
	for _, p := range paths {
		if budget <= 0 {
			break
		}
		if !plainLogPath(h, p) {
			continue
		}
		data, err := h.ReadTail(p, budget)
		if err != nil {
			continue
		}
		if int64(len(data)) >= budget {
			// The byte limit cut the first line in half: drop it.
			if i := strings.IndexByte(string(data), '\n'); i >= 0 {
				data = data[i+1:]
			}
		}
		text := lastLines(string(data), webErrorLines)
		if text == "" {
			continue
		}
		budget -= int64(len(text))
		logs = append(logs, webErrorLog{Path: p, Text: text})
	}
	return json.NewEncoder(out).Encode(logs)
}

// plainLogPath reports whether p is a regular file below /var/log reached
// without passing through a symlink.
func plainLogPath(h Host, p string) bool {
	rest := strings.TrimPrefix(p, webLogRoot+"/")
	cur := webLogRoot
	parts := strings.Split(rest, "/")
	for i, part := range parts {
		cur = cur + "/" + part
		fi, err := h.Lstat(cur)
		if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
			return false
		}
		if i == len(parts)-1 {
			return fi.Mode().IsRegular()
		}
		if !fi.IsDir() {
			return false
		}
	}
	return false
}

// lastLines keeps the last n lines.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
