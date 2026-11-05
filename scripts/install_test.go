package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runInstall(t *testing.T, env []string, path string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "install.sh")
	cmd.Env = append([]string{"PATH=" + path, "HOME=" + t.TempDir()}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stderr.String(), code
}

const refusedVersion = "ROOTMOTE_AGENT_VERSION must be a release tag like v0.2.0."

// Only one line holding exactly vX.Y.Z is accepted. A line-based check would
// let a value with a second line through.
func TestInstallVersionCheck(t *testing.T) {
	bad := []string{
		"", "v1", "v1.2", "1.2.3", "v1.2.3.4", "v1.2.3-rc1", "v1.2.x", "v.1.2", "v1..2", "v1.2.", "V1.2.3",
		"v1.2.3\n", "v1.2.3\nv4.5.6", "v1.2.3\nextra", "x\nv1.2.3", "v1.2.3 ", " v1.2.3", "v1.2.3;id",
		"v1.2.3\r", "v1.2.3/../x", "main",
	}
	for _, v := range bad {
		stderr, code := runInstall(t, []string{"ROOTMOTE_AGENT_VERSION=" + v, "ROOTMOTE_AGENT_BASE_URL=http://127.0.0.1:1"}, os.Getenv("PATH"))
		if code == 0 || !strings.Contains(stderr, refusedVersion) {
			t.Errorf("version %q: exit %d, stderr %q, want the version refusal", v, code, stderr)
		}
	}
	// A good tag passes the check and then stops at the (unreachable) download.
	for _, v := range []string{"v0.2.0", "v10.20.300"} {
		stderr, code := runInstall(t, []string{"ROOTMOTE_AGENT_VERSION=" + v, "ROOTMOTE_AGENT_BASE_URL=http://127.0.0.1:1"}, os.Getenv("PATH"))
		if code == 0 || strings.Contains(stderr, refusedVersion) || !strings.Contains(stderr, "failed to download SHA256SUMS") {
			t.Errorf("version %q: exit %d, stderr %q, want it to get as far as the download", v, code, stderr)
		}
	}
}

// If the sudo rule fails visudo, the installer stops before it changes
// anything, so the agent that is running keeps running.
// installFixture builds a fake release and fake system commands. Every
// recorded command lands in the returned call log.
func installFixture(t *testing.T, visudoOK bool) (env []string, path, log string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs sh")
	}
	dir := t.TempDir()
	shims := filepath.Join(dir, "bin")
	release := filepath.Join(dir, "release")
	log = filepath.Join(dir, "calls.log")
	for _, d := range []string{shims, release} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	files := map[string]string{
		"rootmote-agent-linux-" + arch:      "binary",
		"rootmote-agent.service":            "unit",
		"rootmote-agent.sudoers":            "rootmote ALL=(root) NOPASSWD: /usr/local/bin/rootmote-agent priv *\n",
		"rootmote-agent-sudo.tmpfiles.conf": "d /run/sudo 0711 root root -\n",
	}
	var sums strings.Builder
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(release, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(body))
		sums.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(release, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	shim := func(name, body string) {
		if err := os.WriteFile(filepath.Join(shims, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	record := `echo "$(basename "$0") $*" >> "$CALL_LOG"` + "\n"
	// curl copies the named release file to the -o destination.
	shim("curl", `url=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
cp "$RELEASE_DIR/$(basename "$url")" "$out"
`)
	shim("id", `if [ "${1:-}" = "-u" ]; then echo 0; fi
if [ "${1:-}" = "-nG" ]; then echo "rootmote adm docker"; fi
exit 0
`)
	if visudoOK {
		shim("visudo", "exit 0\n")
	} else {
		shim("visudo", "exit 1\n")
	}
	// The runner may have a real, root-owned /etc/sudoers.d; the staged rule
	// file never exists there in this fixture, so removing it is a no-op.
	shim("rm", `for a in "$@"; do case "$a" in /etc/sudoers.d/*) exit 0 ;; esac; done
exec /bin/rm "$@"
`)
	for _, n := range []string{"install", "useradd", "usermod", "systemctl", "systemd-tmpfiles", "getent", "mv", "journalctl", "gpasswd", "rmdir"} {
		shim(n, record+"exit 0\n")
	}
	sys := "/usr/bin:/bin"
	env = []string{
		"ROOTMOTE_AGENT_VERSION=v0.2.0",
		"ROOTMOTE_AGENT_BASE_URL=http://example.invalid/release",
		"RELEASE_DIR=" + release,
		"CALL_LOG=" + log,
	}
	return env, shims + ":" + sys, log
}

func TestInstallStopsBeforeChangesWhenSudoersFails(t *testing.T) {
	env, path, log := installFixture(t, false)
	stderr, code := runInstall(t, env, path)
	if code == 0 || !strings.Contains(stderr, "did not pass visudo") || !strings.Contains(stderr, "current agent was left running") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	calls, _ := os.ReadFile(log)
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if line == "" {
			continue
		}
		// The only call allowed before the check is staging the .new rule file.
		if !strings.HasPrefix(line, "install -m 0440 ") || !strings.HasSuffix(line, "/etc/sudoers.d/rootmote-agent.new") {
			t.Errorf("the installer changed something before the sudo rule was checked: %q", line)
		}
	}
}

// The installer gives the agent no extra groups besides docker (no `adm`,
// which would expose the auth log), takes `adm` away from an install that
// still has it, and creates no per-user skill folders.
func TestInstallAddsOnlyTheDockerGroupAndNoCLIFolders(t *testing.T) {
	env, path, log := installFixture(t, true)
	// No waiting, and nothing that looks like a listener to kill.
	shimDir := strings.TrimSuffix(path, ":/usr/bin:/bin")
	for name, body := range map[string]string{"sleep": "exit 0\n", "ss": "exit 0\n", "fuser": "exit 0\n"} {
		if err := os.WriteFile(filepath.Join(shimDir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = runInstall(t, env, path) // it fails at the very end: the agent never listens in this fixture
	raw, _ := os.ReadFile(log)
	calls := string(raw)
	if !strings.Contains(calls, "usermod -aG docker rootmote") {
		t.Fatalf("the docker group was not added:\n%s", calls)
	}
	if !strings.Contains(calls, "gpasswd -d rootmote adm") {
		t.Errorf("an old install's adm membership was not removed:\n%s", calls)
	}
	for _, line := range strings.Split(calls, "\n") {
		if strings.HasPrefix(line, "usermod") && !strings.Contains(line, "docker") {
			t.Errorf("unexpected group change: %q", line)
		}
		if strings.HasPrefix(line, "rmdir ") {
			continue // removing the old empty folders is the point
		}
		if strings.Contains(line, ".claude") || strings.Contains(line, ".codex") || strings.Contains(line, "skills") {
			t.Errorf("a CLI-era folder was created: %q", line)
		}
	}
}
