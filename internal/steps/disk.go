package steps

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// MountPointOf returns the mount point of the filesystem that holds path,
// read from /proc/self/mountinfo. The path does not have to exist, and no
// permission on it is needed (Docker's data directory is closed to the agent).
func MountPointOf(path string) (string, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("Could not read the list of mounted disks: %v", err)
	}
	return mountPointFrom(string(raw), path)
}

// mountPointFrom picks the longest mount point that contains path. When two
// mounts share a point, the later one is on top.
func mountPointFrom(mountinfo, path string) (string, error) {
	best := ""
	found := false
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mp := unescapeMountField(f[4])
		if !pathWithin(mp, path) {
			continue
		}
		if !found || len(mp) >= len(best) {
			best, found = mp, true
		}
	}
	if !found {
		return "", fmt.Errorf("Could not find the disk that holds %s.", path)
	}
	return best, nil
}

func pathWithin(mount, path string) bool {
	if mount == "/" {
		return true
	}
	return path == mount || strings.HasPrefix(path, mount+"/")
}

// unescapeMountField decodes the octal escapes mountinfo uses (\040 for a space).
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			v := 0
			ok := true
			for _, c := range s[i+1 : i+4] {
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + int(c-'0')
			}
			if ok {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// DiskPercentAtPath returns how full the filesystem that holds path is, using
// statfs on its mount point (so it also works when "/" is an overlay, as in a
// container). The figure is used/total, the same one the disk monitor uses.
func DiskPercentAtPath(path string) (float64, error) {
	mp, err := MountPointOf(path)
	if err != nil {
		return 0, err
	}
	return statfsPercent(mp)
}

func statfsPercent(mount string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mount, &st); err != nil {
		return 0, fmt.Errorf("Could not read disk usage for %s: %v", mount, err)
	}
	total := uint64(st.Blocks) * uint64(st.Bsize)
	if total == 0 {
		return 0, fmt.Errorf("Disk usage for %s is not available.", mount)
	}
	avail := uint64(st.Bavail) * uint64(st.Bsize)
	return float64(total-avail) * 100 / float64(total), nil
}
