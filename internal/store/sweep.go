//go:build unix

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// staleAfter is the age at which a cvpnctl temp folder counts as left behind
// by a crash. Commands finish in seconds; an hour leaves room for one waiting
// at a passphrase prompt.
const staleAfter = time.Hour

// Sweep removes cvpnctl-* folders in dir that belong to uid, are older than
// olderThan, and whose process (recorded in their .pid file) is no longer
// running. A command that crashed (kill -9, power loss) can't delete its temp
// folder, which holds a copy of the CA key; the next S3 command does. The
// process check keeps a command that has been waiting at a prompt for a long
// time safe from a second command started meanwhile. Errors are ignored:
// sweeping is best-effort.
func Sweep(dir string, uid int, olderThan time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-olderThan)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "cvpnctl-") {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.ModTime().Before(cutoff) {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != uid {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if running(path) {
			continue
		}
		_ = os.RemoveAll(path)
	}
}

// running reports whether the process recorded in dir's .pid file still
// exists. Signal 0 checks for a process without affecting it; EPERM means it
// exists but belongs to someone else.
func running(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, pidFile))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false
	}
	err = syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
