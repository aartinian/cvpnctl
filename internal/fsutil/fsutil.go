// Package fsutil provides file helpers shared by the packages that write
// certificates, keys, .ovpn files, and state to disk.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile atomically replaces path with data and gives it exactly mode perm.
//
// The data goes to a temporary file in the same directory, which is synced and
// then renamed over path, so readers see either the old file or the new one,
// never a partial write. The mode is set explicitly rather than through
// os.WriteFile, which ignores perm when the file already exists and is subject
// to the umask — neither is acceptable for private keys.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmp := f.Name()

	// remove the temp file if anything goes wrong
	defer func() { _ = os.Remove(tmp) }()

	// write the data, set the mode, sync, and close
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}
