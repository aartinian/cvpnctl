// Package store keeps cvpnctl's PKI, state and template either in local
// directories or, in S3 mode, as one archive in an S3 bucket.
package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// topDirs are the only top-level directories an archive holds.
var topDirs = []string{"pki", "state", "template"}

// maxArchiveSize caps the unpacked size of an archive. A PKI is a few hundred
// kilobytes; anything near this is not one.
const maxArchiveSize = 10 << 20

// ErrUnsafeArchive is returned for archives with entries outside the three
// top-level directories, links, devices, or more than maxArchiveSize of data.
var ErrUnsafeArchive = errors.New("unsafe archive")

// Pack archives the pki/, state/ and template/ directories under root as a
// gzipped tar. pki/ must exist; the other two are optional. The output is
// deterministic: entries are sorted, and times and owners are zeroed.
func Pack(root string) ([]byte, error) {
	if fi, err := os.Stat(filepath.Join(root, "pki")); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("store: pack: %s has no pki directory", root)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, top := range topDirs {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		// WalkDir visits entries in lexical order, which keeps the output
		// deterministic.
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			name := filepath.ToSlash(rel)
			switch {
			case d.IsDir():
				return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: time.Unix(0, 0)})
			case d.Type().IsRegular():
				data, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0)}); err != nil {
					return err
				}
				_, err = tw.Write(data)
				return err
			default:
				return fmt.Errorf("%s is not a regular file or directory", name)
			}
		})
		if err != nil {
			return nil, fmt.Errorf("store: pack: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("store: pack: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("store: pack: %w", err)
	}
	return buf.Bytes(), nil
}

// Unpack extracts an archive made by Pack into root, which is created if
// needed. Files are written with mode 0600 and directories with 0700. Any
// entry that could escape root or isn't a plain file or directory makes it
// fail with ErrUnsafeArchive.
//
// Besides checking the names, it writes through an os.Root, so the OS itself
// refuses any path that would leave root, even through a symlink in it.
func Unpack(data []byte, root string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("store: unpack: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("store: unpack: %w", err)
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("store: unpack: %w", err)
	}
	defer func() { _ = dir.Close() }()

	tr := tar.NewReader(io.LimitReader(gz, maxArchiveSize+1))
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("store: unpack: %w", err)
		}
		name, err := safeName(h.Name)
		if err != nil {
			return err
		}
		target := filepath.FromSlash(name)

		switch h.Typeflag {
		case tar.TypeDir:
			if err := dir.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("store: unpack: %w", err)
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxArchiveSize {
				return fmt.Errorf("%w: more than %d bytes", ErrUnsafeArchive, maxArchiveSize)
			}
			if err := writeEntry(dir, tr, target, h.Size); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %s is not a regular file or directory", ErrUnsafeArchive, h.Name)
		}
	}
}

// safeName validates an archive entry name and returns it cleaned. It must
// be relative, stay inside the root, and sit below one of topDirs.
func safeName(name string) (string, error) {
	clean := path.Clean(strings.TrimSuffix(name, "/"))
	if path.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("%w: %s escapes the archive root", ErrUnsafeArchive, name)
	}
	top, _, _ := strings.Cut(clean, "/")
	if !slices.Contains(topDirs, top) {
		return "", fmt.Errorf("%w: %s is outside %s", ErrUnsafeArchive, name, strings.Join(topDirs, ", "))
	}
	return clean, nil
}

// writeEntry writes size bytes from r to target, a path inside dir.
func writeEntry(dir *os.Root, r io.Reader, target string, size int64) error {
	if err := dir.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("store: unpack: %w", err)
	}
	f, err := dir.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("store: unpack: %w", err)
	}
	if _, err := io.CopyN(f, r, size); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: unpack %s: %w", target, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: unpack: %w", err)
	}
	return f.Close()
}
