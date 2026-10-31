package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{
		"pki/ca.crt":                "CA",
		"pki/private/ca.key":        "KEY",
		"pki/index.txt":             "V\t…",
		"state/.cvpnctl-state.json": "{}",
		"template/base.ovpn":        "client",
	}
	for p, body := range files {
		writeFile(t, filepath.Join(src, p), body)
	}

	data, err := Pack(src)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	dst := t.TempDir()
	if err := Unpack(data, dst); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	for p, body := range files {
		got, err := os.ReadFile(filepath.Join(dst, p))
		if err != nil || string(got) != body {
			t.Errorf("%s = %q, %v; want %q", p, got, err, body)
		}
		fi, _ := os.Stat(filepath.Join(dst, p))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, fi.Mode().Perm())
		}
	}
	fi, _ := os.Stat(filepath.Join(dst, "pki", "private"))
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %o, want 700", fi.Mode().Perm())
	}
}

func TestPackIsDeterministic(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "pki/b"), "b")
	writeFile(t, filepath.Join(src, "pki/a"), "a")
	one, _ := Pack(src)
	two, _ := Pack(src)
	if !bytes.Equal(one, two) {
		t.Error("two packs of the same tree differ")
	}
}

func TestPackIgnoresOtherDirs(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "pki/ca.crt"), "CA")
	writeFile(t, filepath.Join(src, "out/max.ovpn"), "secret")
	data, _ := Pack(src)
	dst := t.TempDir()
	if err := Unpack(data, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "out")); err == nil {
		t.Error("out/ was packed")
	}
}

func TestPackRequiresPKI(t *testing.T) {
	if _, err := Pack(t.TempDir()); err == nil {
		t.Error("Pack without pki/ succeeded")
	}
}

// rawArchive builds a .tar.gz from hand-made headers, to produce archives
// Pack never would.
func rawArchive(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		h := h
		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = 1
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUnpackRejects(t *testing.T) {
	reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600} }
	tests := map[string][]tar.Header{
		"parent dir":     {reg("../x")},
		"nested parent":  {reg("pki/../../x")},
		"absolute":       {reg("/etc/x")},
		"symlink":        {{Name: "pki/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		"hard link":      {{Name: "pki/link", Typeflag: tar.TypeLink, Linkname: "pki/ca.crt"}},
		"char device":    {{Name: "pki/dev", Typeflag: tar.TypeChar}},
		"unknown top":    {reg("other/x")},
		"top-level file": {reg("ca.crt")},
		"too large":      {{Name: "pki/big", Typeflag: tar.TypeReg, Size: 11 << 20, Mode: 0o600}},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dst := filepath.Join(parent, "root")
			err := Unpack(rawArchive(t, entries...), dst)
			if !errors.Is(err, ErrUnsafeArchive) {
				t.Errorf("err = %v, want ErrUnsafeArchive", err)
			}
			if _, err := os.Stat(filepath.Join(parent, "x")); err == nil {
				t.Error("a file was written outside the root")
			}
		})
	}
}

func TestUnpackRejectsGarbage(t *testing.T) {
	if err := Unpack([]byte("not a gzip"), t.TempDir()); err == nil {
		t.Error("Unpack accepted garbage")
	}
}

// A symlink already inside the target that points outside it: the names in
// the archive are fine, but writing through the link would escape the root.
func TestUnpackDoesNotFollowSymlinkOut(t *testing.T) {
	outside, dst := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dst, "pki")); err != nil {
		t.Fatal(err)
	}
	err := Unpack(rawArchive(t, tar.Header{Name: "pki/ca.crt", Typeflag: tar.TypeReg, Mode: 0o600}), dst)
	if err == nil {
		t.Error("Unpack wrote through a symlink that leaves the root")
	}
	if _, err := os.Stat(filepath.Join(outside, "ca.crt")); err == nil {
		t.Error("a file was written outside the root")
	}
}

// Dots inside a name are no parent reference: users like a..b are valid.
func TestUnpackAcceptsDotsInNames(t *testing.T) {
	dst := t.TempDir()
	if err := Unpack(rawArchive(t, tar.Header{Name: "pki/issued/a..b.crt", Typeflag: tar.TypeReg, Mode: 0o600}), dst); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "pki", "issued", "a..b.crt")); err != nil {
		t.Error(err)
	}
}

// Pack refuses what Unpack would refuse, both by file size and by the size
// of the tar stream (headers included), and accepts what fits.
func TestPackSizeLimit(t *testing.T) {
	tests := map[string]struct {
		files   int
		size    int64
		wantErr bool
	}{
		"one large file":        {1, maxArchiveSize + 1, true},
		"many files near limit": {1024, maxArchiveSize/1024 - 256, true}, // contents fit, headers don't
		"fits":                  {1, maxArchiveSize - 64<<10, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for i := range tc.files {
				p := filepath.Join(root, "pki", "issued", fmt.Sprintf("f%04d", i))
				writeFile(t, p, "")
				if err := os.Truncate(p, tc.size); err != nil {
					t.Fatal(err)
				}
			}
			data, err := Pack(root)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "nothing was saved") {
					t.Fatalf("err = %v, want a size refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			if err := Unpack(data, t.TempDir()); err != nil {
				t.Errorf("Unpack of an archive Pack accepted: %v", err)
			}
		})
	}
}
