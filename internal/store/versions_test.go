package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// More versions than fit on one list page (S3 returns at most 1000): all are
// listed, newest first, with the current one marked.
func TestVersionsFollowsPages(t *testing.T) {
	_, f := s3Env(t) // one archive version
	for i := range 6 {
		f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(fmt.Appendf(nil, "v%d", i)),
			Metadata: map[string]string{"cvpnctl-arn": fmt.Sprintf("admin-%d", i)}})
	}
	f.PageSize = 2

	vs, err := Versions(context.Background(), f, testStore)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 7 {
		t.Fatalf("%d versions, want 7", len(vs))
	}
	seen := map[string]bool{}
	for i, v := range vs {
		if seen[v.ID] {
			t.Errorf("version %s listed twice", v.ID)
		}
		seen[v.ID] = true
		if i > 0 && v.Modified.After(vs[i-1].Modified) {
			t.Errorf("not newest first at %d", i)
		}
		if v.Current != (i == 0) {
			t.Errorf("version %d: Current = %v", i, v.Current)
		}
		// Each version names its own writer (newest first: admin-5 … admin-0).
		if want := fmt.Sprintf("admin-%d", 5-i); i < 6 && v.Writer != want {
			t.Errorf("version %d: Writer = %q, want %q", i, v.Writer, want)
		}
	}
}

func TestDeleted(t *testing.T) {
	f := storetest.New()
	if d, err := Deleted(context.Background(), f, testStore); d || err != nil {
		t.Errorf("empty bucket: %v, %v", d, err)
	}
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("a"))})
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz.old"), Body: bytes.NewReader([]byte("x"))})
	if d, _ := Deleted(context.Background(), f, testStore); d {
		t.Error("Deleted with a current version")
	}
	f.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz")})
	if d, _ := Deleted(context.Background(), f, testStore); !d {
		t.Error("not Deleted after the archive was deleted")
	}
	// The first page holds only the delete marker.
	f.PageSize = 1
	if d, err := Deleted(context.Background(), f, testStore); !d || err != nil {
		t.Errorf("versions behind a page of delete markers: %v, %v", d, err)
	}
}

// The current archive was deleted (a delete marker on top of its versions):
// ordinary commands say so, and Recover restores into the gap, but only
// while it is still a gap.
func TestOpenDeleted(t *testing.T) {
	cfg, f := s3Env(t)
	f.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz")})

	if _, err := Open(context.Background(), cfg, Write, deps(f, "create alice")); !errors.Is(err, ErrStoreDeleted) {
		t.Fatalf("Write: err = %v, want ErrStoreDeleted", err)
	}
	open := func() Workspace {
		ws, err := Open(context.Background(), cfg, Recover, deps(f, "store restore"))
		if err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if ws.Damaged() == nil {
			t.Error("Damaged() = nil for a deleted archive")
		}
		if err := ws.Verify(context.Background()); err != nil {
			t.Errorf("Verify while still deleted: %v", err)
		}
		writeFile(t, filepath.Join(ws.PKIDir(), "ca.crt"), "CA")
		return ws
	}

	ws := open()
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("Checkpoint into the gap: %v", err)
	}
	if got := stored(t, f, "pki/ca.crt"); got != "CA" {
		t.Errorf("restored ca.crt = %q", got)
	}
	ws.Close(context.Background())

	// Deleted again, then someone writes after our open: we must not
	// overwrite them.
	f.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz")})
	ws = open()
	defer ws.Close(context.Background())
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("newer"))})
	if err := ws.Verify(context.Background()); !errors.Is(err, ErrStoreChanged) {
		t.Errorf("Verify after someone wrote: err = %v, want ErrStoreChanged", err)
	}
	if err := ws.Checkpoint(context.Background()); !errors.Is(err, ErrStoreChanged) {
		t.Errorf("Checkpoint after someone wrote: err = %v, want ErrStoreChanged", err)
	}
}

// Archives that unpack but lack what commands read: Write refuses them with a
// hint to restore, Recover opens them as damaged.
func TestOpenIncomplete(t *testing.T) {
	tests := map[string]map[string]string{
		"no index.txt": {"pki/ca.crt": "CA"},
		"bad state":    {"pki/ca.crt": "CA", "pki/index.txt": "", "state/.cvpnctl-state.json": "{not json"},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, f := s3Env(t)
			src := t.TempDir()
			for p, body := range files {
				writeFile(t, filepath.Join(src, p), body)
			}
			data, err := Pack(src)
			if err != nil {
				t.Fatal(err)
			}
			f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(data)})

			if _, err := Open(context.Background(), cfg, Write, deps(f, "create alice")); err == nil || !strings.Contains(err.Error(), "store restore") {
				t.Errorf("Write: err = %v, want a hint to restore", err)
			}
			ws, err := Open(context.Background(), cfg, Recover, deps(f, "store restore"))
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			defer ws.Close(context.Background())
			if ws.Damaged() == nil {
				t.Error("Damaged() = nil")
			}
		})
	}
}
