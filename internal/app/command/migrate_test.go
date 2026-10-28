package command

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// localThenS3 returns a local-mode harness with users, plus the path of its
// local config. The harness is then switched to an S3-mode config with an
// empty bucket, ready for `store migrate --from <local config>`.
func localThenS3(t *testing.T) (*harness, string) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	h := newHarness(t)
	h.must(h.create("alice"))
	h.must(h.create("bob"))
	h.must(h.revoke("bob"))
	local := h.opts.ConfigFile
	h.useS3Config(filepath.Join(h.dir, "cvpnctl-s3.yaml"))
	return h, local
}

func migrate(h *harness, from string) (string, error) {
	return captureStdout(h.t, func() error { return runMigrate(context.Background(), h.opts, from) })
}

func TestMigrate(t *testing.T) {
	h, local := localThenS3(t)
	localSerial := func() string {
		c, err := readCert(filepath.Join(h.pki, "issued", "alice.crt"))
		if err != nil {
			t.Fatal(err)
		}
		return c.SerialNumber.Text(16)
	}()

	out, err := migrate(h, local)
	if err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	for _, want := range []string{"cvpnctl status", "delete the local copies"} {
		if !strings.Contains(out, want) {
			t.Errorf("next steps lack %q:\n%s", want, out)
		}
	}

	// Everything came across: the certificate, the state, the revocation and the template.
	if got := h.serial("alice"); got != localSerial {
		t.Errorf("stored alice serial %s, local %s", got, localSerial)
	}
	if r, ok := h.record("alice"); !ok || r.ProviderID == "" {
		t.Errorf("stored state lacks alice: %+v", r)
	}
	if _, ok := h.record("bob"); ok {
		t.Error("revoked bob came back in the stored state")
	}
	if tmpl, _ := os.ReadFile(filepath.Join(h.storedCopy(), "template", "base.ovpn")); !strings.Contains(string(tmpl), "{{.User}}") {
		t.Errorf("stored template = %q", tmpl)
	}

	// S3 mode works on the migrated PKI.
	h.must(h.renew("alice"))
	if h.serial("alice") == localSerial {
		t.Error("renew after migrate didn't issue a new certificate")
	}
	if _, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg); held {
		t.Error("lock left behind")
	}
	if l := h.leftovers(); len(l) != 0 {
		t.Errorf("temp folders left: %v", l)
	}
}

func TestMigrateNeverDeletesLocal(t *testing.T) {
	h, local := localThenS3(t)
	if _, err := migrate(h, local); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(h.pki, "ca.crt"), filepath.Join(h.certsDir(), ".cvpnctl-state.json"), filepath.Join(h.dir, "base.ovpn")} {
		if !h.exists(p) {
			t.Errorf("migrate removed %s", p)
		}
	}
}

func TestMigrateRefusesExistingArchive(t *testing.T) {
	h, local := localThenS3(t)
	existing := []byte("someone's PKI")
	h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(existing)})

	_, err := migrate(h, local)
	if err == nil || !strings.Contains(err.Error(), "already holds a PKI") {
		t.Fatalf("err = %v", err)
	}
	if got, _ := h.s3.Object("cvpnctl/pki.tar.gz"); !bytes.Equal(got, existing) {
		t.Error("the existing archive was overwritten")
	}
}

func TestMigrateRefusesBadBucket(t *testing.T) {
	h, local := localThenS3(t)
	h.s3.Settings.Versioning = false
	_, err := migrate(h, local)
	if err == nil || !strings.Contains(err.Error(), "bucket") || !strings.Contains(err.Error(), "versioning is off") {
		t.Fatalf("err = %v, want it to name the versioning problem", err)
	}
	if _, ok := h.s3.Object("cvpnctl/pki.tar.gz"); ok {
		t.Error("an archive was uploaded to a misconfigured bucket")
	}
	if _, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg); held {
		t.Error("lock left behind")
	}
}

func TestMigrateRequiresModes(t *testing.T) {
	h, local := localThenS3(t)
	s3cfg := h.opts.ConfigFile
	if _, err := migrate(h, s3cfg); err == nil || !strings.Contains(err.Error(), "--from") {
		t.Errorf("--from an S3 config: err = %v", err)
	}
	h.opts.ConfigFile = local
	if _, err := migrate(h, local); err == nil || !strings.Contains(err.Error(), "requires `store`") {
		t.Errorf("active config in local mode: err = %v", err)
	}
}

// A state file that can't be checked is not a missing one: migrating without
// it would drop every user's ACM mapping, so migrate stops.
func TestMigrateUnreadableState(t *testing.T) {
	h, local := localThenS3(t)
	if err := os.Chmod(h.certsDir(), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(h.certsDir(), 0o700) })

	if _, err := migrate(h, local); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want the stat error", err)
	}
	if _, ok := h.s3.Object("cvpnctl/pki.tar.gz"); ok {
		t.Error("an archive was uploaded without the state")
	}
}

// Someone deleted the stored archive: migrate must not put a different PKI on
// top of its history, but point to restore.
func TestMigrateOntoDeletedStore(t *testing.T) {
	h, local := localThenS3(t)
	h.must(func() error { _, err := migrate(h, local); return err }())
	h.s3.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz")})

	if _, err := migrate(h, local); !errors.Is(err, store.ErrStoreDeleted) {
		t.Fatalf("err = %v, want ErrStoreDeleted", err)
	}
	if _, ok := h.s3.Object("cvpnctl/pki.tar.gz"); ok {
		t.Error("migrate wrote a new archive over the deleted one")
	}
}
