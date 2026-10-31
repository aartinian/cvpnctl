package command

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aartinian/cvpnctl/internal/store"
)

// version returns the current archive version in the fake bucket.
func (h *harness) version() string {
	h.t.Helper()
	v, ok, err := store.Current(context.Background(), h.s3, storeCfg)
	if err != nil || !ok {
		h.t.Fatalf("no current version: %v", err)
	}
	return v.ID
}

func restore(h *harness, version string, yes bool) (string, error) {
	return captureStdout(h.t, func() error { return runRestore(context.Background(), h.opts, version, yes) })
}

func TestVersionsLists(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	current := h.version()
	out, err := captureStdout(t, func() error { return runVersions(context.Background(), h.opts, "") })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, current) || !strings.Contains(out, "current") || !strings.Contains(out, testCaller) {
		t.Errorf("versions output lacks the current version, its mark or its writer:\n%s", out)
	}
	if strings.Count(out, "\n") < 3 {
		t.Errorf("want the initial and the create versions listed:\n%s", out)
	}
}

// Like the other S3 commands, versions refuses rather than panics in a
// build without S3 support.
func TestVersionsWithoutS3(t *testing.T) {
	h := newHarnessS3(t)
	h.opts.NewS3 = nil
	if err := runVersions(context.Background(), h.opts, ""); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("err = %v, want 'S3 mode is not available'", err)
	}
}

func TestVersionsDetails(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	h.must(h.create("bob"))
	out, err := captureStdout(t, func() error { return runVersions(context.Background(), h.opts, h.version()) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"max", "bob", "0 revoked"} {
		if !strings.Contains(out, want) {
			t.Errorf("details lack %q:\n%s", want, out)
		}
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	// A restore that doesn't cross the issuing of a certificate is safe and
	// needs no typed confirmation: here, undoing a template change.
	h := newHarnessS3(t)
	h.must(h.create("max"))
	if err := runTemplateSet(context.Background(), h.opts, writeTemplate(t, "client\n# first {{.User}}\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n")); err != nil {
		t.Fatal(err)
	}
	first := h.version()
	if err := runTemplateSet(context.Background(), h.opts, writeTemplate(t, "client\n# second {{.User}}\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n")); err != nil {
		t.Fatal(err)
	}
	pushes := h.cloud.crlPushes

	out, err := restore(h, first, true)
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if tmpl, _ := os.ReadFile(filepath.Join(h.storedCopy(), "template", "base.ovpn")); !strings.Contains(string(tmpl), "# first") {
		t.Errorf("the template wasn't restored: %q", tmpl)
	}
	if _, ok := h.record("max"); !ok {
		t.Error("max is missing from the stored state")
	}
	if h.version() == first {
		t.Error("restore didn't write a new version on top")
	}
	if h.cloud.crlPushes != pushes {
		t.Error("restore pushed a CRL; it must leave that to the admin")
	}
	if !strings.Contains(out, "cvpnctl status") {
		t.Errorf("follow-up steps missing:\n%s", out)
	}
}

// Restoring a state from before a revocation would let that user connect
// again after the next push. --yes isn't enough for that.
func TestRestoreUnrevokeGuard(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	before := h.version()
	h.must(h.revoke("max")) // revoked and pushed
	archive, _ := h.s3.Object("cvpnctl/pki.tar.gz")

	_, err := restore(h, before, true)
	if err == nil || err.Error() != "--yes is not accepted when a restore would un-revoke certificates or lose track of valid ones, or when the current version is unusable" {
		t.Fatalf("with --yes: err = %v", err)
	}
	// Without a terminal (or with stdin closed, as under go test) nobody can
	// type 'restore', so it aborts.
	out, err := restore(h, before, false)
	if err == nil || (!strings.Contains(err.Error(), "not a terminal") && !strings.Contains(err.Error(), "aborted")) {
		t.Fatalf("without --yes: err = %v", err)
	}
	if !strings.Contains(out, "max") || !strings.Contains(out, "connect again") {
		t.Errorf("the warning doesn't name max:\n%s", out)
	}
	if got, _ := h.s3.Object("cvpnctl/pki.tar.gz"); !bytes.Equal(got, archive) {
		t.Error("the archive changed although the restore was refused")
	}
	if l := h.leftovers(); len(l) != 0 {
		t.Errorf("temp folders left: %v", l)
	}
}

func TestRestoreRefusesCurrentAndUnknown(t *testing.T) {
	h := newHarnessS3(t)
	if _, err := restore(h, h.version(), true); err == nil || !strings.Contains(err.Error(), "already the current version") {
		t.Errorf("current version: err = %v", err)
	}
	if _, err := restore(h, "v999", true); err == nil || !strings.Contains(err.Error(), "v999") {
		t.Errorf("unknown version: err = %v", err)
	}
}

func TestRestoreLocalMode(t *testing.T) {
	h := newHarness(t)
	if err := runRestore(context.Background(), h.opts, "v1", true); err == nil || !strings.Contains(err.Error(), "requires `store`") {
		t.Errorf("err = %v", err)
	}
}

// Restoring a version from before a user was created would leave their
// certificate valid (signed by the CA, trusted by the endpoint) but unknown to
// the restored PKI, so it could never be revoked. That gets the same guard as
// a lost revocation.
func TestRestoreUnknownCertGuard(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	before := h.version()
	h.must(h.create("judy"))
	archive, _ := h.s3.Object("cvpnctl/pki.tar.gz")

	out, err := restore(h, before, true)
	if err == nil || err.Error() != "--yes is not accepted when a restore would un-revoke certificates or lose track of valid ones, or when the current version is unusable" {
		t.Fatalf("with --yes: err = %v\n%s", err, out)
	}
	if !strings.Contains(out, "judy") || !strings.Contains(out, "could never be revoked") {
		t.Errorf("the warning doesn't explain what happens to judy:\n%s", out)
	}
	if got, _ := h.s3.Object("cvpnctl/pki.tar.gz"); !bytes.Equal(got, archive) {
		t.Error("the archive changed although the restore was refused")
	}
}

// Restoring a version where a certificate is just as valid as now is fine.
func TestRestoreKeepsKnownCerts(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	withMax := h.version()
	if err := runTemplateSet(context.Background(), h.opts, writeTemplate(t, "client\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := restore(h, withMax, true); err != nil {
		t.Fatalf("restoring a version with the same certificates: %v", err)
	}
}

// If the restore's target folder lost its PKI (e.g. swept while waiting at
// the prompt), nothing is replaced: never upload an empty PKI.
func TestReplaceWorkspaceRequiresPKI(t *testing.T) {
	h := newHarnessS3(t)
	cfg, _ := config.Load(h.opts.ConfigFile)
	ws, err := store.Open(context.Background(), cfg, store.Write, store.Deps{S3: h.s3, Caller: testCaller, Command: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(context.Background())

	empty := t.TempDir() // a target without pki/
	if err := replaceWorkspace(ws, empty); err == nil || !strings.Contains(err.Error(), "ca.crt") {
		t.Fatalf("err = %v, want a missing ca.crt error", err)
	}
	if _, err := os.Stat(filepath.Join(ws.PKIDir(), "ca.crt")); err != nil {
		t.Errorf("the workspace's PKI was touched: %v", err)
	}
}

// The current archive is corrupt, so no other command can open the store:
// restore still runs, holds the lock, and treats the restore as dangerous,
// because it can only compare the endpoint's CRL.
func TestRestoreDamagedCurrent(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	good := h.version()
	h.must(h.revoke("max")) // revoked and pushed: the endpoint knows
	h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("garbage"))})

	if err := h.create("bob"); err == nil || !strings.Contains(err.Error(), "store restore") {
		t.Fatalf("create on a damaged store: err = %v, want a hint to restore", err)
	}
	if _, err := restore(h, good, true); err == nil || !strings.Contains(err.Error(), "--yes is not accepted") {
		t.Fatalf("with --yes: err = %v", err)
	}
	out, err := restore(h, good, false)
	if err == nil || (!strings.Contains(err.Error(), "not a terminal") && !strings.Contains(err.Error(), "aborted")) {
		t.Fatalf("without --yes: err = %v", err)
	}
	for _, want := range []string{"current version is unusable", "max", "connect again"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if got, _ := h.s3.Object("cvpnctl/pki.tar.gz"); string(got) != "garbage" {
		t.Error("the archive changed although the restore was refused")
	}
	if _, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg); held {
		t.Error("the lock was left behind")
	}
}

// What restore does once confirmed: a Recover workspace on a damaged archive
// takes the good version and replaces exactly the damaged one.
func TestRecoverWorkspaceReplacesDamaged(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	good := h.version()
	h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("garbage"))})

	cfg, err := config.Load(h.opts.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := store.Open(context.Background(), cfg, store.Recover, store.Deps{S3: h.s3, Caller: testCaller, Command: "store restore"})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(context.Background())
	if ws.Damaged() == nil {
		t.Fatal("Damaged() = nil for a garbage archive")
	}
	target, cleanup, err := unpackVersion(context.Background(), h.s3, storeCfg, good)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := replaceWorkspace(ws, target); err != nil {
		t.Fatal(err)
	}
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if !h.exists(filepath.Join(h.storedCopy(), "pki", "issued", "max.crt")) {
		t.Error("the restored archive lacks max")
	}
}

// Restore writes, so its lock (and the archive it saves) must name the admin.
func TestRestoreLockNamesCaller(t *testing.T) {
	h := newHarnessS3(t)
	cfg, err := config.Load(h.opts.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := h.opts.openWorkspace(context.Background(), cfg, store.Recover, "store restore")
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(context.Background())
	info, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg)
	if !held || info.ARN != testCaller {
		t.Errorf("lock = %+v, want it to name %s", info, testCaller)
	}
}

// The current archive was deleted: restore still opens the store and warns
// that it can only compare the endpoint's CRL.
func TestRestoreDeletedCurrent(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("max"))
	good := h.version()
	h.s3.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz")})

	if err := h.create("bob"); !errors.Is(err, store.ErrStoreDeleted) {
		t.Fatalf("create: err = %v, want ErrStoreDeleted", err)
	}
	out, err := restore(h, good, false)
	if err == nil || (!strings.Contains(err.Error(), "not a terminal") && !strings.Contains(err.Error(), "aborted")) {
		t.Fatalf("restore: err = %v, want it to stop at the typed confirmation", err)
	}
	if !strings.Contains(out, "no current archive") {
		t.Errorf("no warning about the deleted archive:\n%s", out)
	}
}
