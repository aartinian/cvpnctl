package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/store"
)

// version returns the current archive version in the fake bucket.
func (h *harness) version() string {
	h.t.Helper()
	v, ok, err := store.Head(context.Background(), h.s3, storeCfg)
	if err != nil || !ok {
		h.t.Fatalf("no current version: %v", err)
	}
	return v
}

func restore(h *harness, version string, yes bool) (string, error) {
	return captureStdout(h.t, func() error { return runRestore(context.Background(), h.opts, version, yes) })
}

func TestVersionsLists(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
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

func TestVersionsDetails(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	h.must(h.create("bob"))
	out, err := captureStdout(t, func() error { return runVersions(context.Background(), h.opts, h.version()) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"alice", "bob", "0 revoked"} {
		if !strings.Contains(out, want) {
			t.Errorf("details lack %q:\n%s", want, out)
		}
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	withAlice := h.version()
	h.must(h.create("bob"))
	pushes := h.cloud.crlPushes

	out, err := restore(h, withAlice, true)
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "users removed") || !strings.Contains(out, "bob") {
		t.Errorf("restore didn't show that bob goes away:\n%s", out)
	}
	if _, ok := h.record("bob"); ok {
		t.Error("bob is still in the stored state")
	}
	if _, ok := h.record("alice"); !ok {
		t.Error("alice is missing from the stored state")
	}
	if h.version() == withAlice {
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
	h.must(h.create("alice"))
	before := h.version()
	h.must(h.revoke("alice")) // revoked and pushed
	archive, _ := h.s3.Object("cvpnctl/pki.tar.gz")

	_, err := restore(h, before, true)
	if err == nil || err.Error() != "--yes is not accepted when a restore would un-revoke certificates" {
		t.Fatalf("with --yes: err = %v", err)
	}
	// Without a terminal (or with stdin closed, as under go test) nobody can
	// type 'restore', so it aborts.
	out, err := restore(h, before, false)
	if err == nil || (!strings.Contains(err.Error(), "not a terminal") && !strings.Contains(err.Error(), "aborted")) {
		t.Fatalf("without --yes: err = %v", err)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "connect again") {
		t.Errorf("the warning doesn't name alice:\n%s", out)
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
