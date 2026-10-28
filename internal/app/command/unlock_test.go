package command

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// holdLock takes the store's lock as another admin, started age ago.
func (h *harness) holdLock(age time.Duration) {
	h.t.Helper()
	info := store.LockInfo{ARN: "arn:aws:iam::111122223333:user/nils", Host: "nils-mbp", PID: 4242, Command: "renew bob", Started: time.Now().Add(-age).UTC()}
	if _, err := store.Acquire(context.Background(), h.s3, storeCfg, info); err != nil {
		h.t.Fatal(err)
	}
}

func TestUnlock(t *testing.T) {
	h := newHarnessS3(t)
	h.holdLock(3 * time.Hour)
	out, err := captureStdout(t, func() error { return runUnlock(context.Background(), h.opts, true) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"user/nils", "nils-mbp", "renew bob", "3h"} {
		if !strings.Contains(out, want) {
			t.Errorf("unlock output lacks %q:\n%s", want, out)
		}
	}
	if _, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg); held {
		t.Error("lock still held after unlock")
	}
	h.must(h.create("alice")) // the store is usable again
}

func TestUnlockAsksFirst(t *testing.T) {
	h := newHarnessS3(t)
	h.holdLock(time.Hour)
	if err := runUnlock(context.Background(), h.opts, false); err == nil {
		t.Fatal("unlock without --yes and without a terminal went ahead")
	}
	if _, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg); !held {
		t.Error("the lock was removed without confirmation")
	}
}

func TestUnlockNoLock(t *testing.T) {
	h := newHarnessS3(t)
	out, err := captureStdout(t, func() error { return runUnlock(context.Background(), h.opts, true) })
	if err != nil || !strings.Contains(out, "no lock held") {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestUnlockLocalMode(t *testing.T) {
	h := newHarness(t)
	if err := runUnlock(context.Background(), h.opts, true); err == nil || !strings.Contains(err.Error(), "requires `store`") {
		t.Errorf("err = %v", err)
	}
}

func TestStatusS3Rows(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	out, err := h.status()
	wantStatus(t, out, err, false, "s3://b/cvpnctl/", "bucket", "versioning, KMS, public access blocked", "store", testCaller)
	if regexp.MustCompile(`(?m)^\s+\S+\s+lock\s`).MatchString(out) {
		t.Errorf("a lock row without a lock:\n%s", out)
	}
}

func TestStatusS3BadBucket(t *testing.T) {
	h := newHarnessS3(t)
	h.s3.Settings.Versioning = false
	out, err := h.status()
	wantStatus(t, out, err, true, "versioning is off")
}

func TestStatusShowsLock(t *testing.T) {
	h := newHarnessS3(t)
	h.holdLock(10 * time.Minute)
	out, err := h.status()
	wantStatus(t, out, err, false, "lock", "user/nils", "renew bob")
}

func TestStatusShowsOldLock(t *testing.T) {
	h := newHarnessS3(t)
	h.holdLock(2 * time.Hour)
	out, err := h.status()
	if !errors.Is(err, ErrNeedsAttention) || !strings.Contains(out, "cvpnctl unlock") {
		t.Errorf("a 2-hour-old lock: err=%v\n%s", err, out)
	}
}

// A revoke whose lock is forced right after its checkpoint, while another
// admin revokes bob and pushes: the stale revoke must not push its older CRL,
// which would let bob back in.
func TestStaleCommandDoesNotPushCRL(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	h.must(h.create("bob"))
	pushes := 0
	h.cloud.onPush = func(map[string]bool) { pushes++ }

	fired := false
	h.s3.AfterPut = func(key string) {
		if fired || !strings.HasSuffix(key, "pki.tar.gz") {
			return
		}
		fired = true
		if err := forceUnlock(t, h.s3); err != nil {
			t.Error(err)
		}
		if _, err := store.Acquire(context.Background(), h.s3, storeCfg, store.LockInfo{ARN: "nils"}); err != nil {
			t.Error(err)
		}
		h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String(key), Body: bytes.NewReader([]byte("nils revoked bob"))})
	}

	err := h.revoke("alice")
	if err == nil || !strings.Contains(err.Error(), "not pushed") || !strings.Contains(err.Error(), "push-crl") {
		t.Fatalf("err = %v, want a refused push that says to run push-crl", err)
	}
	if pushes != 0 {
		t.Errorf("%d CRL pushes after the lock was forced, want 0", pushes)
	}
}

// forceUnlock removes whatever lock is held now, as cvpnctl unlock does.
func forceUnlock(t *testing.T, f *storetest.FakeS3) error {
	t.Helper()
	held, ok, err := store.ReadLock(context.Background(), f, storeCfg)
	if err != nil || !ok {
		t.Fatalf("no lock to remove: %v", err)
	}
	return store.ForceUnlock(context.Background(), f, storeCfg, held.ETag)
}
