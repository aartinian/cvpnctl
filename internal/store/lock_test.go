package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
)

var testStore = config.StoreConfig{Bucket: "b", Prefix: "cvpnctl/", KMSKeyID: "alias/cvpnctl", LinkHours: 24}

func info(who string) LockInfo {
	return LockInfo{ARN: "arn:aws:iam::111122223333:user/" + who, Host: who + "-mbp", PID: 42, Command: "revoke bob", Started: time.Now().UTC()}
}

func init() { lockBackoff = time.Millisecond } // keep retry tests fast

func TestAcquireRelease(t *testing.T) {
	f := storetest.New()
	l, err := Acquire(context.Background(), f, testStore, info("ari"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	body, ok := f.Object("cvpnctl/lock")
	if !ok {
		t.Fatal("no lock object at cvpnctl/lock")
	}
	var got LockInfo
	if err := json.Unmarshal(body, &got); err != nil || got.Host != "ari-mbp" || got.Command != "revoke bob" {
		t.Errorf("lock body = %s (%v)", body, err)
	}
	for _, field := range []string{`"arn"`, `"host"`, `"pid"`, `"command"`, `"started"`} {
		if !strings.Contains(string(body), field) {
			t.Errorf("lock body lacks %s: %s", field, body)
		}
	}
	if err := l.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := f.Object("cvpnctl/lock"); ok {
		t.Error("lock still present after Release")
	}
}

func TestAcquireContended(t *testing.T) {
	f := storetest.New()
	first := info("nils")
	if _, err := Acquire(context.Background(), f, testStore, first); err != nil {
		t.Fatal(err)
	}
	_, err := Acquire(context.Background(), f, testStore, info("ari"))
	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("err = %v, want *LockedError", err)
	}
	want := "locked by arn:aws:iam::111122223333:user/nils on nils-mbp since " + first.Started.Local().Format("15:04") + " (revoke bob)"
	if err.Error() != want {
		t.Errorf("message:\n got %q\nwant %q", err.Error(), want)
	}
}

func TestLockedErrorShowsDateWhenNotToday(t *testing.T) {
	old := info("nils")
	old.Started = time.Now().Add(-72 * time.Hour)
	msg := (&LockedError{Info: old}).Error()
	if !strings.Contains(msg, old.Started.Local().Format("2006-01-02 15:04")) {
		t.Errorf("message for a lock from 3 days ago lacks its date: %q", msg)
	}
}

func TestAcquireRetriesConflict(t *testing.T) {
	f := storetest.New()
	f.ConflictNextPuts(2)
	if _, err := Acquire(context.Background(), f, testStore, info("ari")); err != nil {
		t.Fatalf("2 conflicts then success: %v", err)
	}

	g := storetest.New()
	g.ConflictNextPuts(4) // the first try and all 3 retries conflict
	if _, err := Acquire(context.Background(), g, testStore, info("ari")); err == nil {
		t.Fatal("4 conflicts: expected an error")
	}
}

func TestAcquireHonoursCancel(t *testing.T) {
	f := storetest.New()
	f.ConflictNextPuts(10)
	saved := lockBackoff
	lockBackoff = time.Hour // a cancel must not wait for this
	defer func() { lockBackoff = saved }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, err := Acquire(ctx, f, testStore, info("ari")); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Acquire kept waiting after its context was cancelled")
	}
}

func TestReleaseOnlyOwn(t *testing.T) {
	f := storetest.New()
	a, _ := Acquire(context.Background(), f, testStore, info("ari"))
	if err := ForceUnlock(context.Background(), f, testStore); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(context.Background(), f, testStore, info("nils")); err != nil {
		t.Fatal(err)
	}

	if err := a.Release(context.Background()); !errors.Is(err, ErrLockLost) {
		t.Errorf("Release of a lock taken over by someone else: err = %v, want ErrLockLost", err)
	}
	got, held, _ := ReadLock(context.Background(), f, testStore)
	if !held || got.Host != "nils-mbp" {
		t.Errorf("nils's lock was removed: held=%v info=%+v", held, got)
	}
}

func TestReadLock(t *testing.T) {
	f := storetest.New()
	if _, held, err := ReadLock(context.Background(), f, testStore); held || err != nil {
		t.Errorf("no lock: held=%v err=%v", held, err)
	}
	Acquire(context.Background(), f, testStore, info("ari"))
	got, held, err := ReadLock(context.Background(), f, testStore)
	if !held || err != nil || got.ARN != info("ari").ARN {
		t.Errorf("ReadLock = %+v, %v, %v", got, held, err)
	}
}

func TestForceUnlockWithoutLock(t *testing.T) {
	if err := ForceUnlock(context.Background(), storetest.New(), testStore); err != nil {
		t.Errorf("ForceUnlock with no lock: %v", err)
	}
}

// Admins starting at the same moment: exactly one gets the lock, every other
// one gets a *LockedError.
func TestAcquireConcurrent(t *testing.T) {
	f := storetest.New()
	const n = 20
	type result struct {
		lock *Lock
		err  error
	}
	results := make(chan result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			<-start
			l, err := Acquire(context.Background(), f, testStore, info(fmt.Sprintf("admin%d", i)))
			results <- result{l, err}
		}(i)
	}
	close(start)

	won := 0
	for i := 0; i < n; i++ {
		r := <-results
		var locked *LockedError
		switch {
		case r.err == nil:
			won++
		case !errors.As(r.err, &locked):
			t.Errorf("loser got %v, want *LockedError", r.err)
		}
	}
	if won != 1 {
		t.Errorf("%d admins got the lock, want exactly 1", won)
	}
}
