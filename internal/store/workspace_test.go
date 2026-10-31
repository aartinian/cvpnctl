package store

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3Env returns an S3-mode config, a fake bucket that already holds an
// archive with a CA, a state file and a template, and a private TMPDIR.
func s3Env(t *testing.T) (*config.Config, *storetest.FakeS3) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "pki/ca.crt"), "CA")
	writeFile(t, filepath.Join(src, "pki/index.txt"), "")
	writeFile(t, filepath.Join(src, "state/.cvpnctl-state.json"), "{}")
	writeFile(t, filepath.Join(src, "template/base.ovpn"), "client")
	data, err := Pack(src)
	if err != nil {
		t.Fatal(err)
	}
	f := storetest.New()
	if _, err := f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(data)}); err != nil {
		t.Fatal(err)
	}
	st := testStore
	return &config.Config{Store: &st}, f
}

func deps(f *storetest.FakeS3, command string) Deps {
	return Deps{S3: f, Caller: "arn:aws:iam::111122223333:user/ari", Host: "ari-mbp", Command: command}
}

// tempDirs lists the cvpnctl temp folders currently in TMPDIR.
func tempDirs(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(os.TempDir(), "cvpnctl-*"))
	return m
}

func TestLocalWorkspacePassThrough(t *testing.T) {
	cfg := &config.Config{
		EasyRSA: config.EasyRSAConfig{PKIDir: "/p/pki"},
		Certs:   config.CertsConfig{OutputDir: "/p/certs"},
		OVPN:    config.OVPNConfig{Template: "/p/base.ovpn", OutputDir: "/p/clients"},
	}
	ws, err := Open(context.Background(), cfg, Write, Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if ws.PKIDir() != "/p/pki" || ws.StateDir() != "/p/certs" || ws.TemplatePath() != "/p/base.ovpn" || ws.OutDir() != "/p/clients" || ws.Remote() || ws.Version() != "" {
		t.Errorf("local workspace = %s %s %s %s remote=%v version=%q", ws.PKIDir(), ws.StateDir(), ws.TemplatePath(), ws.OutDir(), ws.Remote(), ws.Version())
	}
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Errorf("local Checkpoint: %v", err)
	}
	if err := ws.Close(context.Background()); err != nil {
		t.Errorf("local Close: %v", err)
	}
}

func TestOpenWriteDownloadsAndLocks(t *testing.T) {
	cfg, f := s3Env(t)
	ws, err := Open(context.Background(), cfg, Write, deps(f, "create max"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ws.Close(context.Background())

	if !ws.Remote() || ws.Version() == "" {
		t.Errorf("remote=%v version=%q", ws.Remote(), ws.Version())
	}
	if _, err := os.Stat(filepath.Join(ws.PKIDir(), "ca.crt")); err != nil {
		t.Errorf("PKI not unpacked: %v", err)
	}
	if got, _ := os.ReadFile(ws.TemplatePath()); string(got) != "client" {
		t.Errorf("template = %q", got)
	}
	if _, err := os.Stat(filepath.Join(ws.StateDir(), ".cvpnctl-state.json")); err != nil {
		t.Errorf("state not unpacked: %v", err)
	}
	if fi, err := os.Stat(ws.OutDir()); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("OutDir = %v, %v", fi, err)
	}
	if !strings.HasPrefix(ws.PKIDir(), os.TempDir()) {
		t.Errorf("PKI at %s, want it under TMPDIR %s", ws.PKIDir(), os.TempDir())
	}
	lock, held, _ := ReadLock(context.Background(), f, testStore)
	if !held || lock.Command != "create max" || lock.Host != "ari-mbp" {
		t.Errorf("lock = %+v, held=%v", lock, held)
	}
}

func TestReadModeNoLock(t *testing.T) {
	cfg, f := s3Env(t)
	ws, err := Open(context.Background(), cfg, Read, deps(f, "list"))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(context.Background())
	if _, held, _ := ReadLock(context.Background(), f, testStore); held {
		t.Error("Read mode took the lock")
	}
	if err := ws.Checkpoint(context.Background()); err == nil {
		t.Error("Checkpoint in Read mode succeeded")
	}
}

func TestOpenEmptyStore(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	st := testStore
	f := storetest.New()
	_, err := Open(context.Background(), &config.Config{Store: &st}, Write, deps(f, "create max"))
	if !errors.Is(err, ErrStoreEmpty) || err.Error() != "store is empty; run cvpnctl store migrate" {
		t.Fatalf("err = %v, want ErrStoreEmpty with the exact message", err)
	}
	if _, held, _ := ReadLock(context.Background(), f, testStore); held {
		t.Error("the lock was left behind")
	}
	if d := tempDirs(t); len(d) != 0 {
		t.Errorf("temp folders left behind: %v", d)
	}
}

func TestOpenRejectsArchiveWithoutCA(t *testing.T) {
	cfg, f := s3Env(t)
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "pki/index.txt"), "")
	data, _ := Pack(src)
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(data)})

	_, err := Open(context.Background(), cfg, Write, deps(f, "create max"))
	if err == nil || !strings.Contains(err.Error(), "ca.crt") {
		t.Fatalf("err = %v, want a missing ca.crt error", err)
	}
	if _, held, _ := ReadLock(context.Background(), f, testStore); held {
		t.Error("the lock was left behind")
	}
	if d := tempDirs(t); len(d) != 0 {
		t.Errorf("temp folders left behind: %v", d)
	}
}

func TestSecondWriteRefused(t *testing.T) {
	cfg, f := s3Env(t)
	first, err := Open(context.Background(), cfg, Write, deps(f, "create max"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())

	_, err = Open(context.Background(), cfg, Write, deps(f, "revoke bob"))
	var locked *LockedError
	if !errors.As(err, &locked) || locked.Info.Command != "create max" {
		t.Fatalf("err = %v, want *LockedError naming the first command", err)
	}
	if d := tempDirs(t); len(d) != 1 {
		t.Errorf("temp folders = %v, want only the first command's", d)
	}
}

// stored unpacks the current archive in the fake bucket and returns the
// content of one file in it.
func stored(t *testing.T, f *storetest.FakeS3, name string) string {
	t.Helper()
	data, ok := f.Object("cvpnctl/pki.tar.gz")
	if !ok {
		t.Fatal("no archive in the bucket")
	}
	dir := t.TempDir()
	if err := Unpack(data, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "(missing)"
	}
	return string(b)
}

func openWrite(t *testing.T) (Workspace, *storetest.FakeS3) {
	t.Helper()
	cfg, f := s3Env(t)
	ws, err := Open(context.Background(), cfg, Write, deps(f, "create max"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close(context.Background()) })
	return ws, f
}

func TestCheckpointChains(t *testing.T) {
	ws, f := openWrite(t)
	before := ws.Version()
	index := filepath.Join(ws.PKIDir(), "index.txt")

	os.WriteFile(index, []byte("V\tmax"), 0o600)
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("first checkpoint: %v", err)
	}
	first := ws.Version()
	os.WriteFile(index, []byte("V\tmax\nR\tbob"), 0o600)
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("second checkpoint (chained on the first): %v", err)
	}
	if ws.Version() == first || first == before {
		t.Errorf("versions did not advance: %s, %s, %s", before, first, ws.Version())
	}
	if got := stored(t, f, "pki/index.txt"); got != "V\tmax\nR\tbob" {
		t.Errorf("stored index.txt = %q", got)
	}
	head, _ := f.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz")})
	if head.Metadata["cvpnctl-arn"] != "arn:aws:iam::111122223333:user/ari" {
		t.Errorf("metadata = %v, want cvpnctl-arn of the caller", head.Metadata)
	}
}

func TestCheckpointExcludesOut(t *testing.T) {
	ws, f := openWrite(t)
	os.WriteFile(filepath.Join(ws.OutDir(), "max.ovpn"), []byte("secret"), 0o600)
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := stored(t, f, "out/max.ovpn"); got != "(missing)" {
		t.Error("a rendered .ovpn was uploaded into the archive")
	}
}

// Someone else wrote the archive in between (e.g. after a forced unlock).
func TestCheckpointStale(t *testing.T) {
	ws, f := openWrite(t)
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("other"))})

	if err := ws.Checkpoint(context.Background()); !errors.Is(err, ErrStoreChanged) {
		t.Fatalf("err = %v, want ErrStoreChanged", err)
	}
	if got, _ := f.Object("cvpnctl/pki.tar.gz"); string(got) != "other" {
		t.Error("the other writer's archive was overwritten")
	}
}

// The response was lost, but S3 stored the archive: the checksum proves it,
// so the checkpoint counts as done and the next one chains on it.
func TestCheckpointAmbiguousLanded(t *testing.T) {
	ws, f := openWrite(t)
	os.WriteFile(filepath.Join(ws.PKIDir(), "index.txt"), []byte("landed"), 0o600)
	f.FailNextPut(errors.New("connection reset"), true)

	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("err = %v, want success (the upload landed)", err)
	}
	if got := stored(t, f, "pki/index.txt"); got != "landed" {
		t.Errorf("stored = %q", got)
	}
	os.WriteFile(filepath.Join(ws.PKIDir(), "index.txt"), []byte("next"), 0o600)
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("next checkpoint: %v (the landed version's ETag was not adopted)", err)
	}
}

// The upload really failed: the checkpoint fails, so the caller rolls back.
func TestCheckpointAmbiguousLost(t *testing.T) {
	ws, f := openWrite(t)
	os.WriteFile(filepath.Join(ws.PKIDir(), "index.txt"), []byte("lost"), 0o600)
	f.FailNextPut(errors.New("connection reset"), false)

	err := ws.Checkpoint(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not reach S3") || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("err = %v, want a 'did not reach S3' error with the cause", err)
	}
	if got := stored(t, f, "pki/index.txt"); got != "" {
		t.Errorf("stored index.txt = %q, want the original (empty)", got)
	}
}

// The response was lost and the SDK's retry got 412 against the upload that
// landed: the checksum shows the archive is ours, so this is no conflict.
func TestCheckpointRetryAfterLanding(t *testing.T) {
	ws, f := openWrite(t)
	os.WriteFile(filepath.Join(ws.PKIDir(), "index.txt"), []byte("landed"), 0o600)
	f.FailNextPut(storetest.APIError("PutObject", http.StatusPreconditionFailed, "PreconditionFailed"), true)

	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("err = %v, want success (the upload landed)", err)
	}
	os.WriteFile(filepath.Join(ws.PKIDir(), "index.txt"), []byte("next"), 0o600)
	if err := ws.Checkpoint(context.Background()); err != nil {
		t.Fatalf("next checkpoint: %v", err)
	}
}

// Neither the upload nor the check afterwards answered: the outcome is
// unknown, which the caller must be able to tell from a plain failure.
func TestCheckpointUnknown(t *testing.T) {
	ws, f := openWrite(t)
	os.WriteFile(filepath.Join(ws.PKIDir(), "index.txt"), []byte("maybe"), 0o600)
	f.FailNextPut(errors.New("connection reset"), true)
	f.FailNextHead(errors.New("timeout"))

	err := ws.Checkpoint(context.Background())
	if !errors.Is(err, ErrUploadUnknown) || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("err = %v, want ErrUploadUnknown with the cause", err)
	}
}

// A garbage archive: Write refuses it with a hint to restore; Recover opens
// an empty workspace under the lock, and its checkpoint replaces only the
// damaged version.
func TestOpenDamaged(t *testing.T) {
	cfg, f := s3Env(t)
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("garbage"))})

	if _, err := Open(context.Background(), cfg, Write, deps(f, "create max")); err == nil || !strings.Contains(err.Error(), "store restore") {
		t.Fatalf("Write: err = %v, want a hint to restore", err)
	}
	ws, err := Open(context.Background(), cfg, Recover, deps(f, "store restore"))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer ws.Close(context.Background())
	if ws.Damaged() == nil {
		t.Error("Damaged() = nil")
	}
	if _, held, _ := ReadLock(context.Background(), f, testStore); !held {
		t.Error("Recover does not hold the lock")
	}
	if entries, _ := os.ReadDir(ws.PKIDir()); len(entries) != 0 {
		t.Errorf("PKI dir holds %d entries, want empty", len(entries))
	}

	// Someone writes in between (after a forced unlock): the restore must
	// not overwrite it.
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("newer"))})
	writeFile(t, filepath.Join(ws.PKIDir(), "ca.crt"), "CA")
	if err := ws.Checkpoint(context.Background()); !errors.Is(err, ErrStoreChanged) {
		t.Errorf("Checkpoint over a newer version: err = %v, want ErrStoreChanged", err)
	}
}

func TestVerify(t *testing.T) {
	ws, f := openWrite(t)
	if err := ws.Verify(context.Background()); err != nil {
		t.Fatalf("fresh workspace: %v", err)
	}

	// The archive was overwritten behind our back.
	f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader([]byte("newer"))})
	if err := ws.Verify(context.Background()); !errors.Is(err, ErrStoreChanged) {
		t.Errorf("archive changed: err = %v, want ErrStoreChanged", err)
	}

	// The lock was forced and taken by someone else.
	if err := forceUnlock(t, f); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(context.Background(), f, testStore, LockInfo{ARN: "nils"}); err != nil {
		t.Fatal(err)
	}
	if err := ws.Verify(context.Background()); !errors.Is(err, ErrLockLost) {
		t.Errorf("lock taken over: err = %v, want ErrLockLost", err)
	}
}

func TestCloseRemovesTempAndLock(t *testing.T) {
	cfg, f := s3Env(t)
	ws, err := Open(context.Background(), cfg, Write, deps(f, "create max"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := tempDirs(t); len(d) != 0 {
		t.Errorf("temp folders left: %v", d)
	}
	if _, held, _ := ReadLock(context.Background(), f, testStore); held {
		t.Error("lock left behind")
	}
	if err := ws.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// After Ctrl-C the command's context is cancelled; Close must still clean up.
func TestCloseAfterCancelledContext(t *testing.T) {
	cfg, f := s3Env(t)
	ctx, cancel := context.WithCancel(context.Background())
	ws, err := Open(ctx, cfg, Write, deps(f, "create max"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := ws.Close(ctx); err != nil {
		t.Fatalf("Close after cancel: %v", err)
	}
	if d := tempDirs(t); len(d) != 0 {
		t.Errorf("temp folders left: %v", d)
	}
	if _, held, _ := ReadLock(context.Background(), f, testStore); held {
		t.Error("lock left behind after Ctrl-C")
	}
}

// If someone force-unlocked meanwhile, Close only warns, and leaves the new
// holder's lock alone.
func TestCloseAfterLockLost(t *testing.T) {
	cfg, f := s3Env(t)
	ws, _ := Open(context.Background(), cfg, Write, deps(f, "create max"))
	forceUnlock(t, f)
	other, _ := Acquire(context.Background(), f, testStore, info("nils"))

	if err := ws.Close(context.Background()); err != nil {
		t.Errorf("Close with a lost lock: %v, want only a warning", err)
	}
	if lock, held, _ := ReadLock(context.Background(), f, testStore); !held || lock.Host != "nils-mbp" {
		t.Error("the other admin's lock was removed")
	}
	other.Release(context.Background())
}

func mkTemp(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(p, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestSweepOnlyOwnStale(t *testing.T) {
	dir := t.TempDir()
	stale := mkTemp(t, dir, "cvpnctl-111", 2*time.Hour)
	fresh := mkTemp(t, dir, "cvpnctl-222", 10*time.Minute)
	other := mkTemp(t, dir, "something-else", 2*time.Hour)

	Sweep(dir, os.Getuid()+1, time.Hour) // another OS user's sweep must not touch ours
	if !exists(stale) {
		t.Fatal("a sweep for another user removed our folder")
	}

	Sweep(dir, os.Getuid(), time.Hour)
	if exists(stale) {
		t.Error("stale cvpnctl folder was kept")
	}
	if !exists(fresh) {
		t.Error("a folder younger than an hour was removed (it may belong to a running command)")
	}
	if !exists(other) {
		t.Error("a folder not named cvpnctl-* was removed")
	}
}

// A crashed run's leftovers are removed by the next S3 command.
func TestOpenSweepsLeftovers(t *testing.T) {
	cfg, f := s3Env(t)
	leftover := mkTemp(t, os.TempDir(), "cvpnctl-crashed", 3*time.Hour)
	ws, err := Open(context.Background(), cfg, Read, deps(f, "list"))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(context.Background())
	if exists(leftover) {
		t.Error("a crashed run's temp folder was not swept")
	}
}

// A command waiting at a passphrase prompt for over an hour is still alive;
// a `cvpnctl list` in another terminal must not delete its workspace.
func TestSweepKeepsLiveProcess(t *testing.T) {
	dir := t.TempDir()
	alive := mkTemp(t, dir, "cvpnctl-alive", 2*time.Hour)
	os.WriteFile(filepath.Join(alive, ".pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	dead := mkTemp(t, dir, "cvpnctl-dead", 2*time.Hour)
	os.WriteFile(filepath.Join(dead, ".pid"), []byte("2147483646"), 0o600) // no such process
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(alive, old, old)
	os.Chtimes(dead, old, old)

	Sweep(dir, os.Getuid(), time.Hour)
	if !exists(alive) {
		t.Error("the workspace of a running process was swept")
	}
	if exists(dead) {
		t.Error("the workspace of a dead process was kept")
	}
}

func TestWorkspaceRecordsPID(t *testing.T) {
	ws, _ := openWrite(t)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(ws.PKIDir()), ".pid"))
	if err != nil || string(b) != strconv.Itoa(os.Getpid()) {
		t.Errorf(".pid = %q, %v", b, err)
	}
}

// Every cvpnctl-* folder records its process, so the sweep never removes one
// that is still in use, however old.
func TestTempDirRecordsPID(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir, err := TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(dir), "cvpnctl-") {
		t.Errorf("TempDir() = %s, want a cvpnctl-* folder", dir)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 700", fi.Mode().Perm())
	}
	old := time.Now().Add(-3 * time.Hour)
	os.Chtimes(dir, old, old)
	Sweep(os.TempDir(), os.Getuid(), time.Hour)
	if !exists(dir) {
		t.Error("the sweep removed a folder of a running process")
	}
}
