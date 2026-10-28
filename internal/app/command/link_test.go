package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aartinian/cvpnctl/internal/store"
)

// stubPresigner returns https://example.test/<key> and records the expiry.
type stubPresigner struct {
	expires    time.Duration
	credsUntil time.Time // zero: credentials that don't expire
}

func (p *stubPresigner) PresignGetObject(_ context.Context, in *s3.GetObjectInput, opts ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	var o s3.PresignOptions
	for _, f := range opts {
		f(&o)
	}
	p.expires = o.Expires
	return &v4.PresignedHTTPRequest{URL: "https://example.test/" + aws.ToString(in.Key), Method: "GET"}, nil
}

// credsUntil makes the stub sign with credentials that expire at until.
func (p *stubPresigner) CredentialsExpire(context.Context) (time.Time, bool, error) {
	return p.credsUntil, !p.credsUntil.IsZero(), nil
}

// captureStderr runs fn and returns what it printed to stderr.
func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	runErr := fn()
	os.Stderr = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// captureStdout runs fn and returns what it printed to stdout.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// links returns the delivery objects currently in the bucket.
func (h *harness) links() []string {
	h.t.Helper()
	out, _ := h.s3.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String("b"), Prefix: aws.String("cvpnctl/delivery/")})
	var ks []string
	for _, o := range out.Contents {
		ks = append(ks, aws.ToString(o.Key))
	}
	return ks
}

var linkURL = regexp.MustCompile(`https://example\.test/cvpnctl/delivery/alice-[0-9a-f]{32}\.ovpn`)

func TestCreatePrintsLink(t *testing.T) {
	h := newHarnessS3(t)
	out, err := captureStdout(t, func() error { return h.create("alice") })
	if err != nil {
		t.Fatal(err)
	}
	if !linkURL.MatchString(out) || !strings.Contains(out, "link valid until") || !strings.Contains(out, "directly; it contains their private key") {
		t.Errorf("output lacks the link or its notes:\n%s", out)
	}
	ls := h.links()
	if len(ls) != 1 {
		t.Fatalf("links = %v, want one", ls)
	}
	body, _ := h.s3.Object(ls[0])
	if !strings.Contains(string(body), "# alice") || !strings.Contains(string(body), "BEGIN PRIVATE KEY") {
		t.Errorf("published .ovpn is not alice's:\n%s", body)
	}
	if h.presign.expires != 24*time.Hour {
		t.Errorf("link valid for %v, want the configured 24h", h.presign.expires)
	}
	if l := h.leftovers(); len(l) != 0 {
		t.Errorf("temp folders left: %v", l)
	}
}

func TestRenewReplacesLink(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	before := h.links()
	h.must(h.renew("alice"))
	after := h.links()
	if len(after) != 1 || after[0] == before[0] {
		t.Errorf("links before %v, after %v: want one new link", before, after)
	}
}

func TestRevokeDeletesLink(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	h.must(h.revoke("alice"))
	if ls := h.links(); len(ls) != 0 {
		t.Errorf("links after revoke: %v", ls)
	}
}

func TestLinkReissues(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	serial, before := h.serial("alice"), h.links()

	out, err := captureStdout(t, func() error { return runLink(context.Background(), h.opts, "alice", 48) })
	if err != nil {
		t.Fatal(err)
	}
	if !linkURL.MatchString(out) {
		t.Errorf("no link printed:\n%s", out)
	}
	if after := h.links(); len(after) != 1 || after[0] == before[0] {
		t.Errorf("links before %v, after %v: want one new link", before, after)
	}
	if h.serial("alice") != serial || len(h.cloud.certs) != 1 {
		t.Error("link changed the certificate; it must only re-issue the link")
	}
	if h.presign.expires != 48*time.Hour {
		t.Errorf("--link-hours 48 gave %v", h.presign.expires)
	}
	if _, held, _ := store.ReadLock(context.Background(), h.s3, storeCfg); held {
		t.Error("link left a lock")
	}
}

// Review focus: link for someone who doesn't exist, or whose certificate is gone.
func TestLinkUnknownUser(t *testing.T) {
	h := newHarnessS3(t)
	err := runLink(context.Background(), h.opts, "nobody", 0)
	if err == nil || !strings.Contains(err.Error(), `user "nobody" not found`) {
		t.Errorf("err = %v", err)
	}
	if ls := h.links(); len(ls) != 0 {
		t.Errorf("a link was published: %v", ls)
	}
}

func TestLinkMissingCertificate(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	before := h.links()

	// Remove alice's certificate from the stored PKI behind cvpnctl's back.
	dir := h.storedCopy()
	if err := os.Remove(filepath.Join(dir, "pki", "issued", "alice.crt")); err != nil {
		t.Fatal(err)
	}
	data, err := store.Pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(data)})

	err = runLink(context.Background(), h.opts, "alice", 0)
	if err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("err = %v, want a missing-certificate error", err)
	}
	if after := h.links(); len(after) != 1 || after[0] != before[0] {
		t.Errorf("links changed: %v → %v", before, after)
	}
}

func TestLinkLocalMode(t *testing.T) {
	h := newHarness(t)
	err := runLink(context.Background(), h.opts, "alice", 0)
	if err == nil || !strings.Contains(err.Error(), "requires `store` in the config") {
		t.Errorf("err = %v", err)
	}
}

func TestLinkHoursRange(t *testing.T) {
	h := newHarnessS3(t)
	for _, hours := range []int{169, -1} {
		if err := runCreate(context.Background(), h.opts, "alice", hours); err == nil || !strings.Contains(err.Error(), "link_hours must be 1–168") {
			t.Errorf("--link-hours %d: err = %v", hours, err)
		}
	}
	if len(h.cloud.certs) != 0 {
		t.Error("an invalid --link-hours still created a certificate")
	}
	local := newHarness(t)
	if err := runCreate(context.Background(), local.opts, "alice", 12); err == nil || !strings.Contains(err.Error(), "requires `store`") {
		t.Errorf("--link-hours in local mode: err = %v", err)
	}
}

// link takes the lock: otherwise a link running alongside a renew could
// publish the revoked certificate over the new link.
func TestLinkTakesLock(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	h.holdLock(time.Minute)
	var locked *store.LockedError
	if err := runLink(context.Background(), h.opts, "alice", 0); !errors.As(err, &locked) {
		t.Fatalf("link while the lock is held: err = %v, want *LockedError", err)
	}
}

// Signed with an SSO session that ends in 2 hours: the link is reported as
// ending then, with a warning, instead of the 24 hours asked for.
func TestLinkWarnsWhenCredentialsExpireFirst(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	h.presign.credsUntil = time.Now().Add(2 * time.Hour)

	errOut, err := captureStderr(t, func() error {
		_, err := captureStdout(t, func() error { return runLink(context.Background(), h.opts, "alice", 24) })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "credentials expire") || !strings.Contains(errOut, "not after 24 h") {
		t.Errorf("no warning about the shorter link:\n%s", errOut)
	}
}
