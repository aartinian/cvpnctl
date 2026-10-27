package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/delivery"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/provider"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const testCaller = "arn:aws:iam::111122223333:user/ari"

// newHarnessS3 is newHarness in S3 mode: the same throwaway PKI, packed into
// a fake bucket, and a config with a store section instead of local paths.
func newHarnessS3(t *testing.T) *harness {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	h := newHarness(t) // builds the PKI and template in h.dir
	h.s3 = storetest.New()

	staging := t.TempDir()
	if err := os.Rename(h.pki, filepath.Join(staging, "pki")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(staging, "template"), 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl, _ := os.ReadFile(filepath.Join(h.dir, "base.ovpn"))
	if err := os.WriteFile(filepath.Join(staging, "template", "base.ovpn"), tmpl, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := store.Pack(staging)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(data)}); err != nil {
		t.Fatal(err)
	}

	cfg := fmt.Sprintf(`
easyrsa:
  path: %s
store:
  bucket: b
  prefix: cvpnctl
  kms_key_id: alias/cvpnctl
aws:
  region: eu-central-1
  vpn_endpoint_id: cvpn-endpoint-test
`, findEasyRSA(t))
	if err := os.WriteFile(h.opts.ConfigFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	h.opts.NewS3 = func(context.Context, *config.Config) (store.S3API, func(context.Context) (string, error), error) {
		return h.s3, func(context.Context) (string, error) { return testCaller, nil }, nil
	}
	h.presign = &stubPresigner{}
	h.opts.NewPresigner = func(context.Context, *config.Config) (delivery.Presigner, error) { return h.presign, nil }
	return h
}

// leftovers returns cvpnctl temp folders still in TMPDIR.
func (h *harness) leftovers() []string {
	m, _ := filepath.Glob(filepath.Join(os.TempDir(), "cvpnctl-*"))
	return m
}

func TestS3Lifecycle(t *testing.T) {
	h := newHarnessS3(t)
	check := func(after string) {
		t.Helper()
		if l := h.leftovers(); len(l) != 0 {
			t.Errorf("after %s: temp folders left: %v", after, l)
		}
		if _, held, _ := store.ReadLock(context.Background(), h.s3, config.StoreConfig{Bucket: "b", Prefix: "cvpnctl/"}); held {
			t.Errorf("after %s: lock left behind", after)
		}
		for _, d := range []string{h.certsDir(), h.clientsDir()} {
			if h.exists(d) {
				t.Errorf("after %s: %s exists; S3 mode must leave nothing on disk", after, d)
			}
		}
	}

	h.must(h.create("alice"))
	first := h.serial("alice")
	check("create")
	if r, ok := h.record("alice"); !ok || r.ProviderID != "cert-1" {
		t.Fatalf("stored state after create = %+v, %v", r, ok)
	}
	if h.cloud.certs["cert-1"] != first {
		t.Errorf("provider holds %v, want cert-1 with serial %s", h.cloud.certs, first)
	}

	h.must(h.renew("alice"))
	second := h.serial("alice")
	check("renew")
	if second == first {
		t.Fatal("renew did not issue a new certificate")
	}
	if r, _ := h.record("alice"); r.ProviderID != "cert-2" {
		t.Errorf("stored state after renew points at %s, want cert-2", r.ProviderID)
	}
	if !h.cloud.revoked[first] || h.cloud.revoked[second] {
		t.Errorf("CRL after renew = %v, want %s revoked and %s not", h.cloud.revoked, first, second)
	}

	h.must(h.revoke("alice"))
	check("revoke")
	if len(h.cloud.certs) != 0 || !h.cloud.revoked[second] {
		t.Errorf("after revoke: provider %v, CRL %v", h.cloud.certs, h.cloud.revoked)
	}
	if _, ok := h.record("alice"); ok {
		t.Error("alice still in the stored state after revoke")
	}

	h.must(runPushCRL(context.Background(), h.opts))
	check("push-crl")
	h.must(h.create("alice"))
	check("second create")
}

// The core rule of S3 mode: a CRL is pushed only after a checkpoint that
// already holds every revocation in it, so S3 is never behind the endpoint.
func TestS3CRLNeverAheadOfStore(t *testing.T) {
	h := newHarnessS3(t)
	pushes := 0
	h.cloud.onPush = func(pushed map[string]bool) {
		pushes++
		stored, err := easyrsa.New(&config.EasyRSAConfig{PKIDir: h.pkiDir()}, false).RevokedSerials()
		if err != nil {
			t.Fatal(err)
		}
		for serial := range pushed {
			if !stored[easyrsa.NormSerial(serial)] {
				t.Errorf("CRL push %d revokes %s, which the archive in S3 doesn't have as revoked yet", pushes, serial)
			}
		}
	}
	h.must(h.create("alice"))
	h.must(h.create("bob"))
	h.must(h.renew("alice"))
	h.must(h.revoke("bob"))
	h.must(runPushCRL(context.Background(), h.opts))
	if pushes != 3 {
		t.Errorf("%d CRL pushes, want 3 (renew, revoke, push-crl)", pushes)
	}
}

// Someone else writes the archive after our ACM import: our checkpoint is
// refused, and the certificate we imported is deleted from ACM again, so ACM
// never holds a certificate the stored state doesn't know about.
func TestS3CheckpointRejectedRollsBackACM(t *testing.T) {
	h := newHarnessS3(t)
	other := []byte("another admin's archive")
	h.cloud.afterImport = func() {
		h.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(other)})
	}

	err := h.create("alice")
	if !errors.Is(err, store.ErrStoreChanged) {
		t.Fatalf("err = %v, want ErrStoreChanged", err)
	}
	if len(h.cloud.certs) != 0 {
		t.Errorf("ACM still holds %v after the failed checkpoint", h.cloud.certs)
	}
	if got, _ := h.s3.Object("cvpnctl/pki.tar.gz"); !bytes.Equal(got, other) {
		t.Error("the other admin's archive was overwritten")
	}
	if l := h.leftovers(); len(l) != 0 {
		t.Errorf("temp folders left: %v", l)
	}
}

func TestS3SecondAdminLocked(t *testing.T) {
	h := newHarnessS3(t)
	cfg, err := config.Load(h.opts.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := store.Open(context.Background(), cfg, store.Write, store.Deps{S3: h.s3, Caller: "arn:aws:iam::111122223333:user/nils", Host: "nils-mbp", Command: "revoke bob"})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(context.Background())

	var locked *store.LockedError
	if err := h.create("alice"); !errors.As(err, &locked) || locked.Info.Host != "nils-mbp" {
		t.Fatalf("err = %v, want *LockedError naming nils-mbp", err)
	}
	if len(h.cloud.certs) != 0 {
		t.Error("a certificate was imported although the lock was held")
	}
}

// list reads the store without AWS credentials for the provider.
func TestS3List(t *testing.T) {
	h := newHarnessS3(t)
	h.must(h.create("alice"))
	h.opts.NewProvider = func(context.Context, *config.Config) (provider.CertStore, error) {
		t.Error("list created a provider")
		return nil, errors.New("no")
	}
	h.must(runList(h.opts))
	if l := h.leftovers(); len(l) != 0 {
		t.Errorf("temp folders left after list: %v", l)
	}
}

var _ = time.Second

var storeCfg = config.StoreConfig{Bucket: "b", Prefix: "cvpnctl/"}
