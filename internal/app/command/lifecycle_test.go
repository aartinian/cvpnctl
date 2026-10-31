package command

// These tests run the real commands against a throwaway EasyRSA PKI, with a
// fake in place of the cloud provider. They need EasyRSA 3.2.7 or later and
// are skipped when it is not installed; set CVPNCTL_TEST_EASYRSA to the
// directory containing the easyrsa script to point them at a specific copy.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/provider"
	"github.com/aartinian/cvpnctl/internal/state"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
)

// fakeCloud records what the commands send to the provider.
type fakeCloud struct {
	certs      map[string]string // provider ID → certificate serial (hex)
	revoked    map[string]bool   // serials in the most recently pushed CRL
	crlPushes  int
	nextID     int
	failImport bool
	failCRL    bool

	// For status: the endpoint's certificates (ID → expiry) and the CRL it
	// currently holds, as last pushed or as set by a test.
	endpointCerts map[string]time.Time
	crlPEM        []byte

	// Hooks for S3-mode tests: afterImport runs right after a successful
	// ImportCert; onPush gets the serials of every CRL being imported.
	afterImport func()
	onPush      func(revoked map[string]bool)
}

const (
	fakeServerID = "arn:fake:server"
	fakeRootID   = "arn:fake:client-root"
)

func (f *fakeCloud) EndpointCerts(context.Context) (string, string, error) {
	return fakeServerID, fakeRootID, nil
}

func (f *fakeCloud) CertInfo(_ context.Context, id string) (string, time.Time, bool, error) {
	if exp, ok := f.endpointCerts[id]; ok {
		return strings.TrimPrefix(id, "arn:fake:"), exp, true, nil
	}
	if _, ok := f.certs[id]; ok {
		return id, time.Now().AddDate(2, 0, 0), true, nil
	}
	return "", time.Time{}, false, nil
}

func (f *fakeCloud) ExportCRL(context.Context) ([]byte, error) {
	return f.crlPEM, nil
}

func (f *fakeCloud) ImportCert(_ context.Context, certFile, _, _ string) (string, error) {
	if f.failImport {
		return "", errors.New("fake: import refused")
	}
	cert, err := readCert(certFile)
	if err != nil {
		return "", err
	}
	f.nextID++
	id := fmt.Sprintf("cert-%d", f.nextID)
	f.certs[id] = cert.SerialNumber.Text(16)
	if f.afterImport != nil {
		f.afterImport()
	}
	return id, nil
}

func (f *fakeCloud) DeleteCert(_ context.Context, id string) error {
	delete(f.certs, id)
	return nil
}

func (f *fakeCloud) ImportCRL(_ context.Context, crlFile string) error {
	if f.failCRL {
		return errors.New("fake: CRL import refused")
	}
	data, err := os.ReadFile(crlFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("fake: CRL is not PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return err
	}
	f.crlPEM = data
	f.revoked = make(map[string]bool)
	for _, e := range crl.RevokedCertificateEntries {
		f.revoked[e.SerialNumber.Text(16)] = true
	}
	f.crlPushes++
	if f.onPush != nil {
		f.onPush(f.revoked)
	}
	return nil
}

type harness struct {
	t       *testing.T
	opts    *Options
	cloud   *fakeCloud
	dir     string
	pki     string
	s3      *storetest.FakeS3 // non-nil in S3 mode
	presign *stubPresigner
}

// pkiDir returns the PKI as it currently is: the local directory, or in S3
// mode a fresh unpacked copy of the archive in the bucket.
func (h *harness) pkiDir() string {
	h.t.Helper()
	if h.s3 == nil {
		return h.pki
	}
	return filepath.Join(h.storedCopy(), "pki")
}

// stateDir is like pkiDir, for cvpnctl's state file.
func (h *harness) stateDir() string {
	h.t.Helper()
	if h.s3 == nil {
		return h.certsDir()
	}
	return filepath.Join(h.storedCopy(), "state")
}

func (h *harness) storedCopy() string {
	h.t.Helper()
	data, ok := h.s3.Object("cvpnctl/pki.tar.gz")
	if !ok {
		h.t.Fatal("no archive in the bucket")
	}
	dir := h.t.TempDir()
	if err := store.Unpack(data, dir); err != nil {
		h.t.Fatal(err)
	}
	return dir
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ersDir := findEasyRSA(t)
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, pki: filepath.Join(dir, "pki")}

	easyrsa := func(args ...string) {
		cmd := exec.Command(filepath.Join(ersDir, "easyrsa"), append([]string{"--batch"}, args...)...)
		cmd.Dir = ersDir
		cmd.Env = append(os.Environ(), "EASYRSA_PKI="+h.pki)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("easyrsa %v: %v\n%s", args, err, out)
		}
	}
	easyrsa("init-pki")
	easyrsa("--req-cn=Test CA", "build-ca", "nopass")

	tmpl := filepath.Join(dir, "base.ovpn")
	if err := os.WriteFile(tmpl, []byte("client\n# {{.User}}\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`
easyrsa:
  path: %s
  pki_dir: %s
certs:
  output_dir: %s
aws:
  region: eu-central-1
  vpn_endpoint_id: cvpn-endpoint-test
ovpn:
  template: %s
  output_dir: %s
`, ersDir, h.pki, h.certsDir(), tmpl, h.clientsDir())
	cfgPath := filepath.Join(dir, "cvpnctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	h.cloud = &fakeCloud{certs: map[string]string{}, revoked: map[string]bool{}, endpointCerts: map[string]time.Time{
		fakeServerID: time.Now().AddDate(5, 0, 0),
		fakeRootID:   time.Now().AddDate(5, 0, 0),
	}}
	h.opts = &Options{
		ConfigFile: cfgPath,
		NewProvider: func(context.Context, *config.Config) (provider.CertStore, error) {
			return h.cloud, nil
		},
	}
	return h
}

func findEasyRSA(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("CVPNCTL_TEST_EASYRSA")}
	if p, err := exec.LookPath("easyrsa"); err == nil {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			candidates = append(candidates, filepath.Dir(real))
		}
	}
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "easyrsa")); err == nil {
			return dir
		}
	}
	t.Skip("easyrsa not found; set CVPNCTL_TEST_EASYRSA to the directory containing it")
	return ""
}

func (h *harness) certsDir() string   { return filepath.Join(h.dir, "certs") }
func (h *harness) clientsDir() string { return filepath.Join(h.dir, "clients") }

func (h *harness) create(user string) error { return runCreate(context.Background(), h.opts, user, 0) }
func (h *harness) renew(user string) error  { return runRenew(context.Background(), h.opts, user, 0) }
func (h *harness) revoke(user string) error {
	return runRevoke(context.Background(), h.opts, user, true)
}

func (h *harness) must(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
}

// serial returns the serial of user's currently issued certificate.
func (h *harness) serial(user string) string {
	h.t.Helper()
	cert, err := readCert(filepath.Join(h.pkiDir(), "issued", user+".crt"))
	if err != nil {
		h.t.Fatal(err)
	}
	return cert.SerialNumber.Text(16)
}

func (h *harness) record(user string) (state.UserRecord, bool) {
	h.t.Helper()
	s, err := state.Load(h.stateDir())
	if err != nil {
		h.t.Fatal(err)
	}
	return s.Get(user)
}

func (h *harness) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func TestLifecycle(t *testing.T) {
	h := newHarness(t)
	ovpnPath := filepath.Join(h.clientsDir(), "max.ovpn")
	userDir := filepath.Join(h.certsDir(), "max")

	// create
	h.must(h.create("max"))
	first := h.serial("max")

	if r, ok := h.record("max"); !ok || r.ProviderID != "cert-1" {
		t.Fatalf("state after create = %+v, %v", r, ok)
	}
	if h.cloud.certs["cert-1"] != first {
		t.Errorf("provider holds %v, want cert-1 with serial %s", h.cloud.certs, first)
	}
	conf, err := os.ReadFile(ovpnPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# max", "<cert>\n-----BEGIN CERTIFICATE-----", "BEGIN PRIVATE KEY"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf(".ovpn missing %q", want)
		}
	}
	if strings.Contains(string(conf), "Certificate:") {
		t.Error(".ovpn contains EasyRSA's text dump; only the PEM block belongs there")
	}
	for _, p := range []string{ovpnPath, filepath.Join(userDir, "max.key")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode not 0600 (%v)", p, err)
		}
	}

	if err := h.create("max"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second create: err = %v, want 'already exists'", err)
	}

	// renew
	h.must(h.renew("max"))
	second := h.serial("max")

	if second == first {
		t.Fatal("renew did not issue a new certificate")
	}
	if r, _ := h.record("max"); r.ProviderID != "cert-2" {
		t.Errorf("state after renew points at %s, want cert-2", r.ProviderID)
	}
	if len(h.cloud.certs) != 1 || h.cloud.certs["cert-2"] != second {
		t.Errorf("provider after renew holds %v, want only cert-2", h.cloud.certs)
	}
	if !h.cloud.revoked[first] || h.cloud.revoked[second] {
		t.Errorf("CRL after renew = %v, want old serial %s revoked and new %s not", h.cloud.revoked, first, second)
	}
	if copied, err := readCert(filepath.Join(userDir, "max.crt")); err != nil || copied.SerialNumber.Text(16) != second {
		t.Errorf("per-user copy is not the new certificate (%v)", err)
	}

	// revoke
	h.must(h.revoke("max"))

	if len(h.cloud.certs) != 0 {
		t.Errorf("provider after revoke still holds %v", h.cloud.certs)
	}
	if !h.cloud.revoked[second] {
		t.Errorf("CRL after revoke does not list %s", second)
	}
	if _, ok := h.record("max"); ok {
		t.Error("max still in state after revoke")
	}
	if h.exists(userDir) || h.exists(ovpnPath) {
		t.Error("revoke left the per-user directory or .ovpn behind")
	}

	// The name is free again.
	h.must(h.create("max"))
}

func TestCreateRollsBackWhenImportFails(t *testing.T) {
	h := newHarness(t)

	h.cloud.failImport = true
	if err := h.create("bob"); err == nil {
		t.Fatal("create succeeded despite import failure")
	}
	// EasyRSA also writes an inline bundle containing the private key.
	for _, p := range []string{"reqs/bob.req", "issued/bob.crt", "private/bob.key", "inline/private/bob.inline"} {
		if h.exists(filepath.Join(h.pki, p)) {
			t.Errorf("failed create left %s in the PKI", p)
		}
	}
	if _, ok := h.record("bob"); ok {
		t.Error("failed create left bob in state")
	}
	if h.exists(filepath.Join(h.certsDir(), "bob")) {
		t.Error("failed create left bob's key in the per-user directory")
	}

	h.cloud.failImport = false
	h.must(h.create("bob"))
}

func TestRenewResumesAfterImportFailure(t *testing.T) {
	h := newHarness(t)
	h.must(h.create("carol"))
	first := h.serial("carol")

	copied, err := os.ReadFile(filepath.Join(h.certsDir(), "carol", "carol.crt"))
	if err != nil {
		t.Fatal(err)
	}

	h.cloud.failImport = true
	if err := h.renew("carol"); err == nil {
		t.Fatal("renew succeeded despite import failure")
	}
	// The unrecorded certificate is gone from the PKI; its copy must not
	// have replaced the user's current one.
	if now, _ := os.ReadFile(filepath.Join(h.certsDir(), "carol", "carol.crt")); !bytes.Equal(now, copied) {
		t.Error("failed renew replaced the per-user copy with the unrecorded certificate")
	}
	if r, _ := h.record("carol"); r.ProviderID != "cert-1" {
		t.Errorf("failed renew changed state to %s", r.ProviderID)
	}
	if h.cloud.crlPushes != 0 {
		t.Error("failed renew pushed a CRL; the user's current .ovpn should keep working")
	}

	h.cloud.failImport = false
	h.must(h.renew("carol"))
	if !h.cloud.revoked[first] {
		t.Errorf("CRL after resumed renew does not list the original serial %s", first)
	}
	if _, ok := h.cloud.certs["cert-1"]; ok || len(h.cloud.certs) != 1 {
		t.Errorf("provider after resumed renew holds %v, want only the new certificate", h.cloud.certs)
	}
}

func TestRevokeResumesAfterCRLFailure(t *testing.T) {
	h := newHarness(t)
	h.must(h.create("dave"))
	serial := h.serial("dave")

	h.cloud.failCRL = true
	if err := h.revoke("dave"); err == nil {
		t.Fatal("revoke succeeded despite CRL failure")
	}
	if _, ok := h.record("dave"); !ok {
		t.Fatal("failed revoke dropped dave from state")
	}

	h.cloud.failCRL = false
	h.must(h.revoke("dave"))
	if !h.cloud.revoked[serial] {
		t.Errorf("CRL after resumed revoke does not list %s", serial)
	}
	if _, ok := h.record("dave"); ok {
		t.Error("dave still in state after resumed revoke")
	}
}
