package command

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
)

// status runs `cvpnctl status` and returns its output and error.
func (h *harness) status() (string, error) {
	h.t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		h.t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	runErr := runStatus(context.Background(), h.opts, time.Now())
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// easyrsa returns an EasyRSA client for pkiDir, for changes made behind
// cvpnctl's back.
func (h *harness) easyrsa(pkiDir string) *easyrsa.Client {
	return easyrsa.New(&config.EasyRSAConfig{Path: findEasyRSA(h.t), PKIDir: pkiDir}, false)
}

func wantStatus(t *testing.T, out string, err error, attention bool, notes ...string) {
	t.Helper()
	if attention != errors.Is(err, ErrNeedsAttention) || (err != nil && !errors.Is(err, ErrNeedsAttention)) {
		t.Errorf("err = %v, want attention=%v\n%s", err, attention, out)
	}
	for _, n := range notes {
		if !strings.Contains(out, n) {
			t.Errorf("output lacks %q:\n%s", n, out)
		}
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t)

	// A fresh PKI: no CRL anywhere yet, and nothing revoked.
	out, err := h.status()
	wantStatus(t, out, err, false, "none yet", "none (nothing revoked yet)", "All good.")

	h.must(h.create("alice"))
	h.must(h.renew("alice")) // revokes the first certificate and pushes the CRL
	out, err = h.status()
	wantStatus(t, out, err, false, "matches your PKI", "1 revoked", "alice", "server", "client-root")

	// Expiring within 30 days needs attention; expired is critical.
	h.cloud.endpointCerts[fakeServerID] = time.Now().AddDate(0, 0, 10)
	out, err = h.status()
	wantStatus(t, out, err, true, "expires soon", "1 item needs attention")
	h.cloud.endpointCerts[fakeServerID] = time.Now().AddDate(0, 0, -1)
	out, err = h.status()
	wantStatus(t, out, err, true, "expired")
	h.cloud.endpointCerts[fakeServerID] = time.Now().AddDate(5, 0, 0)

	// A user's ACM entry deleted behind cvpnctl's back.
	r, _ := h.record("alice")
	delete(h.cloud.certs, r.ProviderID)
	out, err = h.status()
	wantStatus(t, out, err, true, "ACM entry missing")
}

func TestStatusComparesEndpointCRL(t *testing.T) {
	h := newHarness(t)
	h.must(h.create("alice"))
	h.must(h.create("bob"))
	h.must(h.create("carol"))
	h.must(h.revoke("alice"))
	out, err := h.status()
	wantStatus(t, out, err, false, "matches your PKI")

	// Issued and revoked in the PKI by hand, outside cvpnctl, but never
	// pushed: dave can still connect.
	h.must(h.easyrsa(h.pki).BuildCert("dave"))
	h.must(h.easyrsa(h.pki).Revoke("dave"))
	out, err = h.status()
	wantStatus(t, out, err, true, "1 revocation not pushed yet", "run cvpnctl push-crl")
	h.must(runPushCRL(context.Background(), h.opts))
	out, err = h.status()
	wantStatus(t, out, err, false, "matches your PKI")

	// Drift: a second copy of the PKI revoked carol and pushed its CRL. A push
	// from this PKI would let carol connect again.
	other := filepath.Join(t.TempDir(), "pki")
	if out, err := exec.Command("/bin/cp", "-R", h.pki, other).CombinedOutput(); err != nil {
		t.Fatalf("copy PKI: %v %s", err, out)
	}
	h.must(h.easyrsa(other).Revoke("carol"))
	h.cloud.crlPEM = mustRead(t, filepath.Join(other, "crl.pem"))
	out, err = h.status()
	wantStatus(t, out, err, true, "revokes 1 certificate your PKI doesn't")

	// A CRL from a different CA altogether.
	foreign := filepath.Join(t.TempDir(), "pki")
	ers := filepath.Join(findEasyRSA(t), "easyrsa")
	for _, args := range [][]string{{"init-pki"}, {"--req-cn=Other CA", "build-ca", "nopass"}, {"gen-crl"}} {
		cmd := exec.Command(ers, append([]string{"--batch", "--pki-dir=" + foreign}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("easyrsa %v: %v\n%s", args, err, out)
		}
	}
	h.cloud.crlPEM = mustRead(t, filepath.Join(foreign, "crl.pem"))
	out, err = h.status()
	wantStatus(t, out, err, true, "not signed by your CA")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
