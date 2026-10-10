// Package easyrsa wraps the EasyRSA CLI and the files it produces.
package easyrsa

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/fsutil"
)

// Files locates a client certificate, its private key, and the issuing CA.
type Files struct {
	Cert string
	Key  string
	CA   string
}

// Client runs EasyRSA against one PKI.
type Client struct {
	cfg *config.EasyRSAConfig
}

// New returns a Client configured from cfg.
func New(cfg *config.EasyRSAConfig) *Client {
	return &Client{cfg: cfg}
}

// Files returns where the PKI keeps user's certificate, key, and the CA.
func (c *Client) Files(user string) Files {
	return Files{
		Cert: filepath.Join(c.cfg.PKIDir, "issued", user+".crt"),
		Key:  filepath.Join(c.cfg.PKIDir, "private", user+".key"),
		CA:   filepath.Join(c.cfg.PKIDir, "ca.crt"),
	}
}

// CRLPath returns the path of the CRL that GenCRL writes.
func (c *Client) CRLPath() string {
	return filepath.Join(c.cfg.PKIDir, "crl.pem")
}

// HasCert reports whether the PKI holds an issued, unrevoked certificate for
// user. EasyRSA moves revoked certificates out of pki/issued (since 3.0.6), so
// a missing file means the name is free.
func (c *Client) HasCert(user string) bool {
	_, err := os.Stat(c.Files(user).Cert)
	return err == nil
}

// BuildCert issues a new certificate and passwordless key for user.
func (c *Client) BuildCert(user string) error {
	return c.run("build-client-full", user, "nopass")
}

// Revoke revokes user's certificate and regenerates the CRL.
func (c *Client) Revoke(user string) error {
	if err := c.run("revoke", user); err != nil {
		return err
	}
	return c.GenCRL()
}

// GenCRL regenerates the CRL from the PKI index.
func (c *Client) GenCRL() error {
	return c.run("gen-crl")
}

// RemoveCertFiles deletes user's request, certificate, and key without
// revoking anything. It is only for undoing a certificate that was never
// handed out: a failed build-client-full leaves the request behind, and
// EasyRSA refuses to reuse a name while that file exists. Missing files are
// not an error.
func (c *Client) RemoveCertFiles(user string) error {
	f := c.Files(user)
	for _, p := range []string{
		filepath.Join(c.cfg.PKIDir, "reqs", user+".req"),
		f.Cert,
		f.Key,
		// EasyRSA 3.2+ also writes an "inline" bundle that contains the key.
		filepath.Join(c.cfg.PKIDir, "inline", user+".inline"),
		filepath.Join(c.cfg.PKIDir, "inline", "private", user+".inline"),
	} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("easyrsa: %w", err)
		}
	}
	return nil
}

// UserDir returns the per-user directory under outputDir.
func UserDir(outputDir, user string) string {
	return filepath.Join(outputDir, user)
}

// CopyToUserDir copies user's certificate, key, and the CA into
// outputDir/<user>/ as <user>.crt, <user>.key, and ca.crt, and returns the
// directory.
func (c *Client) CopyToUserDir(user, outputDir string) (string, error) {
	dir := UserDir(outputDir, user)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("easyrsa: %w", err)
	}

	src := c.Files(user)
	copies := []struct{ from, to string }{
		{src.Cert, filepath.Join(dir, user+".crt")},
		{src.Key, filepath.Join(dir, user+".key")},
		{src.CA, filepath.Join(dir, "ca.crt")},
	}
	for _, cp := range copies {
		data, err := os.ReadFile(cp.from)
		if err != nil {
			return "", fmt.Errorf("easyrsa: %w", err)
		}
		if err := fsutil.WriteFile(cp.to, data, 0o600); err != nil {
			return "", fmt.Errorf("easyrsa: %w", err)
		}
	}
	return dir, nil
}

// RemoveUserDir deletes outputDir/<user>/.
func RemoveUserDir(outputDir, user string) error {
	if err := os.RemoveAll(UserDir(outputDir, user)); err != nil {
		return fmt.Errorf("easyrsa: %w", err)
	}
	return nil
}

// run executes the easyrsa script in batch mode against the configured PKI.
// Stdin and the terminal are passed through so EasyRSA can prompt for the CA
// key passphrase, if the CA has one.
func (c *Client) run(args ...string) error {
	cmd := exec.Command(filepath.Join(c.cfg.Path, "easyrsa"), append([]string{"--batch"}, args...)...)
	cmd.Dir = c.cfg.Path
	cmd.Env = append(os.Environ(), "EASYRSA_PKI="+c.cfg.PKIDir)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("easyrsa %s: %w", args[0], err)
	}
	return nil
}
