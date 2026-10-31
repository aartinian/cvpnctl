// Package easyrsa wraps the EasyRSA CLI and the files it produces.
package easyrsa

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

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
	cfg     *config.EasyRSAConfig
	verbose bool
}

// New returns a Client configured from cfg. With verbose, EasyRSA's own
// output is shown as it runs; otherwise it is captured and only shown, in
// part, if a command fails.
func New(cfg *config.EasyRSAConfig, verbose bool) *Client {
	return &Client{cfg: cfg, verbose: verbose}
}

// MinVersion is the oldest EasyRSA release cvpnctl supports.
var MinVersion = []int{3, 2, 7}

var versionLine = regexp.MustCompile(`(?m)^Version:\s+(\d+)\.(\d+)\.(\d+)\s*$`)

// CheckVersion returns the version of the configured easyrsa script, e.g.
// "3.2.7", and fails unless it is a release of MinVersion or newer. Git
// checkouts report "~VER~" rather than a version and are rejected too.
func (c *Client) CheckVersion() (string, error) {
	out, err := exec.Command(c.script(), "--version").Output()
	if err != nil {
		return "", fmt.Errorf("easyrsa: run %s --version: %w", c.script(), err)
	}
	return checkVersionOutput(c.script(), string(out))
}

// Dir returns the directory of the easyrsa script.
func (c *Client) Dir() string {
	return c.cfg.Path
}

func checkVersionOutput(script, out string) (string, error) {
	want := fmt.Sprintf("%d.%d.%d", MinVersion[0], MinVersion[1], MinVersion[2])
	m := versionLine.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("easyrsa: can't tell the version of %s (a git checkout instead of a release?); cvpnctl needs an EasyRSA release, %s or later", script, want)
	}
	got := make([]int, 3)
	for i := range got {
		got[i], _ = strconv.Atoi(m[i+1]) // the regexp guarantees digits
	}
	if slices.Compare(got, MinVersion) < 0 {
		return "", fmt.Errorf("easyrsa: %s is version %s.%s.%s; cvpnctl needs %s or later", script, m[1], m[2], m[3], want)
	}
	return m[1] + "." + m[2] + "." + m[3], nil
}

// Files returns where the PKI keeps user's certificate, key, and the CA.
func (c *Client) Files(user string) Files {
	return Files{
		Cert: filepath.Join(c.cfg.PKIDir, "issued", user+".crt"),
		Key:  filepath.Join(c.cfg.PKIDir, "private", user+".key"),
		CA:   filepath.Join(c.cfg.PKIDir, "ca.crt"),
	}
}

// CAEncrypted reports whether the CA key is protected by a passphrase, in
// which case every step that signs (issuing a certificate, revoking one,
// regenerating the CRL) asks for it.
func (c *Client) CAEncrypted() bool {
	f, err := os.Open(filepath.Join(c.cfg.PKIDir, "private", "ca.key"))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	// PKCS#8 says so in the BEGIN line, traditional PEM in a Proc-Type
	// header right below it.
	r := bufio.NewReader(f)
	first, _ := r.ReadString('\n')
	second, _ := r.ReadString('\n')
	return strings.Contains(first, "ENCRYPTED") || strings.HasPrefix(second, "Proc-Type:") && strings.Contains(second, "ENCRYPTED")
}

// CACert returns the CA certificate.
func (c *Client) CACert() (*x509.Certificate, error) {
	return readCert(c.Files("").CA)
}

// IndexEntry is one certificate in the PKI's index.txt.
type IndexEntry struct {
	Status string // "V" valid, "R" revoked, "E" expired
	Serial string // normalised with NormSerial
	Name   string // the subject's common name
}

// Index returns every certificate the PKI has issued, in index.txt order.
func (c *Client) Index() ([]IndexEntry, error) {
	data, err := os.ReadFile(filepath.Join(c.cfg.PKIDir, "index.txt"))
	if err != nil {
		return nil, fmt.Errorf("easyrsa: %w", err)
	}
	var entries []IndexEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		entries = append(entries, IndexEntry{Status: f[0], Serial: NormSerial(f[3]), Name: commonName(f[5])})
	}
	return entries, nil
}

// commonName extracts CN from a subject like "/C=CH/CN=max/O=x".
func commonName(subject string) string {
	for _, part := range strings.Split(subject, "/") {
		if cn, ok := strings.CutPrefix(part, "CN="); ok {
			return cn
		}
	}
	return subject
}

// RevokedSerials returns the serial numbers the PKI's index.txt marks as
// revoked, normalised with NormSerial. They are what the next CRL will list.
func (c *Client) RevokedSerials() (map[string]bool, error) {
	entries, err := c.Index()
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]bool)
	for _, e := range entries {
		if e.Status == "R" {
			revoked[e.Serial] = true
		}
	}
	return revoked, nil
}

// NormSerial normalises a hex serial number so serials from index.txt and from
// a parsed CRL compare equal: uppercase, without leading zeros.
func NormSerial(hex string) string {
	return strings.TrimLeft(strings.ToUpper(hex), "0")
}

// Expiry returns when user's issued certificate expires.
func (c *Client) Expiry(user string) (time.Time, error) {
	cert, err := readCert(c.Files(user).Cert)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// CRLInfo returns how many certificates the current CRL revokes, and until
// when it is valid.
func (c *Client) CRLInfo() (revoked int, nextUpdate time.Time, err error) {
	data, err := os.ReadFile(c.CRLPath())
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("easyrsa: %w", err)
	}
	crl, err := ParseCRL(data)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("easyrsa: %s: %w", c.CRLPath(), err)
	}
	return len(crl.RevokedCertificateEntries), crl.NextUpdate, nil
}

// ParseCRL parses a PEM-encoded CRL, such as crl.pem or the one exported from
// the VPN endpoint.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("contains no PEM data")
	}
	return x509.ParseRevocationList(block.Bytes)
}

// CRLSerials returns the serial numbers crl revokes, normalised with
// NormSerial so they compare equal to RevokedSerials.
func CRLSerials(crl *x509.RevocationList) map[string]bool {
	serials := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, r := range crl.RevokedCertificateEntries {
		serials[NormSerial(r.SerialNumber.Text(16))] = true
	}
	return serials
}

// readCert parses the first certificate in a PEM file. EasyRSA puts a text
// dump in front of the PEM block, which pem.Decode skips.
func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("easyrsa: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("easyrsa: %s contains no PEM data", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("easyrsa: parse %s: %w", path, err)
	}
	return cert, nil
}

// CRLPath returns the path of the CRL that GenCRL writes.
func (c *Client) CRLPath() string {
	return filepath.Join(c.cfg.PKIDir, "crl.pem")
}

// HasCert reports whether the PKI holds an issued, unrevoked certificate for
// user. EasyRSA moves revoked certificates out of pki/issued, so a missing
// file means the name is free.
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
		// The "inline" bundle EasyRSA writes on every build; it contains the key.
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

func (c *Client) script() string {
	return filepath.Join(c.cfg.Path, "easyrsa")
}

// run executes the easyrsa script in batch mode against the configured PKI.
//
// Unless verbose, EasyRSA's output is captured and, if the command fails, its
// last meaningful lines are added to the error. Stdin stays connected: if the
// CA key has a passphrase, OpenSSL prompts for it through the terminal
// directly, so the prompt still appears while the output is captured.
func (c *Client) run(args ...string) error {
	cmd := exec.Command(c.script(), append([]string{"--batch"}, args...)...)
	cmd.Dir = c.cfg.Path
	cmd.Env = append(os.Environ(), "EASYRSA_PKI="+c.cfg.PKIDir)
	cmd.Stdin = os.Stdin
	var out bytes.Buffer
	if c.verbose {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	} else {
		cmd.Stdout, cmd.Stderr = &out, &out
	}
	if err := cmd.Run(); err != nil {
		hint := ""
		if strings.Contains(out.String(), "unable to get passphrase") {
			hint = " (the CA key has a passphrase and there was no terminal to ask for it: run cvpnctl in a terminal)"
		}
		if tail := lastLines(out.String(), 8); tail != "" {
			return fmt.Errorf("easyrsa %s: %w%s; its last output:\n%s", args[0], err, hint, tail)
		}
		return fmt.Errorf("easyrsa %s: %w%s", args[0], err, hint)
	}
	return nil
}

// lastLines returns the last n meaningful lines of EasyRSA's output, indented.
// Blank lines, OpenSSL's key-generation progress ("....+...+*") and the
// version footer EasyRSA appends to fatal errors are noise.
func lastLines(out string, n int) string {
	if i := strings.Index(out, "EasyRSA Version Information"); i >= 0 {
		out = out[:i]
	}
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, " \r\t")
		if strings.Trim(l, ".+* ") == "" || strings.Trim(l, "-") == "" {
			continue
		}
		keep = append(keep, "    "+l)
	}
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	return strings.Join(keep, "\n")
}
