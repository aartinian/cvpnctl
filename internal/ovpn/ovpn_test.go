package ovpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/ovpncert/internal/config"
	"github.com/aartinian/ovpncert/internal/easyrsa"
)

const (
	pemCert = "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----\n"
	pemKey  = "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n"
	pemCA   = "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n"
)

func setup(t *testing.T, template string) (*Generator, easyrsa.Files, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	files := easyrsa.Files{
		// EasyRSA puts a text dump in front of the PEM block in issued certs.
		Cert: write("alice.crt", "Certificate:\n    Data: ...\n"+pemCert),
		Key:  write("alice.key", pemKey),
		CA:   write("ca.crt", pemCA),
	}
	out := filepath.Join(dir, "clients")
	gen := New(&config.OVPNConfig{Template: write("base.ovpn", template), OutputDir: out})
	return gen, files, out
}

func TestGenerate(t *testing.T) {
	gen, files, _ := setup(t, "client\n# {{.User}}\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n")

	path, err := gen.Generate("alice", files)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got, _ := os.ReadFile(path)
	want := "client\n# alice\n" +
		"<ca>\n" + pemCA + "</ca>\n" +
		"<cert>\n" + pemCert + "</cert>\n" +
		"<key>\n" + pemKey + "</key>\n"
	if string(got) != want {
		t.Errorf("rendered config:\n%s\nwant:\n%s", got, want)
	}

	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestGenerateTightensExistingFileMode(t *testing.T) {
	gen, files, out := setup(t, "{{.Key}}")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gen.Path("alice"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := gen.Generate("alice", files); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(gen.Path("alice"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode after overwrite = %o, want 600", fi.Mode().Perm())
	}
}

func TestGenerateUnknownField(t *testing.T) {
	gen, files, _ := setup(t, "{{.Nope}}")
	if _, err := gen.Generate("alice", files); err == nil || !strings.Contains(err.Error(), "Nope") {
		t.Errorf("err = %v, want an error naming the unknown field", err)
	}
}

func TestRemoveMissingIsNotAnError(t *testing.T) {
	gen, _, _ := setup(t, "")
	if err := gen.Remove("nobody"); err != nil {
		t.Errorf("Remove: %v", err)
	}
}
