package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	cwd, _ := os.Getwd()

	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"~", home},
		{"~/certs", filepath.Join(home, "certs")},
		{"/etc/vpn", "/etc/vpn"},
		{"certs", filepath.Join(cwd, "certs")},
	}
	for _, tt := range tests {
		got, err := ExpandPath(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ExpandPath(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}

	if _, err := ExpandPath("~bob/certs"); err == nil {
		t.Error("ExpandPath(~bob/certs) should fail")
	}
}

// fixture creates a minimal EasyRSA layout and template, and returns a
// function that writes a config file with the given YAML body.
func fixture(t *testing.T) (dir string, write func(body string) string) {
	t.Helper()
	dir = t.TempDir()
	for _, f := range []string{"easyrsa/easyrsa", "easyrsa/pki/ca.crt", "base.ovpn"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, func(body string) string {
		p := filepath.Join(dir, "cvpnctl.yaml")
		body = strings.ReplaceAll(body, "$DIR", dir)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
}

const validConfig = `
easyrsa:
  path: $DIR/easyrsa
  pki_dir: $DIR/easyrsa/pki
certs:
  output_dir: ~/certs
aws:
  region: eu-central-1
  vpn_endpoint_id: cvpn-endpoint-abc
ovpn:
  template: $DIR/base.ovpn
  output_dir: ~/vpn/clients
`

func TestLoad(t *testing.T) {
	_, write := fixture(t)
	cfg, err := Load(write(validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	home, _ := os.UserHomeDir()
	if cfg.Certs.OutputDir != filepath.Join(home, "certs") {
		t.Errorf("certs.output_dir not expanded: %q", cfg.Certs.OutputDir)
	}
	if cfg.Provider != "aws" {
		t.Errorf("provider default = %q, want aws", cfg.Provider)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(string) string
		wantErr string
	}{
		{"missing endpoint", func(s string) string {
			return strings.Replace(s, "vpn_endpoint_id: cvpn-endpoint-abc", "", 1)
		}, "aws.vpn_endpoint_id is required"},
		{"unknown provider", func(s string) string {
			return "provider: gcp\n" + s
		}, `provider "gcp" is not supported`},
		{"bad easyrsa path", func(s string) string {
			return strings.Replace(s, "path: $DIR/easyrsa", "path: /nope", 1)
		}, "easyrsa script not found"},
		{"pki not initialised", func(s string) string {
			return strings.Replace(s, "pki_dir: $DIR/easyrsa/pki", "pki_dir: $DIR", 1)
		}, "CA certificate"},
		{"missing template", func(s string) string {
			return strings.Replace(s, "template: $DIR/base.ovpn", "template: $DIR/nope.ovpn", 1)
		}, "ovpn template not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, write := fixture(t)
			_, err := Load(write(tt.edit(validConfig)))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadSearchesForConfig(t *testing.T) {
	dir, write := fixture(t)
	write(validConfig)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(dir)

	if _, err := Load(""); err != nil {
		t.Fatalf("Load without a path did not find ./cvpnctl.yaml: %v", err)
	}
}

func TestLoadIgnoresBinaryNamedCvpnctl(t *testing.T) {
	// Running from the directory that holds the cvpnctl binary must not
	// make it try to parse the binary as its config.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cvpnctl"), []byte("\xcf\xfa\xed\xfe binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Chdir(dir)

	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), "no config file found") {
		t.Errorf("err = %v, want 'no config file found'", err)
	}
}
