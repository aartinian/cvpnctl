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

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load without a path did not find ./cvpnctl.yaml: %v", err)
	}
	if want := filepath.Join(dir, "cvpnctl.yaml"); !sameFile(t, cfg.Path, want) {
		t.Errorf("Path = %q, want %q", cfg.Path, want)
	}
	if len(cfg.Ignored) != 0 {
		t.Errorf("Ignored = %v, want none", cfg.Ignored)
	}
}

// A ./cvpnctl.yaml takes precedence over ~/.config/cvpnctl/cvpnctl.yaml, and
// Load reports the file it skipped so the commands can warn about it.
func TestLoadReportsOverriddenConfig(t *testing.T) {
	dir, write := fixture(t)
	local := write(validConfig)
	home := t.TempDir()
	user := filepath.Join(home, ".config", "cvpnctl", "cvpnctl.yaml")
	if err := os.MkdirAll(filepath.Dir(user), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(user, []byte("not: used\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(dir)

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !sameFile(t, cfg.Path, local) {
		t.Errorf("Path = %q, want %q", cfg.Path, local)
	}
	if len(cfg.Ignored) != 1 || !sameFile(t, cfg.Ignored[0], user) {
		t.Errorf("Ignored = %v, want [%s]", cfg.Ignored, user)
	}

	// If the overriding file is broken, the error itself must point at the
	// file that was skipped: no warning gets printed when loading fails.
	write(strings.Replace(validConfig, "template: $DIR/base.ovpn", "template: /etc/vpn/base.ovpn", 1))
	_, err = Load("")
	if err == nil || !strings.Contains(err.Error(), "which takes precedence over "+cfg.Ignored[0]) {
		t.Errorf("err = %v, want it to name the ignored %s", err, cfg.Ignored[0])
	}
}

// Errors name the config file by its absolute path, even when it was given
// relatively, so it is obvious which file needs fixing.
func TestLoadErrorNamesAbsolutePath(t *testing.T) {
	dir, write := fixture(t)
	write(strings.Replace(validConfig, "template: $DIR/base.ovpn", "template: $DIR/nope.ovpn", 1))
	t.Chdir(dir)

	_, err := Load("cvpnctl.yaml")
	if err == nil {
		t.Fatal("expected an error")
	}
	if want := "(in " + filepath.Join(dir, "cvpnctl.yaml") + ")"; !strings.Contains(err.Error(), want) &&
		!strings.Contains(err.Error(), "(in "+resolve(t, filepath.Join(dir, "cvpnctl.yaml"))+")") {
		t.Errorf("err = %v, want it to contain %q", err, want)
	}
}

// sameFile compares paths after resolving symlinks (macOS temp dirs live
// under /var, which is a symlink to /private/var).
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	return resolve(t, a) == resolve(t, b)
}

func resolve(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("resolve %s: %v", p, err)
	}
	return r
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

const s3Config = `
easyrsa:
  path: $DIR/easyrsa
store:
  bucket: acme-vpn-pki
  kms_key_id: alias/cvpnctl
aws:
  region: eu-central-1
  vpn_endpoint_id: cvpn-endpoint-abc
`

func TestLoadS3Mode(t *testing.T) {
	_, write := fixture(t)
	cfg, err := Load(write(s3Config))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.S3Mode() {
		t.Fatal("S3Mode() = false, want true")
	}
	if cfg.Store.LinkHours != 24 {
		t.Errorf("LinkHours = %d, want default 24", cfg.Store.LinkHours)
	}
}

func TestLocalModeIsNotS3(t *testing.T) {
	_, write := fixture(t)
	cfg, err := Load(write(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.S3Mode() || cfg.Store != nil {
		t.Errorf("local config: S3Mode()=%v Store=%v", cfg.S3Mode(), cfg.Store)
	}
}

func TestLoadS3ModeRejectsLocalPaths(t *testing.T) {
	for key, yaml := range map[string]string{
		"easyrsa.pki_dir":  "  pki_dir: $DIR/easyrsa/pki\n",
		"certs.output_dir": "certs: {output_dir: ~/certs}\n",
		"ovpn.output_dir":  "ovpn: {output_dir: ~/clients}\n",
		"ovpn.template":    "ovpn: {template: $DIR/base.ovpn}\n",
	} {
		t.Run(key, func(t *testing.T) {
			_, write := fixture(t)
			body := s3Config
			if key == "easyrsa.pki_dir" {
				body = strings.Replace(body, "  path: $DIR/easyrsa\n", "  path: $DIR/easyrsa\n"+yaml, 1)
			} else {
				body += yaml
			}
			_, err := Load(write(body))
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "not allowed with store") {
				t.Errorf("err = %v, want it to name %s and say 'not allowed with store'", err, key)
			}
		})
	}
}

func TestLoadS3ModeLinkHours(t *testing.T) {
	for _, tt := range []struct {
		hours   string
		want    int
		wantErr bool
	}{{"1", 1, false}, {"168", 168, false}, {"169", 0, true}, {"-1", 0, true}} {
		_, write := fixture(t)
		body := strings.Replace(s3Config, "  kms_key_id: alias/cvpnctl\n", "  kms_key_id: alias/cvpnctl\n  link_hours: "+tt.hours+"\n", 1)
		cfg, err := Load(write(body))
		switch {
		case tt.wantErr && (err == nil || !strings.Contains(err.Error(), "link_hours must be 1–168")):
			t.Errorf("link_hours %s: err = %v, want 'link_hours must be 1–168'", tt.hours, err)
		case !tt.wantErr && (err != nil || cfg.Store.LinkHours != tt.want):
			t.Errorf("link_hours %s: cfg=%v err=%v", tt.hours, cfg, err)
		}
	}
}

func TestLoadS3ModeRequires(t *testing.T) {
	for field, line := range map[string]string{
		"store.bucket":     "  bucket: acme-vpn-pki\n",
		"store.kms_key_id": "  kms_key_id: alias/cvpnctl\n",
	} {
		_, write := fixture(t)
		_, err := Load(write(strings.Replace(s3Config, line, "", 1)))
		if err == nil || !strings.Contains(err.Error(), field+" is required") {
			t.Errorf("without %s: err = %v", field, err)
		}
	}
}

func TestStorePrefixNormalised(t *testing.T) {
	for prefix, want := range map[string]string{
		"":         "lock",
		"cvpnctl":  "cvpnctl/lock",
		"cvpnctl/": "cvpnctl/lock",
		"a/b":      "a/b/lock",
	} {
		_, write := fixture(t)
		body := strings.Replace(s3Config, "  bucket: acme-vpn-pki\n", "  bucket: acme-vpn-pki\n  prefix: \""+prefix+"\"\n", 1)
		cfg, err := Load(write(body))
		if err != nil {
			t.Fatalf("prefix %q: %v", prefix, err)
		}
		if got := cfg.Store.Key("lock"); got != want {
			t.Errorf("prefix %q: Key(lock) = %q, want %q", prefix, got, want)
		}
	}
}
