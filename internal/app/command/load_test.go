package command

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/provider"
)

// An unsupported EasyRSA must be refused before anything changes: no PKI
// files, and no cloud provider (so no AWS calls).
func TestRejectsOldEasyRSA(t *testing.T) {
	dir := t.TempDir()
	ersDir := filepath.Join(dir, "easyrsa")
	pki := filepath.Join(dir, "pki")
	for _, d := range []string{ersDir, pki} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// A fake easyrsa that reports an old version and records any other use.
	marker := filepath.Join(dir, "easyrsa-was-run")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = --version ]; then printf 'Version:     3.1.7\\n'; exit 0; fi\n" +
		"touch " + marker + "\n"
	if err := os.WriteFile(filepath.Join(ersDir, "easyrsa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(pki, "ca.crt"), filepath.Join(dir, "base.ovpn")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := fmt.Sprintf("easyrsa: {path: %s, pki_dir: %s}\ncerts: {output_dir: %s}\naws: {region: x, vpn_endpoint_id: cvpn-endpoint-x}\novpn: {template: %s, output_dir: %s}\n",
		ersDir, pki, filepath.Join(dir, "certs"), filepath.Join(dir, "base.ovpn"), filepath.Join(dir, "clients"))
	cfgPath := filepath.Join(dir, "cvpnctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := &Options{
		ConfigFile: cfgPath,
		NewProvider: func(context.Context, *config.Config) (provider.CertStore, error) {
			t.Error("cloud provider created despite unsupported EasyRSA")
			return nil, nil
		},
	}

	err := runCreate(context.Background(), opts, "alice")
	if err == nil || !strings.Contains(err.Error(), "is version 3.1.7; cvpnctl needs 3.2.7 or later") {
		t.Fatalf("err = %v, want a version error", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("easyrsa was run for something other than --version")
	}
}
