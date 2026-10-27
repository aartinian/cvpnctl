package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemplate(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "base.ovpn")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTemplateShow(t *testing.T) {
	h := newHarnessS3(t)
	out, err := captureStdout(t, func() error { return runTemplateShow(context.Background(), h.opts) })
	if err != nil {
		t.Fatal(err)
	}
	if out != "client\n# {{.User}}\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n" {
		t.Errorf("show printed %q", out)
	}
}

// A new template is stored and used for every .ovpn rendered afterwards.
func TestTemplateSet(t *testing.T) {
	h := newHarnessS3(t)
	file := writeTemplate(t, "client\nremote vpn.example 443\n# for {{.User}}\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n")
	if _, err := captureStdout(t, func() error { return runTemplateSet(context.Background(), h.opts, file) }); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(h.storedCopy(), "template", "base.ovpn")); !strings.Contains(string(got), "remote vpn.example 443") {
		t.Errorf("stored template = %q", got)
	}

	h.must(h.create("alice"))
	body, _ := h.s3.Object(h.links()[0])
	if !strings.Contains(string(body), "remote vpn.example 443") || !strings.Contains(string(body), "# for alice") {
		t.Errorf("alice's .ovpn doesn't use the new template:\n%s", body)
	}
}

// A template that doesn't render is refused before anything is uploaded.
func TestTemplateSetRejectsUnknownField(t *testing.T) {
	h := newHarnessS3(t)
	before, _ := h.s3.Object("cvpnctl/pki.tar.gz")
	err := runTemplateSet(context.Background(), h.opts, writeTemplate(t, "{{.Nope}}\n"))
	if err == nil || !strings.Contains(err.Error(), "Nope") {
		t.Fatalf("err = %v, want an error naming the unknown field", err)
	}
	if after, _ := h.s3.Object("cvpnctl/pki.tar.gz"); !bytes.Equal(before, after) {
		t.Error("the archive changed although the template was refused")
	}
	if l := h.leftovers(); len(l) != 0 {
		t.Errorf("temp folders left: %v", l)
	}
}

func TestTemplateSetMissingFile(t *testing.T) {
	h := newHarnessS3(t)
	if err := runTemplateSet(context.Background(), h.opts, "/nope/base.ovpn"); err == nil {
		t.Error("set with a missing file succeeded")
	}
}

func TestTemplateLocalMode(t *testing.T) {
	h := newHarness(t)
	for name, run := range map[string]func() error{
		"show": func() error { return runTemplateShow(context.Background(), h.opts) },
		"set":  func() error { return runTemplateSet(context.Background(), h.opts, writeTemplate(t, "x")) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "requires `store` in the config") {
			t.Errorf("%s in local mode: err = %v", name, err)
		}
	}
}
