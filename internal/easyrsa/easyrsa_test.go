package easyrsa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/config"
)

func TestCheckVersionOutput(t *testing.T) {
	release := func(v string) string {
		return "EasyRSA Version Information\nVersion:     " + v + "\nGenerated:   Sat Sep 19 07:53:22 CDT 2026\n"
	}
	tests := []struct {
		name    string
		out     string
		wantErr string // empty: accepted
	}{
		{"minimum", release("3.2.7"), ""},
		{"newer patch", release("3.2.10"), ""},
		{"newer minor", release("3.3.0"), ""},
		{"newer major", release("4.0.0"), ""},
		{"older patch", release("3.2.6"), "is version 3.2.6; cvpnctl needs 3.2.7 or later"},
		{"older minor", release("3.1.7"), "is version 3.1.7"},
		{"git checkout", release("~VER~"), "a git checkout instead of a release?"},
		{"no version line", "something else\n", "can't tell the version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkVersionOutput("/x/easyrsa", tt.out)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("rejected: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLastLines(t *testing.T) {
	out := "\n.....+...+..+++++*\n-----\nUsing SSL: openssl\n\n  \nEasy-RSA error:\n\nRequest file already exists.\n" +
		"\nEasyRSA Version Information\nVersion:     3.2.7\n*** Easy-RSA has encountered a FATAL error, please report this.\n"
	want := "    Using SSL: openssl\n    Easy-RSA error:\n    Request file already exists."
	if got := lastLines(out, 8); got != want {
		t.Errorf("lastLines:\n%q\nwant:\n%q", got, want)
	}
	if got := lastLines(out, 1); got != "    Request file already exists." {
		t.Errorf("lastLines(n=1) = %q", got)
	}
}

// Without verbose, EasyRSA's output is captured; when a command fails, the
// error carries its last meaningful lines.
func TestRunCapturesOutput(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '....+...+++++*\\n\\nEasy-RSA error:\\n\\nsomething broke\\n'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "easyrsa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	c := New(&config.EasyRSAConfig{Path: dir, PKIDir: dir}, false)

	err := c.GenCRL()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "easyrsa gen-crl") || !strings.Contains(msg, "something broke") {
		t.Errorf("error lacks the command or EasyRSA's message: %q", msg)
	}
	if strings.Contains(msg, "+++") {
		t.Errorf("error contains key-generation noise: %q", msg)
	}
}

// A CA key with a passphrase can't be unlocked without a terminal; the error
// says so instead of leaving the user to decode OpenSSL's messages.
func TestRunExplainsMissingTerminalForPassphrase(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'Provider routines:epki2pki_decode:unable to get passphrase' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "easyrsa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	err := New(&config.EasyRSAConfig{Path: dir, PKIDir: dir}, false).GenCRL()
	if err == nil || !strings.Contains(err.Error(), "run cvpnctl in a terminal") {
		t.Errorf("err = %v, want the passphrase hint", err)
	}
}

func TestCAEncrypted(t *testing.T) {
	for name, tt := range map[string]struct {
		key  string // first line of private/ca.key; "" means no file
		want bool
	}{
		"encrypted":   {"-----BEGIN ENCRYPTED PRIVATE KEY-----", true},
		"unencrypted": {"-----BEGIN PRIVATE KEY-----", false},
		"missing":     {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.key != "" {
				if err := os.MkdirAll(filepath.Join(dir, "private"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "private", "ca.key"), []byte(tt.key+"\nAAAA\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := New(&config.EasyRSAConfig{PKIDir: dir}, false).CAEncrypted(); got != tt.want {
				t.Errorf("CAEncrypted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRevokedSerials(t *testing.T) {
	dir := t.TempDir()
	index := "V\t290115152257Z\t\t0AB12\tunknown\t/CN=alice\n" +
		"R\t270420223927Z\t261013150000Z\t0cd34\tunknown\t/CN=bob\n" +
		"R\t250120210018Z\t261013150000Z\tEF56\tunknown\t/CN=carol\n"
	if err := os.WriteFile(filepath.Join(dir, "index.txt"), []byte(index), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := New(&config.EasyRSAConfig{PKIDir: dir}, false).RevokedSerials()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["CD34"] || !got["EF56"] {
		t.Errorf("RevokedSerials() = %v, want CD34 and EF56", got)
	}
}

func TestIndex(t *testing.T) {
	dir := t.TempDir()
	index := "V\t290115152257Z\t\t0AB12\tunknown\t/CN=alice\n" +
		"R\t270420223927Z\t261013150000Z\t0cd34\tunknown\t/CN=bob\n" +
		"R\t250120210018Z\t261013150000Z,keyCompromise\tEF56\tunknown\t/C=CH/CN=carol/O=x\n"
	if err := os.WriteFile(filepath.Join(dir, "index.txt"), []byte(index), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := New(&config.EasyRSAConfig{PKIDir: dir}, false).Index()
	if err != nil {
		t.Fatal(err)
	}
	want := []IndexEntry{{"V", "AB12", "alice"}, {"R", "CD34", "bob"}, {"R", "EF56", "carol"}}
	if len(got) != len(want) {
		t.Fatalf("Index() = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
