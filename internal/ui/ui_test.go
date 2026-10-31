package ui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture redirects stdout and stderr and sets the colour switches for one test.
func capture(t *testing.T, color bool) (out, errOut *bytes.Buffer) {
	t.Helper()
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	oldOut, oldErr, oldCO, oldCE := stdout, stderr, colorOut, colorErr
	stdout, stderr, colorOut, colorErr = out, errOut, color, color
	t.Cleanup(func() { stdout, stderr, colorOut, colorErr = oldOut, oldErr, oldCO, oldCE })
	return out, errOut
}

func TestPlainOutput(t *testing.T) {
	out, errOut := capture(t, false)
	Title("Creating %s", "max")
	OK("certificate issued", "expires 2029-01-15")
	OK("CRL regenerated", "")
	Fail("importing to ACM")
	Warn("careful %d", 1)
	Done("Send it.")

	wantOut := "Creating max\n" +
		"  ✓ certificate issued         expires 2029-01-15\n" +
		"  ✓ CRL regenerated\n" +
		"Done. Send it.\n"
	if out.String() != wantOut {
		t.Errorf("stdout:\n%q\nwant:\n%q", out.String(), wantOut)
	}
	if want := "  ✗ importing to ACM\n  ! careful 1\n"; errOut.String() != want {
		t.Errorf("stderr: %q, want %q", errOut.String(), want)
	}
	if strings.Contains(out.String()+errOut.String(), "\x1b[") {
		t.Error("escape codes in plain output")
	}
}

func TestColouredOutput(t *testing.T) {
	out, _ := capture(t, true)
	OK("certificate issued", "")
	if !strings.Contains(out.String(), green+"✓"+reset) {
		t.Errorf("no green tick in %q", out.String())
	}
}

// Every cell carries an escape sequence of the same length, so a tabwriter,
// which counts bytes, keeps the columns aligned whatever the colour.
func TestCellLengthsMatch(t *testing.T) {
	capture(t, true)
	n, a, c := Cell("2029-01-15", Normal), Cell("2029-01-15", Attention), Cell("2029-01-15", Critical)
	if len(n) != len(a) || len(a) != len(c) {
		t.Errorf("cell lengths differ: %d %d %d", len(n), len(a), len(c))
	}
	capture(t, false)
	if got := Cell("2029-01-15", Critical); got != "2029-01-15" {
		t.Errorf("plain cell = %q", got)
	}
}

func TestNoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if useColor(os.Stdout) {
		t.Error("NO_COLOR set, but colour is on")
	}
}

func TestPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	tests := map[string]string{
		home:                                 "~",
		filepath.Join(home, "vpn", "a.ovpn"): "~/vpn/a.ovpn",
		"/etc/cvpnctl/cvpnctl.yaml":          "/etc/cvpnctl/cvpnctl.yaml",
		home + "-other/x":                    home + "-other/x",
	}
	for in, want := range tests {
		if got := Path(in); got != want {
			t.Errorf("Path(%q) = %q, want %q", in, got, want)
		}
	}
}
