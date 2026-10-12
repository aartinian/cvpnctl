package easyrsa

import (
	"strings"
	"testing"
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
