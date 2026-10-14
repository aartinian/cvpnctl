// Package ui prints the output shared by all subcommands: a title, one line
// per completed step, warnings, and a closing line.
//
// Normal output goes to stdout, warnings and failures to stderr. Colour is
// used only when the stream is a terminal and NO_COLOR is not set
// (https://no-color.org), so output piped to a file or another program stays
// plain.
package ui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	red    = "\x1b[31m"
	dim    = "\x1b[2m"
	bold   = "\x1b[1m"
	plain  = "\x1b[39m" // default foreground; same length as the colours above
	reset  = "\x1b[0m"
)

var (
	stdout   io.Writer = os.Stdout
	stderr   io.Writer = os.Stderr
	colorOut           = useColor(os.Stdout)
	colorErr           = useColor(os.Stderr)
)

func useColor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// line writes s and a newline. A failed write to the terminal is ignored:
// there is nothing useful to do about it, and the command's result does not
// depend on it.
func line(w io.Writer, s string) {
	_, _ = fmt.Fprintln(w, s)
}

func paint(on bool, color, s string) string {
	if !on {
		return s
	}
	return color + s + reset
}

// Title prints the line that starts a command, e.g. "Creating alice".
func Title(format string, args ...any) {
	line(stdout, paint(colorOut, bold, fmt.Sprintf(format, args...)))
}

// OK prints a completed step: "  ✓ label   detail".
func OK(label, detail string) {
	msg := "  " + paint(colorOut, green, "✓") + " " + label
	if detail != "" {
		msg = fmt.Sprintf("  %s %-26s %s", paint(colorOut, green, "✓"), label, detail)
	}
	line(stdout, msg)
}

// Fail prints the step that failed: "  ✗ label". The error itself is printed
// by the caller.
func Fail(label string) {
	line(stderr, "  "+paint(colorErr, red, "✗")+" "+label)
}

// Warn prints a non-fatal problem: "  ! message".
func Warn(format string, args ...any) {
	line(stderr, "  "+paint(colorErr, yellow, "!")+" "+fmt.Sprintf(format, args...))
}

// Note prints a secondary detail, such as what was cleaned up after a failure.
func Note(format string, args ...any) {
	line(stderr, "  "+paint(colorErr, dim, "· "+fmt.Sprintf(format, args...)))
}

// Done prints the closing line of a successful command.
func Done(format string, args ...any) {
	line(stdout, fmt.Sprintf("Done. "+format, args...))
}

// Path shortens a path under the home directory to start with ~.
func Path(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if rel, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
		return "~/" + rel
	}
	return p
}

// Level is how urgent a value shown in a table is.
type Level int

const (
	Normal Level = iota
	Attention
	Critical
)

// Cell colours s for a table column. Every cell gets an escape sequence of
// the same length, coloured or not, so that a tabwriter (which counts bytes)
// still lines the columns up. Without colour, s is returned unchanged.
func Cell(s string, level Level) string {
	if !colorOut {
		return s
	}
	switch level {
	case Attention:
		return yellow + s + reset
	case Critical:
		return red + s + reset
	default:
		return plain + s + reset
	}
}

// Mark returns the status symbol for level: ✓, ! or ✗, coloured like Cell so
// a table stays aligned.
func Mark(level Level) string {
	switch level {
	case Attention:
		return paint(colorOut, yellow, "!")
	case Critical:
		return paint(colorOut, red, "✗")
	default:
		return paint(colorOut, green, "✓")
	}
}
