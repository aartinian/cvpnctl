// Package ui prints the progress output shared by all subcommands.
package ui

import (
	"fmt"
	"os"
)

// Step prints a top-level action header.
func Step(format string, args ...any) {
	fmt.Printf("\n"+format+"\n", args...)
}

// Info prints a sub-step progress line.
func Info(format string, args ...any) {
	fmt.Printf("  → "+format+"\n", args...)
}

// Warn prints a non-fatal problem to stderr.
func Warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  ! "+format+"\n", args...)
}

// Success prints a completion message.
func Success(format string, args ...any) {
	fmt.Printf("\n✓ "+format+"\n", args...)
}

// Field prints an aligned label/value line under a Success message.
func Field(label, value string) {
	fmt.Printf("  %-9s %s\n", label, value)
}
