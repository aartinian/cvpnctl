//go:build !unix

package store

import "time"

const staleAfter = time.Hour

// Sweep does nothing on platforms without Unix file ownership; cvpnctl is
// only built for Linux and macOS.
func Sweep(string, int, time.Duration) {}
