// Command cvpnctl manages OpenVPN client certificates. See internal/app.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/aartinian/cvpnctl/internal/app"
)

// version is set by release builds: -ldflags "-X main.version=v1.2.3".
var version string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := app.Run(ctx, resolveVersion(), os.Args[1:])
	stop()
	code := app.ExitCode(err)
	if code == 1 {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	if code != 0 {
		os.Exit(code) // status has already reported what needs attention
	}
}

// resolveVersion prefers the release version, then the module version that
// `go install ...@vX.Y.Z` records, and falls back to "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
