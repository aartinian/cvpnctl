// Package app wires the subcommands into the root Cobra command.
package app

import (
	"context"
	"errors"

	"github.com/aartinian/cvpnctl/internal/app/command"
	"github.com/aartinian/cvpnctl/internal/provider"
	"github.com/spf13/cobra"
)

// Run executes the CLI with args (without the program name).
func Run(ctx context.Context, version string, args []string) error {
	opts := &command.Options{NewProvider: provider.New}

	root := &cobra.Command{
		Use:   "cvpnctl",
		Short: "Manage OpenVPN client certificates with EasyRSA and AWS Client VPN",
		Long: `cvpnctl automates the lifecycle of OpenVPN client certificates:

  - issue and revoke certificates with EasyRSA
  - import them to AWS Certificate Manager and push the CRL to AWS Client VPN
  - write a ready-to-use .ovpn file per user`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("cvpnctl {{.Version}}\n")
	root.PersistentFlags().StringVarP(&opts.ConfigFile, "config", "c", "", "config file (default: search ./, ~/.config/cvpnctl/, /etc/cvpnctl/)")
	root.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "show EasyRSA's output as it runs")

	root.AddCommand(
		command.NewCreateCmd(opts),
		command.NewRenewCmd(opts),
		command.NewRevokeCmd(opts),
		command.NewListCmd(opts),
		command.NewPushCRLCmd(opts),
		command.NewStatusCmd(opts),
		command.NewLinkCmd(opts),
		command.NewTemplateCmd(opts),
		command.NewStoreCmd(opts),
		command.NewUnlockCmd(opts),
	)

	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}

// ExitCode maps the error Run returned to the process exit code: 0 for
// success, 2 when status found something that needs attention, 1 otherwise.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, command.ErrNeedsAttention):
		return 2
	default:
		return 1
	}
}
