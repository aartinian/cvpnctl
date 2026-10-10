package command

import (
	"context"
	"fmt"

	"github.com/aartinian/ovpncert/internal/ui"
	"github.com/spf13/cobra"
)

// NewCreateCmd returns the create subcommand.
func NewCreateCmd(opts *Options) *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "create --user <username>",
		Short: "Issue a certificate for a new user and write their .ovpn",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCreate(cmd.Context(), opts, user)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "username (required)")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func runCreate(ctx context.Context, opts *Options, user string) error {
	if err := validateUser(user); err != nil {
		return err
	}
	e, err := opts.load(ctx)
	if err != nil {
		return err
	}

	if _, ok := e.users.Get(user); ok {
		return fmt.Errorf("user %q already exists; use 'ovpncert renew' to reissue their certificate", user)
	}
	if e.pki.HasCert(user) {
		return fmt.Errorf("the PKI already has a certificate for %q that ovpncert does not track; revoke it with easyrsa or choose another username", user)
	}

	ui.Step("Creating VPN certificate for %q", user)
	iss, err := e.issue(ctx, user)
	if err != nil {
		return err
	}

	ui.Success("certificate created for %q", user)
	printIssued(iss)
	fmt.Println("\nSend the .ovpn file to the user securely.")
	return nil
}

func printIssued(iss *issued) {
	ui.Field("cert dir", iss.userDir)
	ui.Field("provider", iss.providerID)
	ui.Field(".ovpn", iss.ovpnPath)
}
