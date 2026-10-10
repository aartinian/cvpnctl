package command

import (
	"context"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewRenewCmd returns the renew subcommand.
func NewRenewCmd(opts *Options) *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "renew --user <username>",
		Short: "Reissue an existing user's certificate and revoke the old one",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRenew(cmd.Context(), opts, user)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "username (required)")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

// runRenew reissues user's certificate under the same name.
//
// EasyRSA frees a name only by revoking its certificate, so the old one is
// revoked in the local PKI first. The VPN endpoint keeps accepting it until the
// CRL is pushed, which happens only once the new certificate is fully in place:
// a failure before that leaves the user's current .ovpn working, and running
// renew again picks up where this run stopped.
func runRenew(ctx context.Context, opts *Options, user string) error {
	if err := validateUser(user); err != nil {
		return err
	}
	e, err := opts.load(ctx)
	if err != nil {
		return err
	}

	record, ok := e.users.Get(user)
	if !ok {
		return fmt.Errorf("user %q not found; use 'cvpnctl create' first", user)
	}
	oldID := record.ProviderID

	ui.Step("Renewing VPN certificate for %q", user)

	if err := e.revokeLocal(user); err != nil {
		return err
	}

	iss, err := e.issue(ctx, user)
	if err != nil {
		return err
	}

	if err := e.pushCRL(ctx); err != nil {
		return fmt.Errorf("%w\nthe new certificate is in place, but the VPN endpoint still accepts the old one: "+
			"run 'cvpnctl push-crl', then delete %s from the provider", err, oldID)
	}

	if oldID != "" {
		ui.Info("deleting old certificate from cloud provider")
		if err := e.cloud.DeleteCert(ctx, oldID); err != nil {
			return fmt.Errorf("%w\nthe renewal is otherwise complete; delete %s from the provider by hand", err, oldID)
		}
	}

	ui.Success("certificate renewed for %q", user)
	printIssued(iss)
	fmt.Println("\nSend the new .ovpn file to the user securely; the old one no longer works.")
	return nil
}
