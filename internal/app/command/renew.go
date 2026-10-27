package command

import (
	"context"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewRenewCmd returns the renew subcommand.
func NewRenewCmd(opts *Options) *cobra.Command {
	var (
		user  string
		hours int
	)
	cmd := &cobra.Command{
		Use:   "renew --user <username>",
		Short: "Reissue an existing user's certificate and revoke the old one",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRenew(cmd.Context(), opts, user, hours)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "username (required)")
	cmd.Flags().IntVar(&hours, "link-hours", 0, "how long the .ovpn link is valid, 1–168 (S3 mode; default: store.link_hours)")
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
func runRenew(ctx context.Context, opts *Options, user string, hoursFlag int) error {
	if err := validateUser(user); err != nil {
		return err
	}
	e, err := opts.load(ctx, store.Write, "renew "+user)
	if err != nil {
		return err
	}
	defer e.close()

	record, ok := e.users.Get(user)
	if !ok {
		return fmt.Errorf("user %q not found; use 'cvpnctl create' first", user)
	}
	oldID := record.ProviderID
	hours, err := linkHours(e.cfg, hoursFlag)
	if err != nil {
		return err
	}

	ui.Title("Renewing %s", user)

	if err := e.revokeLocal(ctx, user, "old certificate revoked"); err != nil {
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
		if err := e.deleteCert(ctx, oldID, "deleting the old ACM entry", "old ACM entry deleted"); err != nil {
			return fmt.Errorf("%w\nthe renewal is otherwise complete; delete %s from the provider by hand", err, oldID)
		}
	}

	e.saved()
	if e.ws.Remote() {
		url, err := e.publish(ctx, user, hours)
		if err != nil {
			return fmt.Errorf("%w\nthe renewal is complete; run 'cvpnctl link -u %s' to get the new link", err, user)
		}
		sendLink(user, url, "Their old .ovpn no longer works.")
		return nil
	}
	ui.Done("Send %s to %s securely; the old one no longer works.", ui.Path(iss.ovpnPath), user)
	return nil
}
