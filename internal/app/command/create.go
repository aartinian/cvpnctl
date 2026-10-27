package command

import (
	"context"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewCreateCmd returns the create subcommand.
func NewCreateCmd(opts *Options) *cobra.Command {
	var (
		user  string
		hours int
	)
	cmd := &cobra.Command{
		Use:   "create --user <username>",
		Short: "Issue a certificate for a new user and write their .ovpn",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCreate(cmd.Context(), opts, user, hours)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "username (required)")
	cmd.Flags().IntVar(&hours, "link-hours", 0, "how long the .ovpn link is valid, 1–168 (S3 mode; default: store.link_hours)")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func runCreate(ctx context.Context, opts *Options, user string, hoursFlag int) error {
	if err := validateUser(user); err != nil {
		return err
	}
	e, err := opts.load(ctx, store.Write, "create "+user)
	if err != nil {
		return err
	}
	defer e.close()
	hours, err := linkHours(e.cfg, hoursFlag)
	if err != nil {
		return err
	}

	if _, ok := e.users.Get(user); ok {
		return fmt.Errorf("user %q already exists; use 'cvpnctl renew' to reissue their certificate", user)
	}
	if e.pki.HasCert(user) {
		return fmt.Errorf("the PKI already has a certificate for %q that cvpnctl does not track; revoke it with easyrsa or choose another username", user)
	}

	ui.Title("Creating %s", user)
	iss, err := e.issue(ctx, user)
	if err != nil {
		return err
	}

	e.saved()
	if e.ws.Remote() {
		url, err := e.publish(ctx, user, hours)
		if err != nil {
			return fmt.Errorf("%w\nthe certificate for %s is created; run 'cvpnctl link -u %s' to get its link", err, user, user)
		}
		sendLink(user, url, "")
		return nil
	}
	ui.Done("Send %s to %s securely.", ui.Path(iss.ovpnPath), user)
	return nil
}
