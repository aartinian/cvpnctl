package command

import (
	"context"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewLinkCmd returns the link subcommand.
func NewLinkCmd(opts *Options) *cobra.Command {
	var (
		user  string
		hours int
	)
	cmd := &cobra.Command{
		Use:   "link --user <username>",
		Short: "Issue a new .ovpn link for a user, without a new certificate (S3 mode)",
		Long: `Render the user's .ovpn again from the stored PKI and print a fresh
download link. The certificate stays the same; the user's previous link
stops working. Use it when a link expired or got lost.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLink(cmd.Context(), opts, user, hours)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "username (required)")
	cmd.Flags().IntVar(&hours, "link-hours", 0, "how long the link is valid, 1–168 (default: store.link_hours)")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

// runLink takes the lock although it changes nothing in the PKI: otherwise a
// link running alongside a renew of the same user could read the old
// certificate and publish it over the renew's new link. It never checkpoints.
func runLink(ctx context.Context, opts *Options, user string, hoursFlag int) error {
	if err := validateUser(user); err != nil {
		return err
	}
	cfg, err := opts.loadS3Config("link", "")
	if err != nil {
		return err
	}
	hours, err := linkHours(cfg, hoursFlag)
	if err != nil {
		return err
	}
	e, err := opts.newEnv(ctx, cfg, store.Write, "link "+user)
	if err != nil {
		return err
	}
	defer e.close()

	if _, ok := e.users.Get(user); !ok {
		return fmt.Errorf("user %q not found", user)
	}
	if !e.pki.HasCert(user) {
		return fmt.Errorf("the stored PKI has no certificate for %q; renew it with 'cvpnctl renew -u %s'", user, user)
	}

	ui.Title("New link for %s", user)
	if err := step("rendering the .ovpn", ".ovpn rendered", func() (string, error) {
		_, err := e.ovpn.Generate(user, e.pki.Files(user))
		return "", err
	}); err != nil {
		return err
	}
	url, err := e.publish(ctx, user, hours)
	if err != nil {
		return err
	}
	sendLink(user, url, "The previous link no longer works.")
	return nil
}
