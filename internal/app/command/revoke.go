package command

import (
	"context"
	"errors"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewRevokeCmd returns the revoke subcommand.
func NewRevokeCmd(opts *Options) *cobra.Command {
	var (
		user string
		yes  bool
	)
	cmd := &cobra.Command{
		Use:   "revoke --user <username>",
		Short: "Revoke a user's certificate and delete all their files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRevoke(cmd.Context(), opts, user, yes)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "username (required)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

// runRevoke takes user's access away, in an order that is safe to resume:
// revoke in the PKI and save, push the CRL (which is what ends access), then
// remove the link and the ACM entry, and only then the user's record, so that
// a re-run after any failure still knows what is left to do.
func runRevoke(ctx context.Context, opts *Options, user string, yes bool) error {
	if err := validateUser(user); err != nil {
		return err
	}
	e, err := opts.load(ctx, store.Write, "revoke "+user)
	if err != nil {
		return err
	}
	defer e.close()

	record, ok := e.users.Get(user)
	if !ok {
		return fmt.Errorf("user %q not found; nothing to revoke", user)
	}

	if !yes {
		ok, err := confirm(fmt.Sprintf("Revoke the certificate for %q and delete their files? This cannot be undone.", user))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}

	ui.Title("Revoking %s", user)

	if err := e.revokeLocal(ctx, user, "certificate revoked"); err != nil {
		return err
	}
	if err := e.pushCRL(ctx); err != nil {
		return err
	}
	if e.ws.Remote() {
		if err := step("removing the link", "link removed", func() (string, error) {
			return "", e.deliver.Remove(ctx, user)
		}); err != nil {
			return err
		}
	}
	if record.ProviderID != "" {
		if err := e.deleteCert(ctx, record.ProviderID, "deleting the ACM entry", "ACM entry deleted"); err != nil {
			return err
		}
	}

	// The VPN endpoint and the provider are done with this user. Drop the
	// record before the local cleanup: leftover files are harmless, but a
	// record pointing at a deleted certificate is not.
	e.users.Delete(user)
	if err := e.save(ctx); err != nil {
		return err
	}
	e.saved()

	if !e.ws.Remote() { // S3 mode keeps no per-user files on disk
		if err := step("removing the files", "files removed", func() (string, error) {
			if err := easyrsa.RemoveUserDir(e.cfg.Certs.OutputDir, user); err != nil {
				return "", err
			}
			return ui.Path(easyrsa.UserDir(e.cfg.Certs.OutputDir, user)) + "/, " + ui.Path(e.ovpn.Path(user)), e.ovpn.Remove(user)
		}); err != nil {
			return err
		}
	}
	ui.Done("%s can no longer connect; an open session ends within about a minute.", user)
	return nil
}
