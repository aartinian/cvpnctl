package command

import (
	"context"
	"errors"
	"fmt"

	"github.com/aartinian/ovpncert/internal/easyrsa"
	"github.com/aartinian/ovpncert/internal/ui"
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

func runRevoke(ctx context.Context, opts *Options, user string, yes bool) error {
	if err := validateUser(user); err != nil {
		return err
	}
	e, err := opts.load(ctx)
	if err != nil {
		return err
	}

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

	ui.Step("Revoking VPN certificate for %q", user)

	if err := e.revokeLocal(user); err != nil {
		return err
	}
	if err := e.pushCRL(ctx); err != nil {
		return err
	}
	if record.ProviderID != "" {
		ui.Info("deleting certificate from cloud provider")
		if err := e.cloud.DeleteCert(ctx, record.ProviderID); err != nil {
			return err
		}
	}

	// The VPN endpoint and the provider are done with this user. Drop the
	// record before the local cleanup: leftover files are harmless, but a
	// record pointing at a deleted certificate is not.
	e.users.Delete(user)
	if err := e.users.Save(); err != nil {
		return err
	}

	ui.Info("removing per-user directory and .ovpn file")
	if err := easyrsa.RemoveUserDir(e.cfg.Certs.OutputDir, user); err != nil {
		return err
	}
	if err := e.ovpn.Remove(user); err != nil {
		return err
	}

	ui.Success("certificate for %q revoked and all files removed", user)
	return nil
}
