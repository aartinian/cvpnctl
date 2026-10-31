package command

import (
	"context"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewPushCRLCmd returns the push-crl subcommand.
func NewPushCRLCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "push-crl",
		Short: "Regenerate the CRL and import it to the VPN endpoint",
		Long: `Regenerate the CRL from the PKI and import it to the VPN endpoint.

revoke and renew do this automatically. Run it by hand to finish a renew whose
CRL push failed, or to refresh the CRL before it expires (EasyRSA's default
validity is 180 days).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPushCRL(cmd.Context(), opts)
		},
	}
}

// runPushCRL regenerates the CRL, which also renews its validity, and imports
// it to the endpoint.
func runPushCRL(ctx context.Context, opts *Options) error {
	e, err := opts.load(ctx, store.Write, "push-crl")
	if err != nil {
		return err
	}
	defer e.close()

	ui.Title("Pushing the CRL")
	e.passphraseHint("regenerating the CRL", 1)
	if err := step("regenerating the CRL", "CRL regenerated", func() (string, error) {
		return "", e.pki.GenCRL()
	}); err != nil {
		return err
	}
	// Save the regenerated CRL before pushing it, so the endpoint never holds
	// a CRL the stored PKI doesn't.
	if err := e.save(ctx); err != nil {
		return err
	}
	if err := e.pushCRL(ctx); err != nil {
		return err
	}
	e.saved()

	ui.Done("The endpoint has the current CRL.")
	return nil
}
