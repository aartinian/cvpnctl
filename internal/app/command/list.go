package command

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/aartinian/ovpncert/internal/config"
	"github.com/aartinian/ovpncert/internal/easyrsa"
	"github.com/aartinian/ovpncert/internal/state"
	"github.com/spf13/cobra"
)

// NewListCmd returns the list subcommand.
func NewListCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List managed users with certificate expiry and provider IDs",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runList(opts)
		},
	}
}

// runList reads only the config, the state file, and the PKI; it needs no
// cloud credentials.
func runList(opts *Options) error {
	cfg, err := config.Load(opts.ConfigFile)
	if err != nil {
		return err
	}
	users, err := state.Load(cfg.Certs.OutputDir)
	if err != nil {
		return err
	}

	records := users.All()
	if len(records) == 0 {
		fmt.Println("no users found")
		return nil
	}

	pki := easyrsa.New(&cfg.EasyRSA)
	// tabwriter buffers until Flush, which reports any write error, so the
	// individual row writes need no checks of their own.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "USER\tEXPIRES\tCREATED\tUPDATED\tPROVIDER ID")
	for _, r := range records {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.User,
			certExpiry(pki.Files(r.User).Cert),
			r.CreatedAt.Format(time.DateOnly),
			r.UpdatedAt.Format(time.DateOnly),
			r.ProviderID,
		)
	}
	return w.Flush()
}

// certExpiry returns the expiry date of the certificate at path, or a short
// explanation if it cannot be read.
func certExpiry(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(no cert)"
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "(unreadable)"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "(unreadable)"
	}
	return cert.NotAfter.Format(time.DateOnly)
}
