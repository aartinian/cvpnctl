package command

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/state"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
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
// provider credentials (in S3 mode, only read access to the store).
func runList(opts *Options) error {
	ctx := context.Background()
	cfg, err := opts.loadConfig()
	if err != nil {
		return err
	}
	ws, _, err := opts.openWorkspace(ctx, cfg, store.Read, "list")
	if err != nil {
		return err
	}
	defer func() {
		if err := ws.Close(ctx); err != nil {
			ui.Warn("%v", err)
		}
	}()
	users, err := state.Load(ws.StateDir())
	if err != nil {
		return err
	}

	records := users.All()
	if len(records) == 0 {
		fmt.Println("no users found")
		return nil
	}

	pki := easyrsa.New(&config.EasyRSAConfig{Path: cfg.EasyRSA.Path, PKIDir: ws.PKIDir()}, false)
	now := time.Now()
	// tabwriter buffers until Flush, which reports any write error, so the
	// individual row writes need no checks of their own.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintf(w, "USER\t%s\tCREATED\tUPDATED\tPROVIDER ID\n", ui.Cell("EXPIRES", ui.Normal))
	for _, r := range records {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.User,
			expiryCell(pki, r.User, now),
			r.CreatedAt.Format(time.DateOnly),
			r.UpdatedAt.Format(time.DateOnly),
			r.ProviderID,
		)
	}
	return w.Flush()
}

// expiryCell shows when user's certificate expires: yellow within 30 days,
// red once expired.
func expiryCell(pki *easyrsa.Client, user string, now time.Time) string {
	exp, err := pki.Expiry(user)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ui.Cell("(no cert)", ui.Critical)
	case err != nil:
		return ui.Cell("(unreadable)", ui.Critical)
	case now.After(exp):
		return ui.Cell(exp.Format(time.DateOnly), ui.Critical)
	case exp.Sub(now) < 30*24*time.Hour:
		return ui.Cell(exp.Format(time.DateOnly), ui.Attention)
	default:
		return ui.Cell(exp.Format(time.DateOnly), ui.Normal)
	}
}
