package command

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewUnlockCmd returns the unlock subcommand.
func NewUnlockCmd(opts *Options) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Remove a lock left behind by a crashed command (S3 mode)",
		Long: `Show who holds the store's lock, and remove it after confirmation. Use it
only when the command holding it has crashed or been killed. If that command
is in fact still running, removing the lock is still safe: its next save fails
instead of overwriting newer work.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnlock(cmd.Context(), opts, yes)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

func runUnlock(ctx context.Context, opts *Options, yes bool) error {
	cfg, err := opts.loadConfig()
	if err != nil {
		return err
	}
	if !cfg.S3Mode() {
		return errors.New("unlock requires `store` in the config")
	}
	if opts.NewS3 == nil {
		return errors.New("S3 mode is not available in this build")
	}
	client, _, err := opts.NewS3(ctx, cfg)
	if err != nil {
		return err
	}
	info, held, err := store.ReadLock(ctx, client, *cfg.Store)
	if err != nil {
		return err
	}
	if !held {
		fmt.Println("no lock held")
		return nil
	}
	fmt.Printf("locked by %s\n  on %s (pid %d), running '%s'\n  since %s (%s ago)\n",
		info.ARN, info.Host, info.PID, info.Command, info.Started.Local().Format("2006-01-02 15:04"), age(time.Since(info.Started)))

	if !yes {
		ok, err := confirm("Remove the lock? Only do this if that command is no longer running.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}
	if err := store.ForceUnlock(ctx, client, *cfg.Store); err != nil {
		return err
	}
	ui.Done("Lock removed. If that command is still running, its next save will fail instead of overwriting newer work.")
	return nil
}

// age formats a duration as "3h05m" or "12m".
func age(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}
