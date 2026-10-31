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
only when the command holding it has crashed or been killed.

If that command is in fact still running, its next save fails instead of
overwriting newer work, and it checks the lock again right before pushing a
CRL. Whatever it was doing in that moment, such as importing a certificate to
ACM or pushing a CRL, can still complete, so run cvpnctl status afterwards.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnlock(cmd.Context(), opts, yes)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

// runUnlock shows the lock and removes it after confirmation, but only if it
// is still the lock that was shown (see store.ForceUnlock).
func runUnlock(ctx context.Context, opts *Options, yes bool) error {
	cfg, err := opts.loadS3Config("unlock", "")
	if err != nil {
		return err
	}
	client, _, err := opts.s3(ctx, cfg)
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
	if err := store.ForceUnlock(ctx, client, *cfg.Store, info.ETag); err != nil {
		if errors.Is(err, store.ErrLockChanged) {
			return fmt.Errorf("%w; run cvpnctl unlock again to see who holds it now", err)
		}
		return err
	}
	ui.Done("Lock removed. If that command was still running, run cvpnctl status once it has stopped: what it was doing in that moment may have completed.")
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
