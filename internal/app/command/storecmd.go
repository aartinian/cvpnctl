package command

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/state"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewStoreCmd returns the store command and its subcommands.
func NewStoreCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "store",
		Short: "Manage the shared PKI in S3",
		Args:  cobra.NoArgs,
	}
	var from string
	migrate := &cobra.Command{
		Use:   "migrate --from <local config>",
		Short: "Upload a local PKI into an empty store",
		Long: `Upload the PKI, the state file and the .ovpn template named in a local-mode
config into the store of the active (S3-mode) config. The bucket's settings
are checked first; an existing PKI in the store is never overwritten; the
upload is verified file by file. Nothing local is deleted, and nothing
changes in AWS or for users.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrate(cmd.Context(), opts, from)
		},
	}
	migrate.Flags().StringVar(&from, "from", "", "the local-mode config whose PKI to upload (required)")
	_ = migrate.MarkFlagRequired("from")

	var details string
	versions := &cobra.Command{
		Use:   "versions",
		Short: "List the stored versions of the PKI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVersions(cmd.Context(), opts, details)
		},
	}
	versions.Flags().StringVar(&details, "details", "", "show the users and revocations held by this version")

	var yes bool
	restore := &cobra.Command{
		Use:   "restore <version>",
		Short: "Make an earlier version of the PKI the current one",
		Long: `Make an earlier stored version of the PKI the current one, as a new version
on top (nothing is deleted). It shows what changes first. If the restored
state would un-revoke certificates (revoked now, valid in that version), or
lose track of valid ones (issued after that version, so it couldn't revoke
them), it names them and asks you to type 'restore'; --yes is not accepted then.
Restore never pushes a CRL: check with 'cvpnctl status' afterwards.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestore(cmd.Context(), opts, args[0], yes)
		},
	}
	restore.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation (refused if the restore would un-revoke certificates or lose track of valid ones)")

	cmd.AddCommand(migrate, versions, restore)
	return cmd
}

func runMigrate(ctx context.Context, opts *Options, from string) error {
	cfg, err := opts.loadConfig()
	if err != nil {
		return err
	}
	if !cfg.S3Mode() {
		return errors.New("store migrate requires `store` in the config; pass the local config with --from")
	}
	src, err := config.Load(from)
	if err != nil {
		return err
	}
	if src.S3Mode() {
		return fmt.Errorf("--from %s must be a local-mode config (without store)", from)
	}
	if err := easyrsa.New(&cfg.EasyRSA, false).CheckVersion(); err != nil {
		return err
	}
	if opts.NewS3 == nil {
		return errors.New("S3 mode is not available in this build")
	}
	client, caller, err := opts.NewS3(ctx, cfg)
	if err != nil {
		return err
	}
	arn, err := caller(ctx)
	if err != nil {
		return err
	}
	sc := *cfg.Store

	ui.Title("Migrating the PKI to s3://%s/%s", sc.Bucket, sc.Prefix)
	problems, err := store.CheckBucket(ctx, client, sc)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		ui.Fail("checking the bucket")
		msg := "the bucket isn't set up for cvpnctl; fix these settings and run migrate again:"
		for _, p := range problems {
			msg += fmt.Sprintf("\n  - %s %s", p.What, p.Detail)
		}
		return errors.New(msg)
	}
	ui.OK("bucket checked", "versioning, KMS, public access blocked")

	host, _ := os.Hostname()
	lock, err := store.Acquire(ctx, client, sc, store.LockInfo{ARN: arn, Host: host, PID: os.Getpid(), Command: "store migrate", Started: time.Now().UTC()})
	if err != nil {
		return err
	}
	defer func() {
		relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := lock.Release(relCtx); err != nil {
			ui.Warn("%v", err)
		}
	}()
	if deleted, err := store.Deleted(ctx, client, sc); err != nil {
		return err
	} else if deleted {
		return store.ErrStoreDeleted
	}
	if version, exists, err := store.Head(ctx, client, sc); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("%w (version %s); migrate never overwrites it", store.ErrStoreExists, version)
	}

	staging, err := store.TempDir()
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	var files map[string][32]byte
	if err := step("packing the PKI", "PKI packed", func() (string, error) {
		if err := stage(src, staging); err != nil {
			return "", err
		}
		var err error
		files, err = checksums(staging)
		return fmt.Sprintf("%d files", len(files)), err
	}); err != nil {
		return err
	}
	archive, err := store.Pack(staging)
	if err != nil {
		return err
	}

	var version string
	if err := step("uploading", "uploaded", func() (string, error) {
		var err error
		version, err = store.Create(ctx, client, sc, archive, arn)
		return "version " + shortVersion(version), err
	}); err != nil {
		return err
	}
	if err := step("verifying the upload", "verified", func() (string, error) {
		n, err := verifyArchive(archive, files)
		return fmt.Sprintf("%d files identical; CA, index and CRL readable", n), err
	}); err != nil {
		return fmt.Errorf("%w\nthe archive is in the store (version %s) but doesn't match the local PKI; inspect it before using it", err, version)
	}

	ui.Done("Next: run 'cvpnctl status'. Once everything is ✓, delete the local copies yourself (%s, %s, %s) and keep one encrypted backup off this machine.",
		ui.Path(src.EasyRSA.PKIDir), ui.Path(src.Certs.OutputDir), ui.Path(src.OVPN.OutputDir))
	return nil
}

// stage copies a local setup into dir in the archive's layout: pki/, state/
// (if there is a state file yet) and template/base.ovpn.
func stage(src *config.Config, dir string) error {
	if err := copyTree(src.EasyRSA.PKIDir, filepath.Join(dir, "pki")); err != nil {
		return err
	}
	stateFile := filepath.Join(src.Certs.OutputDir, state.Filename)
	switch _, err := os.Stat(stateFile); {
	case err == nil:
		if err := copyFile(stateFile, filepath.Join(dir, "state", state.Filename)); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		// Unreadable is not absent: migrating without it would drop every
		// user's ACM mapping.
		return err
	}
	return copyFile(src.OVPN.Template, filepath.Join(dir, "template", "base.ovpn"))
}

// copyTree copies regular files and directories; anything else (a symlink,
// a device) is refused, as the archive couldn't hold it anyway.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type().IsRegular():
			return copyFile(p, target)
		default:
			return fmt.Errorf("%s is not a regular file or directory; the store can't hold it", p)
		}
	})
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// checksums returns the SHA-256 of every file under dir, by relative path.
func checksums(dir string) (map[string][32]byte, error) {
	sums := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == ".pid" && filepath.Dir(p) == dir {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		sums[filepath.ToSlash(rel)] = sha256.Sum256(data)
		return nil
	})
	return sums, err
}

// verifyArchive unpacks archive and checks every file against want, and that
// the CA, the index and (if present) the CRL can be read.
func verifyArchive(archive []byte, want map[string][32]byte) (int, error) {
	dir, err := store.TempDir()
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := store.Unpack(archive, dir); err != nil {
		return 0, err
	}
	got, err := checksums(dir)
	if err != nil {
		return 0, err
	}
	if len(got) != len(want) {
		return 0, fmt.Errorf("the archive holds %d files, the local PKI %d", len(got), len(want))
	}
	for p, sum := range want {
		if got[p] != sum {
			return 0, fmt.Errorf("%s differs in the archive", p)
		}
	}
	pki := easyrsa.New(&config.EasyRSAConfig{PKIDir: filepath.Join(dir, "pki")}, false)
	if _, err := pki.CACert(); err != nil {
		return 0, err
	}
	if _, err := pki.RevokedSerials(); err != nil {
		return 0, err
	}
	if _, err := os.Stat(pki.CRLPath()); err == nil {
		if _, _, err := pki.CRLInfo(); err != nil {
			return 0, err
		}
	}
	return len(got), nil
}
