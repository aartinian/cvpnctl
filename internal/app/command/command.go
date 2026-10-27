// Package command implements the cvpnctl subcommands.
//
// Every lifecycle command follows the same rule: everything that can be
// checked up front (username, config, PKI, credentials) is checked before the
// first change, and every command can simply be run again if it fails partway.
package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/ovpn"
	"github.com/aartinian/cvpnctl/internal/provider"
	"github.com/aartinian/cvpnctl/internal/state"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
)

// Options is shared by all subcommands. NewProvider and NewS3 are fields
// rather than direct calls so tests can substitute fakes.
type Options struct {
	ConfigFile  string
	Verbose     bool // show EasyRSA's own output as it runs
	NewProvider func(context.Context, *config.Config) (provider.CertStore, error)

	// NewS3 returns the S3 client for S3 mode, and a lookup of the caller's
	// IAM ARN, which is only called by commands that take the lock.
	NewS3 func(context.Context, *config.Config) (store.S3API, func(context.Context) (string, error), error)
}

// env is everything a lifecycle command works with.
type env struct {
	cfg   *config.Config
	ws    store.Workspace
	users *state.Store
	pki   *easyrsa.Client
	cloud provider.CertStore
	ovpn  *ovpn.Generator
}

// loadConfig loads the config and warns about config files it overrides:
// a ./cvpnctl.yaml silently taking precedence over ~/.config/cvpnctl is easy
// to miss otherwise.
func (o *Options) loadConfig() (*config.Config, error) {
	cfg, err := config.Load(o.ConfigFile)
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.Ignored {
		ui.Warn("using %s; ignoring %s", cfg.Path, p)
	}
	return cfg, nil
}

// load prepares a lifecycle command. Everything that can fail without side
// effects (config, EasyRSA version, AWS credentials) is checked before the
// workspace is opened, so a failure there never holds the lock. In S3 mode a
// Write workspace takes the lock; the caller must always defer e.close().
func (o *Options) load(ctx context.Context, mode store.Mode, command string) (*env, error) {
	cfg, err := o.loadConfig()
	if err != nil {
		return nil, err
	}
	if err := easyrsa.New(&cfg.EasyRSA, o.Verbose).CheckVersion(); err != nil {
		return nil, err
	}
	cloud, err := o.NewProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ws, err := o.openWorkspace(ctx, cfg, mode, command)
	if err != nil {
		return nil, err
	}
	users, err := state.Load(ws.StateDir())
	if err != nil {
		_ = ws.Close(ctx)
		return nil, err
	}
	return &env{
		cfg:   cfg,
		ws:    ws,
		users: users,
		pki:   easyrsa.New(&config.EasyRSAConfig{Path: cfg.EasyRSA.Path, PKIDir: ws.PKIDir()}, o.Verbose),
		cloud: cloud,
		ovpn:  ovpn.New(&config.OVPNConfig{Template: ws.TemplatePath(), OutputDir: ws.OutDir()}),
	}, nil
}

// openWorkspace opens the local directories, or in S3 mode the store.
func (o *Options) openWorkspace(ctx context.Context, cfg *config.Config, mode store.Mode, command string) (store.Workspace, error) {
	if !cfg.S3Mode() {
		return store.Open(ctx, cfg, mode, store.Deps{})
	}
	if o.NewS3 == nil {
		return nil, errors.New("S3 mode is not available in this build")
	}
	client, caller, err := o.NewS3(ctx, cfg)
	if err != nil {
		return nil, err
	}
	d := store.Deps{S3: client, Command: command}
	if mode == store.Write {
		if d.Caller, err = caller(ctx); err != nil {
			return nil, err
		}
	}
	return store.Open(ctx, cfg, mode, d)
}

// save records the state and checkpoints the workspace. Locally that writes
// the state file; in S3 mode it also uploads the archive. Commands call it
// wherever a change must be durable before the next step: after an ACM
// import is recorded, and after a local revocation, before the CRL is pushed.
func (e *env) save(ctx context.Context) error {
	if err := e.users.Save(); err != nil {
		return err
	}
	return e.ws.Checkpoint(ctx)
}

// saved prints where an S3-mode command's changes ended up.
func (e *env) saved() {
	if e.ws.Remote() {
		ui.OK("saved to S3", "version "+shortVersion(e.ws.Version()))
	}
}

// close releases the workspace: in S3 mode it deletes the temp folder and
// releases the lock. Problems are only warned about, because the command's
// own result is already decided.
func (e *env) close() {
	if err := e.ws.Close(context.Background()); err != nil {
		ui.Warn("%v", err)
	}
}

func shortVersion(v string) string {
	if len(v) > 8 {
		return v[:8]
	}
	return v
}

// issued describes a freshly issued certificate.
type issued struct {
	ovpnPath string
}

// step runs fn and prints its outcome: "✓ done  detail" when it succeeds, or
// "✗ doing" when it fails. The error itself is printed by main.
func step(doing, done string, fn func() (detail string, err error)) error {
	detail, err := fn()
	if err != nil {
		ui.Fail(doing)
		return err
	}
	ui.OK(done, detail)
	return nil
}

// passphraseHint says which step the CA passphrase prompt that follows
// belongs to: each ✓ line only appears once its step is done, so the prompt
// would otherwise come without context. Shown only when the CA key is
// encrypted.
func (e *env) passphraseHint(doing string, prompts int) {
	if !e.pki.CAEncrypted() {
		return
	}
	if prompts > 1 {
		ui.Note("%s: CA passphrase needed (asked %d times)", doing, prompts)
		return
	}
	ui.Note("%s: CA passphrase needed", doing)
}

// shortID shortens a provider ID such as an ACM ARN for display.
func shortID(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	if len(id) > 8 {
		id = id[:8]
	}
	return "…/" + id
}

// crlDetail describes the current CRL, e.g. "31 revoked, valid until 2027-04-12".
func (e *env) crlDetail() string {
	n, next, err := e.pki.CRLInfo()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d revoked, valid until %s", n, next.Format(time.DateOnly))
}

// issue builds a certificate for user, copies it to the per-user directory,
// imports it into the cloud store, records it in state, and renders the .ovpn.
//
// Until the certificate is recorded in state, a failure deletes its files from
// the PKI again. The certificate was never handed out, so nothing needs
// revoking, and the command can be re-run straight away.
func (e *env) issue(ctx context.Context, user string) (_ *issued, err error) {
	recorded := false
	var id string // set once the certificate is imported
	defer func() {
		if err == nil || recorded {
			return
		}
		if rmErr := e.pki.RemoveCertFiles(user); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("cleaning up after failure: %w", rmErr))
		} else {
			ui.Note("removed the unfinished certificate from the PKI; the command can simply be run again")
		}
		if id == "" {
			return
		}
		// Imported but not recorded: delete it from the provider again, so
		// the provider never holds a certificate the state doesn't know.
		delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if delErr := e.cloud.DeleteCert(delCtx, id); delErr != nil {
			err = errors.Join(err, fmt.Errorf("certificate %s was imported but not recorded, and deleting it failed (%w); delete it from the provider by hand", id, delErr))
		} else {
			ui.Note("deleted the unrecorded certificate from the provider")
		}
	}()

	e.passphraseHint("issuing the certificate", 1)
	if err := step("issuing the certificate", "certificate issued", func() (string, error) {
		if err := e.pki.BuildCert(user); err != nil {
			return "", err
		}
		exp, err := e.pki.Expiry(user)
		if err != nil {
			return "", nil // issued fine; the detail is only cosmetic
		}
		return "expires " + exp.Format(time.DateOnly), nil
	}); err != nil {
		return nil, err
	}

	// Per-user copies only exist in local mode: S3 mode leaves nothing on disk.
	if !e.ws.Remote() {
		if err := step("saving the files", "files saved", func() (string, error) {
			dir, err := e.pki.CopyToUserDir(user, e.cfg.Certs.OutputDir)
			return ui.Path(dir) + "/", err
		}); err != nil {
			return nil, err
		}
	}

	files := e.pki.Files(user)
	if err := step("importing to ACM", "imported to ACM", func() (string, error) {
		var err error
		if id, err = e.cloud.ImportCert(ctx, files.Cert, files.Key, files.CA); err != nil {
			id = ""
			return "", err
		}
		e.users.Set(user, id)
		if err := e.save(ctx); err != nil {
			return "", err
		}
		recorded = true
		return shortID(id), nil
	}); err != nil {
		return nil, err
	}

	var ovpnPath string
	if err := step("writing the .ovpn", ".ovpn written", func() (string, error) {
		var err error
		ovpnPath, err = e.ovpn.Generate(user, files)
		return ui.Path(ovpnPath), err
	}); err != nil {
		return nil, err
	}

	return &issued{ovpnPath: ovpnPath}, nil
}

// revokeLocal revokes user's certificate in the PKI and regenerates the CRL,
// printing done on success. If the PKI has no issued certificate for user, an
// earlier interrupted run already revoked it, so only the CRL is regenerated.
//
// The revocation is saved (checkpointed) before it returns, so that the CRL
// push that follows never gets ahead of the stored PKI.
func (e *env) revokeLocal(ctx context.Context, user, done string) error {
	if !e.pki.HasCert(user) {
		ui.Warn("no issued certificate for %q in the PKI; assuming an earlier run already revoked it", user)
		e.passphraseHint("regenerating the CRL", 1)
		if err := step("regenerating the CRL", "CRL regenerated", func() (string, error) {
			return "", e.pki.GenCRL()
		}); err != nil {
			return err
		}
		return e.save(ctx)
	}
	// Revoking asks twice: once to revoke, once to regenerate the CRL.
	e.passphraseHint("revoking in the PKI", 2)
	if err := step("revoking in the PKI", done, func() (string, error) {
		return "in the PKI", e.pki.Revoke(user)
	}); err != nil {
		return err
	}
	return e.save(ctx)
}

// pushCRL uploads the current CRL to the VPN endpoint.
func (e *env) pushCRL(ctx context.Context) error {
	return step("pushing the CRL", "CRL pushed", func() (string, error) {
		if err := e.cloud.ImportCRL(ctx, e.pki.CRLPath()); err != nil {
			return "", err
		}
		return e.crlDetail(), nil
	})
}

// deleteCert removes a certificate from the provider, printing done on success.
func (e *env) deleteCert(ctx context.Context, id, doing, done string) error {
	return step(doing, done, func() (string, error) {
		return shortID(id), e.cloud.DeleteCert(ctx, id)
	})
}

// confirm asks a yes/no question on the terminal. It refuses to guess when
// stdin is not a terminal, so scripts have to opt in explicitly.
func confirm(question string) (bool, error) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false, errors.New("stdin is not a terminal; pass --yes to confirm")
	}
	fmt.Printf("%s [y/N] ", question)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
