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
	"io"
	"os"
	"strings"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/delivery"
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

	// NewPresigner signs the .ovpn download links in S3 mode.
	NewPresigner func(context.Context, *config.Config) (delivery.Presigner, error)
}

// env is everything a lifecycle command works with.
type env struct {
	cfg   *config.Config
	ws    store.Workspace
	users *state.Store
	pki   *easyrsa.Client
	cloud provider.CertStore
	ovpn  *ovpn.Generator

	deliver *delivery.Deliverer // nil in local mode
	s3      store.S3API         // nil in local mode
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
	return o.loadWith(ctx, cfg, mode, command)
}

// loadWith is load for a config the caller has already loaded.
func (o *Options) loadWith(ctx context.Context, cfg *config.Config, mode store.Mode, command string) (*env, error) {
	if err := easyrsa.New(&cfg.EasyRSA, o.Verbose).CheckVersion(); err != nil {
		return nil, err
	}
	cloud, err := o.NewProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	e, err := o.newEnv(ctx, cfg, mode, command)
	if err != nil {
		return nil, err
	}
	e.cloud = cloud
	return e, nil
}

// newEnv opens the workspace and everything that works in it, without a
// provider: list and link need none.
func (o *Options) newEnv(ctx context.Context, cfg *config.Config, mode store.Mode, command string) (*env, error) {
	ws, client, err := o.openWorkspace(ctx, cfg, mode, command)
	if err != nil {
		return nil, err
	}
	e := &env{
		cfg:  cfg,
		ws:   ws,
		s3:   client,
		pki:  easyrsa.New(&config.EasyRSAConfig{Path: cfg.EasyRSA.Path, PKIDir: ws.PKIDir()}, o.Verbose),
		ovpn: ovpn.New(&config.OVPNConfig{Template: ws.TemplatePath(), OutputDir: ws.OutDir()}),
	}
	if e.users, err = state.Load(ws.StateDir()); err != nil {
		e.close()
		return nil, err
	}
	if cfg.S3Mode() {
		if o.NewPresigner == nil {
			e.close()
			return nil, errors.New("S3 mode is not available in this build")
		}
		p, err := o.NewPresigner(ctx, cfg)
		if err != nil {
			e.close()
			return nil, err
		}
		e.deliver = delivery.New(client, p, *cfg.Store)
	}
	return e, nil
}

// openWorkspace opens the local directories, or in S3 mode the store, and
// returns the S3 client it uses (nil locally).
func (o *Options) openWorkspace(ctx context.Context, cfg *config.Config, mode store.Mode, command string) (store.Workspace, store.S3API, error) {
	if !cfg.S3Mode() {
		ws, err := store.Open(ctx, cfg, mode, store.Deps{})
		return ws, nil, err
	}
	if o.NewS3 == nil {
		return nil, nil, errors.New("S3 mode is not available in this build")
	}
	client, caller, err := o.NewS3(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	d := store.Deps{S3: client, Command: command}
	if mode != store.Read { // the lock and the archive record who wrote them
		if d.Caller, err = caller(ctx); err != nil {
			return nil, nil, err
		}
	}
	ws, err := store.Open(ctx, cfg, mode, d)
	return ws, client, err
}

// linkHours resolves --link-hours: 0 means the configured default. Links only
// exist in S3 mode.
func linkHours(cfg *config.Config, flag int) (int, error) {
	if !cfg.S3Mode() {
		if flag != 0 {
			return 0, errors.New("--link-hours requires `store` in the config")
		}
		return 0, nil
	}
	hours := flag
	if hours == 0 {
		hours = cfg.Store.LinkHours
	}
	if hours < 1 || hours > delivery.MaxHours {
		return 0, fmt.Errorf("link_hours must be 1–%d, got %d", delivery.MaxHours, hours)
	}
	return hours, nil
}

// publish uploads user's rendered .ovpn and prints the link.
func (e *env) publish(ctx context.Context, user string, hours int) (string, error) {
	data, err := os.ReadFile(e.ovpn.Path(user))
	if err != nil {
		return "", err
	}
	var url string
	var expires time.Time
	err = step("uploading the .ovpn", ".ovpn uploaded", func() (string, error) {
		// As for a CRL push: after a forced unlock, another admin may have
		// renewed user since, and this older certificate would replace
		// their link.
		if err := e.ws.Verify(ctx); err != nil {
			return "", fmt.Errorf("the link was not published: %w; run cvpnctl link -u %s once nobody else is running cvpnctl", err, user)
		}
		var err error
		if url, expires, err = e.deliver.Publish(ctx, user, data, hours); err != nil {
			return "", err
		}
		return "link valid until " + expires.Local().Format("2006-01-02 15:04"), nil
	})
	if err == nil && time.Until(expires) < time.Duration(hours)*time.Hour-time.Minute {
		ui.Warn("the link stops working when your AWS credentials expire, at %s, not after %d h; for a longer link, use a longer session or an IAM user, or run cvpnctl link later",
			expires.Local().Format("2006-01-02 15:04"), hours)
	}
	return url, err
}

// sendLink prints the closing lines that hand a link to the admin. note, if
// set, is a sentence put first, e.g. "The previous link no longer works."
func sendLink(user, url, note string) {
	if note != "" {
		note += " "
	}
	ui.Done("%sSend this link to %s directly; it contains their private key:", note, user)
	fmt.Println(url)
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

// issue builds a certificate for user, imports it into the cloud store,
// records it in state, copies it to the per-user directory, and renders the .ovpn.
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
		if errors.Is(err, store.ErrUploadUnknown) {
			// The stored PKI may already record the certificate: undoing
			// it in ACM or the PKI could break a user who is saved.
			err = fmt.Errorf("%w\ncertificate %s was imported to ACM; if cvpnctl list does not show it as %s's PROVIDER ID, delete it from ACM by hand", err, id, user)
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

	// Per-user copies only exist in local mode: S3 mode leaves nothing on disk.
	// They are made once the certificate is recorded, so a failed import never
	// leaves a key on disk that the PKI no longer knows.
	if !e.ws.Remote() {
		if err := step("saving the files", "files saved", func() (string, error) {
			dir, err := e.pki.CopyToUserDir(user, e.cfg.Certs.OutputDir)
			return ui.Path(dir) + "/", err
		}); err != nil {
			return nil, err
		}
	}

	var ovpnPath string
	done := ".ovpn written"
	if e.ws.Remote() {
		done = ".ovpn rendered" // into the temp folder; delivered by link
	}
	if err := step("writing the .ovpn", done, func() (string, error) {
		var err error
		ovpnPath, err = e.ovpn.Generate(user, files)
		if e.ws.Remote() {
			return "", err
		}
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
//
// It first checks that the lock is still ours and the store unchanged: after
// a forced unlock, another admin may have revoked someone since, and our
// older CRL would let that user back in. A force in the moment between the
// check and the push is still possible, but no longer a whole command long.
func (e *env) pushCRL(ctx context.Context) error {
	return step("pushing the CRL", "CRL pushed", func() (string, error) {
		if err := e.ws.Verify(ctx); err != nil {
			return "", fmt.Errorf("the CRL was not pushed: %w; once nobody else is running cvpnctl, run cvpnctl push-crl", err)
		}
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
	answer, err := readAnswer()
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// confirmTyped asks the user to type word to go ahead, for actions where a
// reflexive "y" is too easy. Like confirm, it refuses without a terminal.
func confirmTyped(prompt, word string) (bool, error) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false, errors.New("stdin is not a terminal; this can only be confirmed interactively")
	}
	fmt.Printf("%s ", prompt)
	answer, err := readAnswer()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(answer) == word, nil
}

// readAnswer reads one line from stdin. Closed input (EOF, as from
// /dev/null, which passes the terminal check) counts as no answer.
func readAnswer() (string, error) {
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if errors.Is(err, io.EOF) && answer == "" {
		fmt.Println()
		return "", errors.New("no answer (stdin closed); aborted")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return answer, nil
}
