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
	"github.com/aartinian/cvpnctl/internal/ui"
)

// Options is shared by all subcommands. NewProvider is a field rather than a
// direct call so tests can substitute a fake certificate store.
type Options struct {
	ConfigFile  string
	Verbose     bool // show EasyRSA's own output as it runs
	NewProvider func(context.Context, *config.Config) (provider.CertStore, error)
}

// env is everything a lifecycle command works with.
type env struct {
	cfg   *config.Config
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

func (o *Options) load(ctx context.Context) (*env, error) {
	cfg, err := o.loadConfig()
	if err != nil {
		return nil, err
	}
	pki := easyrsa.New(&cfg.EasyRSA, o.Verbose)
	if err := pki.CheckVersion(); err != nil {
		return nil, err
	}
	users, err := state.Load(cfg.Certs.OutputDir)
	if err != nil {
		return nil, err
	}
	cloud, err := o.NewProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &env{
		cfg:   cfg,
		users: users,
		pki:   pki,
		cloud: cloud,
		ovpn:  ovpn.New(&cfg.OVPN),
	}, nil
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
	defer func() {
		if err != nil && !recorded {
			if rmErr := e.pki.RemoveCertFiles(user); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("cleaning up after failure: %w", rmErr))
			} else {
				ui.Note("removed the unfinished certificate from the PKI; the command can simply be run again")
			}
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

	if err := step("saving the files", "files saved", func() (string, error) {
		dir, err := e.pki.CopyToUserDir(user, e.cfg.Certs.OutputDir)
		return ui.Path(dir) + "/", err
	}); err != nil {
		return nil, err
	}

	files := e.pki.Files(user)
	var id string
	if err := step("importing to ACM", "imported to ACM", func() (string, error) {
		var err error
		if id, err = e.cloud.ImportCert(ctx, files.Cert, files.Key, files.CA); err != nil {
			return "", err
		}
		e.users.Set(user, id)
		if err := e.users.Save(); err != nil {
			return "", fmt.Errorf("%w (certificate %s was imported but not recorded; delete it from the provider by hand)", err, id)
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
func (e *env) revokeLocal(user, done string) error {
	if !e.pki.HasCert(user) {
		ui.Warn("no issued certificate for %q in the PKI; assuming an earlier run already revoked it", user)
		e.passphraseHint("regenerating the CRL", 1)
		return step("regenerating the CRL", "CRL regenerated", func() (string, error) {
			return "", e.pki.GenCRL()
		})
	}
	// Revoking asks twice: once to revoke, once to regenerate the CRL.
	e.passphraseHint("revoking in the PKI", 2)
	return step("revoking in the PKI", done, func() (string, error) {
		return "in the PKI", e.pki.Revoke(user)
	})
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
