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
	pki := easyrsa.New(&cfg.EasyRSA)
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
	providerID string
	userDir    string
	ovpnPath   string
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
			}
		}
	}()

	ui.Info("generating certificate via EasyRSA")
	if err := e.pki.BuildCert(user); err != nil {
		return nil, err
	}

	ui.Info("copying certificate to per-user directory")
	dir, err := e.pki.CopyToUserDir(user, e.cfg.Certs.OutputDir)
	if err != nil {
		return nil, err
	}

	ui.Info("importing certificate to cloud provider")
	files := e.pki.Files(user)
	id, err := e.cloud.ImportCert(ctx, files.Cert, files.Key, files.CA)
	if err != nil {
		return nil, err
	}

	e.users.Set(user, id)
	if err := e.users.Save(); err != nil {
		return nil, fmt.Errorf("%w (certificate %s was imported but not recorded; delete it from the provider by hand)", err, id)
	}
	recorded = true

	ui.Info("writing .ovpn config file")
	ovpnPath, err := e.ovpn.Generate(user, files)
	if err != nil {
		return nil, err
	}

	return &issued{providerID: id, userDir: dir, ovpnPath: ovpnPath}, nil
}

// revokeLocal revokes user's certificate in the PKI and regenerates the CRL.
// If the PKI has no issued certificate for user, an earlier interrupted run
// already revoked it, so only the CRL is regenerated.
func (e *env) revokeLocal(user string) error {
	if !e.pki.HasCert(user) {
		ui.Warn("no issued certificate for %q in the PKI; assuming an earlier run already revoked it", user)
		ui.Info("regenerating CRL")
		return e.pki.GenCRL()
	}
	ui.Info("revoking certificate in the PKI")
	return e.pki.Revoke(user)
}

// pushCRL uploads the current CRL to the VPN endpoint.
func (e *env) pushCRL(ctx context.Context) error {
	ui.Info("importing CRL to VPN endpoint")
	return e.cloud.ImportCRL(ctx, e.pki.CRLPath())
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
