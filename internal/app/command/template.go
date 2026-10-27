package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/ovpn"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// NewTemplateCmd returns the template command and its show/set subcommands.
func NewTemplateCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Show or replace the .ovpn template kept in the store (S3 mode)",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "show",
			Short: "Print the stored .ovpn template",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runTemplateShow(cmd.Context(), opts)
			},
		},
		&cobra.Command{
			Use:   "set <file>",
			Short: "Replace the stored .ovpn template, after checking it renders",
			Long: `Replace the .ovpn template kept in the store. The new template is first
rendered with a test user; if it uses an unknown field or is otherwise
invalid, nothing is changed. Files issued from then on use it; existing users
get it with their next renew or link.`,
			Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return runTemplateSet(cmd.Context(), opts, args[0])
			},
		},
	)
	return cmd
}

// templateConfig loads the config and requires S3 mode: locally the template
// is a file named in the config, edited directly.
func templateConfig(opts *Options) (*config.Config, error) {
	cfg, err := opts.loadConfig()
	if err != nil {
		return nil, err
	}
	if !cfg.S3Mode() {
		return nil, errors.New("template requires `store` in the config; in local mode, edit the file at ovpn.template")
	}
	return cfg, nil
}

func runTemplateShow(ctx context.Context, opts *Options) error {
	cfg, err := templateConfig(opts)
	if err != nil {
		return err
	}
	ws, _, err := opts.openWorkspace(ctx, cfg, store.Read, "template show")
	if err != nil {
		return err
	}
	defer closeWorkspace(ws)
	data, err := os.ReadFile(ws.TemplatePath())
	if err != nil {
		return fmt.Errorf("the store has no template yet; set one with 'cvpnctl template set <file>'")
	}
	_, err = os.Stdout.Write(data)
	return err
}

func runTemplateSet(ctx context.Context, opts *Options, file string) error {
	cfg, err := templateConfig(opts)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	ws, _, err := opts.openWorkspace(ctx, cfg, store.Write, "template set")
	if err != nil {
		return err
	}
	defer closeWorkspace(ws)

	ui.Title("Updating the template")
	if err := step("checking that it renders", "template renders", func() (string, error) {
		return "", checkTemplate(data, ws)
	}); err != nil {
		return err
	}
	if err := os.WriteFile(ws.TemplatePath(), data, 0o600); err != nil {
		return err
	}
	if err := ws.Checkpoint(ctx); err != nil {
		return err
	}
	ui.OK("saved to S3", "version "+shortVersion(ws.Version()))
	ui.Done("New .ovpn files use it; existing users get it with their next renew or link.")
	return nil
}

// checkTemplate renders data for a test user, using the PKI's CA certificate
// in place of the certificate and key: only the template is being checked.
func checkTemplate(data []byte, ws store.Workspace) error {
	dir, err := os.MkdirTemp(ws.OutDir(), "check-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	tmpl := filepath.Join(dir, "base.ovpn")
	if err := os.WriteFile(tmpl, data, 0o600); err != nil {
		return err
	}
	ca := filepath.Join(ws.PKIDir(), "ca.crt")
	_, err = ovpn.New(&config.OVPNConfig{Template: tmpl, OutputDir: dir}).
		Generate("template-check", easyrsa.Files{Cert: ca, Key: ca, CA: ca})
	return err
}

func closeWorkspace(ws store.Workspace) {
	if err := ws.Close(context.Background()); err != nil {
		ui.Warn("%v", err)
	}
}
