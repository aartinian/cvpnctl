// Package ovpn renders per-user .ovpn config files from a base template.
package ovpn

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aartinian/ovpncert/internal/config"
	"github.com/aartinian/ovpncert/internal/easyrsa"
	"github.com/aartinian/ovpncert/internal/fsutil"
)

// Data is what a template can reference. CA, Cert, and Key are complete
// <ca>, <cert>, and <key> blocks, ready to be dropped into the config.
type Data struct {
	User string
	CA   string
	Cert string
	Key  string
}

// Generator renders per-user .ovpn files from a base template.
type Generator struct {
	cfg *config.OVPNConfig
}

// New returns a Generator configured from cfg.
func New(cfg *config.OVPNConfig) *Generator {
	return &Generator{cfg: cfg}
}

// Path returns where user's .ovpn file is written.
func (g *Generator) Path(user string) string {
	return filepath.Join(g.cfg.OutputDir, user+".ovpn")
}

// Generate renders the template with user's certificate, key, and CA and
// writes it to Path(user). The file embeds the private key, so it is written
// with mode 0600.
func (g *Generator) Generate(user string, files easyrsa.Files) (string, error) {
	tmpl, err := template.ParseFiles(g.cfg.Template)
	if err != nil {
		return "", fmt.Errorf("ovpn: parse template: %w", err)
	}

	data := Data{User: user}
	for _, part := range []struct {
		tag, path string
		dst       *string
	}{
		{"ca", files.CA, &data.CA},
		{"cert", files.Cert, &data.Cert},
		{"key", files.Key, &data.Key},
	} {
		block, err := readPEM(part.path)
		if err != nil {
			return "", fmt.Errorf("ovpn: %w", err)
		}
		*part.dst = fmt.Sprintf("<%s>\n%s</%s>", part.tag, block, part.tag)
	}

	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", fmt.Errorf("ovpn: render template: %w", err)
	}

	if err := os.MkdirAll(g.cfg.OutputDir, 0o700); err != nil {
		return "", fmt.Errorf("ovpn: %w", err)
	}
	path := g.Path(user)
	if err := fsutil.WriteFile(path, out.Bytes(), 0o600); err != nil {
		return "", fmt.Errorf("ovpn: %w", err)
	}
	return path, nil
}

// readPEM returns only the PEM blocks in path. EasyRSA prefixes issued
// certificates with a human-readable dump, which has no place in a client config.
func readPEM(path string) (string, error) {
	rest, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if err := pem.Encode(&out, block); err != nil {
			return "", err
		}
	}
	if out.Len() == 0 {
		return "", fmt.Errorf("%s contains no PEM data", path)
	}
	return out.String(), nil
}

// Remove deletes user's .ovpn file. A missing file is not an error.
func (g *Generator) Remove(user string) error {
	if err := os.Remove(g.Path(user)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("ovpn: %w", err)
	}
	return nil
}
