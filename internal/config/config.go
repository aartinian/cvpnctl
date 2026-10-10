// Package config loads and validates the ovpncert.yaml configuration file.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the full tool configuration loaded from ovpncert.yaml.
type Config struct {
	Provider string        `mapstructure:"provider"` // "aws" (the default and only option)
	EasyRSA  EasyRSAConfig `mapstructure:"easyrsa"`
	Certs    CertsConfig   `mapstructure:"certs"`
	AWS      AWSConfig     `mapstructure:"aws"`
	OVPN     OVPNConfig    `mapstructure:"ovpn"`
}

// EasyRSAConfig points to the EasyRSA installation and its PKI directory.
type EasyRSAConfig struct {
	Path   string `mapstructure:"path"`    // directory containing the easyrsa script
	PKIDir string `mapstructure:"pki_dir"` // initialised PKI (ca.crt, issued/, private/, ...)
}

// CertsConfig controls where per-user certificate copies and the state file live.
type CertsConfig struct {
	OutputDir string `mapstructure:"output_dir"`
}

// AWSConfig holds the profile, region, and Client VPN endpoint for the AWS provider.
type AWSConfig struct {
	Region        string `mapstructure:"region"`
	Profile       string `mapstructure:"profile"`         // optional; empty uses the default credential chain
	VPNEndpointID string `mapstructure:"vpn_endpoint_id"` // CRLs are pushed here on revoke and renew
}

// OVPNConfig points to the base template and the per-user output directory.
type OVPNConfig struct {
	Template  string `mapstructure:"template"`
	OutputDir string `mapstructure:"output_dir"`
}

// Load reads, expands, and validates the configuration file. Without an
// explicit path it uses the first file found by FindConfig.
func Load(path string) (*Config, error) {
	if path == "" {
		found, err := FindConfig()
		if err != nil {
			return nil, err
		}
		path = found
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if cfg.Provider == "" {
		cfg.Provider = "aws"
	}

	if err := expandPaths(&cfg); err != nil {
		return nil, err
	}
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, path)
	}
	return &cfg, nil
}

// SearchPaths lists, in order, where FindConfig looks for the config file.
func SearchPaths() []string {
	paths := []string{"ovpncert.yaml"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "ovpncert", "ovpncert.yaml"))
	}
	return append(paths, "/etc/ovpncert/ovpncert.yaml")
}

// FindConfig returns the first existing file from SearchPaths.
//
// It matches exact file names rather than using Viper's search, which also
// accepts a file named just "ovpncert" once a config type is set, and so
// would try to parse the ovpncert binary itself when run from its directory.
func FindConfig() (string, error) {
	paths := SearchPaths()
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("config: no config file found (looked for %s); use --config", strings.Join(paths, ", "))
}

// ExpandPath resolves a leading ~ to the user's home directory and makes the
// result absolute. Go does not expand ~ itself, so a value like "~/certs"
// would otherwise be used as a directory literally named "~".
func ExpandPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}

	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: expand %q: %w", p, err)
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	case strings.HasPrefix(p, "~"):
		return "", fmt.Errorf("config: %q: ~user paths are not supported, use an absolute path", p)
	}

	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("config: resolve %q: %w", p, err)
	}
	return abs, nil
}

func expandPaths(cfg *Config) error {
	for _, p := range []*string{
		&cfg.EasyRSA.Path,
		&cfg.EasyRSA.PKIDir,
		&cfg.Certs.OutputDir,
		&cfg.OVPN.Template,
		&cfg.OVPN.OutputDir,
	} {
		expanded, err := ExpandPath(*p)
		if err != nil {
			return err
		}
		*p = expanded
	}
	return nil
}

// validate checks required fields and the files they point to. Everything a
// command depends on is checked here, before it makes any change, so a typo in
// the config can never leave a command half-finished.
func validate(cfg *Config) error {
	required := []struct {
		val  string
		name string
	}{
		{cfg.EasyRSA.Path, "easyrsa.path"},
		{cfg.EasyRSA.PKIDir, "easyrsa.pki_dir"},
		{cfg.Certs.OutputDir, "certs.output_dir"},
		{cfg.OVPN.Template, "ovpn.template"},
		{cfg.OVPN.OutputDir, "ovpn.output_dir"},
	}
	for _, r := range required {
		if r.val == "" {
			return fmt.Errorf("config: %s is required", r.name)
		}
	}

	switch cfg.Provider {
	case "aws":
		if cfg.AWS.Region == "" {
			return errors.New("config: aws.region is required")
		}
		if cfg.AWS.VPNEndpointID == "" {
			return errors.New("config: aws.vpn_endpoint_id is required")
		}
	default:
		return fmt.Errorf("config: provider %q is not supported (supported: aws)", cfg.Provider)
	}

	if err := requireFile(filepath.Join(cfg.EasyRSA.Path, "easyrsa"), "easyrsa script"); err != nil {
		return err
	}
	if err := requireFile(filepath.Join(cfg.EasyRSA.PKIDir, "ca.crt"), "CA certificate (is easyrsa.pki_dir an initialised PKI?)"); err != nil {
		return err
	}
	return requireFile(cfg.OVPN.Template, "ovpn template")
}

func requireFile(path, what string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: %s not found at %s", what, path)
	}
	if fi.IsDir() {
		return fmt.Errorf("config: %s at %s is a directory", what, path)
	}
	return nil
}
