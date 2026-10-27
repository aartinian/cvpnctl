// Package config loads and validates the cvpnctl.yaml configuration file.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the full tool configuration loaded from cvpnctl.yaml.
type Config struct {
	Provider string        `mapstructure:"provider"` // "aws" (the default and only option)
	EasyRSA  EasyRSAConfig `mapstructure:"easyrsa"`
	Certs    CertsConfig   `mapstructure:"certs"`
	AWS      AWSConfig     `mapstructure:"aws"`
	OVPN     OVPNConfig    `mapstructure:"ovpn"`
	// Store, if set, keeps the PKI, the state and the template in S3 instead
	// of local directories ("S3 mode"). Nil means local mode.
	Store *StoreConfig `mapstructure:"store"`

	// Path is the absolute path of the file this config was loaded from.
	Path string `mapstructure:"-"`
	// Ignored lists config files that also exist further down the search
	// order and were therefore not used.
	Ignored []string `mapstructure:"-"`
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

// StoreConfig locates the shared PKI in S3.
type StoreConfig struct {
	Bucket    string `mapstructure:"bucket"`
	Prefix    string `mapstructure:"prefix"`     // optional; normalised to end with "/"
	KMSKeyID  string `mapstructure:"kms_key_id"` // key ID, ARN or alias
	LinkHours int    `mapstructure:"link_hours"` // default validity of .ovpn links, 1–168
}

// DefaultLinkHours is how long a .ovpn link is valid unless configured.
const DefaultLinkHours = 24

// S3Mode reports whether the PKI lives in S3 rather than in local directories.
func (c *Config) S3Mode() bool {
	return c.Store != nil
}

// Key returns the S3 object key for name under the configured prefix.
func (s StoreConfig) Key(name string) string {
	return s.Prefix + name
}

// Load reads, expands, and validates the configuration file. Without an
// explicit path it uses the first file found by FindConfig. Errors name the
// file by its absolute path, so it is clear which config was read.
func Load(path string) (*Config, error) {
	var ignored []string
	if path == "" {
		found, others, err := FindConfig()
		if err != nil {
			return nil, err
		}
		path, ignored = found, others
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}

	// Name the file in every error, and say when it shadows another one: a
	// stray ./cvpnctl.yaml is exactly the case where that matters most.
	where := path
	if len(ignored) > 0 {
		where += ", which takes precedence over " + strings.Join(ignored, ", ")
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", where, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", where, err)
	}
	if cfg.Provider == "" {
		cfg.Provider = "aws"
	}
	if st := cfg.Store; st != nil {
		if st.Prefix != "" && !strings.HasSuffix(st.Prefix, "/") {
			st.Prefix += "/"
		}
		if st.LinkHours == 0 {
			st.LinkHours = DefaultLinkHours
		}
	}

	if err := expandPaths(&cfg); err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, where)
	}
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, where)
	}
	cfg.Path, cfg.Ignored = path, ignored
	return &cfg, nil
}

// SearchPaths lists, in order, where FindConfig looks for the config file.
func SearchPaths() []string {
	paths := []string{"cvpnctl.yaml"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "cvpnctl", "cvpnctl.yaml"))
	}
	return append(paths, "/etc/cvpnctl/cvpnctl.yaml")
}

// FindConfig returns the first existing file from SearchPaths, as an absolute
// path, plus any further existing files that it takes precedence over.
//
// It matches exact file names rather than using Viper's search, which also
// accepts a file named just "cvpnctl" once a config type is set, and so
// would try to parse the cvpnctl binary itself when run from its directory.
func FindConfig() (found string, ignored []string, err error) {
	paths := SearchPaths()
	for _, p := range paths {
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if found == "" {
			found = p
		} else {
			ignored = append(ignored, p)
		}
	}
	if found == "" {
		return "", nil, fmt.Errorf("config: no config file found (looked for %s); use --config", strings.Join(paths, ", "))
	}
	return found, ignored, nil
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
	if cfg.EasyRSA.Path == "" {
		return errors.New("config: easyrsa.path is required")
	}
	local := []struct {
		val  string
		name string
	}{
		{cfg.EasyRSA.PKIDir, "easyrsa.pki_dir"},
		{cfg.Certs.OutputDir, "certs.output_dir"},
		{cfg.OVPN.Template, "ovpn.template"},
		{cfg.OVPN.OutputDir, "ovpn.output_dir"},
	}
	if cfg.S3Mode() {
		// In S3 mode these live in the store. Refusing them means no local
		// path can quietly be used instead of the shared PKI.
		for _, l := range local {
			if l.val != "" {
				return fmt.Errorf("config: %s is not allowed with store (the PKI, state and template live in S3)", l.name)
			}
		}
		if err := validateStore(cfg.Store); err != nil {
			return err
		}
	} else {
		for _, l := range local {
			if l.val == "" {
				return fmt.Errorf("config: %s is required", l.name)
			}
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
	if cfg.S3Mode() {
		return nil // the CA and template are checked once the store is read
	}
	if err := requireFile(filepath.Join(cfg.EasyRSA.PKIDir, "ca.crt"), "CA certificate (is easyrsa.pki_dir an initialised PKI?)"); err != nil {
		return err
	}
	return requireFile(cfg.OVPN.Template, "ovpn template")
}

func validateStore(st *StoreConfig) error {
	switch {
	case st.Bucket == "":
		return errors.New("config: store.bucket is required")
	case st.KMSKeyID == "":
		return errors.New("config: store.kms_key_id is required")
	case st.LinkHours < 1 || st.LinkHours > 168:
		return fmt.Errorf("config: store.link_hours must be 1–168, got %d", st.LinkHours)
	}
	return nil
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
