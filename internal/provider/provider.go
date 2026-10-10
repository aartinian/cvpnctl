// Package provider defines the interface for cloud certificate store backends.
// Commands depend only on this interface; the concrete implementation is
// selected from the config's provider field.
package provider

import (
	"context"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/provider/aws"
)

// CertStore manages certificates in a cloud provider.
type CertStore interface {
	// ImportCert uploads a certificate, its private key, and the CA chain
	// and returns an opaque identifier (e.g. an ACM ARN).
	ImportCert(ctx context.Context, certFile, keyFile, caFile string) (string, error)

	// DeleteCert removes the certificate identified by id. Deleting a
	// certificate that no longer exists is not an error, so an interrupted
	// command can be re-run.
	DeleteCert(ctx context.Context, id string) error

	// ImportCRL uploads a certificate revocation list so the VPN endpoint
	// refuses connections from revoked certificates.
	ImportCRL(ctx context.Context, crlFile string) error
}

// New returns the CertStore for the provider named in cfg.
func New(ctx context.Context, cfg *config.Config) (CertStore, error) {
	switch cfg.Provider {
	case "aws":
		return aws.New(ctx, &cfg.AWS)
	default:
		return nil, fmt.Errorf("provider %q is not supported (supported: aws)", cfg.Provider)
	}
}
