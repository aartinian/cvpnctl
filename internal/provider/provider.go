// Package provider defines the interface for cloud certificate store backends.
// Commands depend only on this interface; the concrete implementation is
// selected from the config's provider field (see internal/app).
package provider

import (
	"context"
	"time"
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

	// The methods below only read. They back `cvpnctl status`.

	// EndpointCerts returns the IDs of the endpoint's server certificate and
	// of its client root certificate chain.
	EndpointCerts(ctx context.Context) (serverID, clientRootID string, err error)

	// CertInfo returns the name and expiry of the certificate identified by
	// id. found is false, without an error, if it doesn't exist.
	CertInfo(ctx context.Context, id string) (name string, notAfter time.Time, found bool, err error)

	// ExportCRL returns the CRL the endpoint currently holds, in PEM, or nil
	// if it has none.
	ExportCRL(ctx context.Context) ([]byte, error)
}
