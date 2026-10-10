// Package aws implements provider.CertStore using AWS ACM for certificate
// storage and the EC2 Client VPN API for CRL distribution.
package aws

import (
	"context"
	"fmt"
	"os"

	"github.com/aartinian/ovpncert/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Provider implements provider.CertStore against AWS ACM and EC2 Client VPN.
type Provider struct {
	acm        *acm.Client
	ec2        *ec2.Client
	endpointID string
}

// New returns a Provider configured from cfg.
func New(ctx context.Context, cfg *config.AWSConfig) (*Provider, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws: load config: %w", err)
	}

	return &Provider{
		acm:        acm.NewFromConfig(awsCfg),
		ec2:        ec2.NewFromConfig(awsCfg),
		endpointID: cfg.VPNEndpointID,
	}, nil
}

// ImportCert uploads the certificate, private key, and CA chain to ACM.
// All three files are required by AWS for a valid client certificate import.
func (p *Provider) ImportCert(ctx context.Context, certFile, keyFile, caFile string) (string, error) {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("aws: read cert: %w", err)
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("aws: read key: %w", err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return "", fmt.Errorf("aws: read CA: %w", err)
	}

	out, err := p.acm.ImportCertificate(ctx, &acm.ImportCertificateInput{
		Certificate:      cert,
		PrivateKey:       key,
		CertificateChain: ca,
	})
	if err != nil {
		return "", fmt.Errorf("aws: import certificate: %w", err)
	}

	return aws.ToString(out.CertificateArn), nil
}

// DeleteCert removes the certificate identified by arn from ACM.
func (p *Provider) DeleteCert(ctx context.Context, arn string) error {
	_, err := p.acm.DeleteCertificate(ctx, &acm.DeleteCertificateInput{
		CertificateArn: aws.String(arn),
	})
	if err != nil {
		return fmt.Errorf("aws: delete certificate: %w", err)
	}
	return nil
}

// ImportCRL uploads the CRL at crlFile to the configured Client VPN endpoint.
// This causes AWS to immediately refuse connections from revoked certificates.
func (p *Provider) ImportCRL(ctx context.Context, crlFile string) error {
	if p.endpointID == "" {
		return fmt.Errorf("aws: vpn_endpoint_id is required for CRL import")
	}

	data, err := os.ReadFile(crlFile)
	if err != nil {
		return fmt.Errorf("aws: read CRL: %w", err)
	}

	_, err = p.ec2.ImportClientVpnClientCertificateRevocationList(ctx,
		&ec2.ImportClientVpnClientCertificateRevocationListInput{
			ClientVpnEndpointId:       aws.String(p.endpointID),
			CertificateRevocationList: aws.String(string(data)),
		},
	)
	if err != nil {
		return fmt.Errorf("aws: import CRL to Client VPN endpoint: %w", err)
	}

	return nil
}
