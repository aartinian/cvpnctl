// Package aws implements provider.CertStore using AWS ACM for certificate
// storage and the EC2 Client VPN API for CRL distribution.
package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// acmAPI and ec2API are the parts of the AWS SDK clients the provider uses.
// Tests substitute fakes for them.
type acmAPI interface {
	ImportCertificate(context.Context, *acm.ImportCertificateInput, ...func(*acm.Options)) (*acm.ImportCertificateOutput, error)
	DeleteCertificate(context.Context, *acm.DeleteCertificateInput, ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error)
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

type ec2API interface {
	ImportClientVpnClientCertificateRevocationList(context.Context, *ec2.ImportClientVpnClientCertificateRevocationListInput, ...func(*ec2.Options)) (*ec2.ImportClientVpnClientCertificateRevocationListOutput, error)
	ExportClientVpnClientCertificateRevocationList(context.Context, *ec2.ExportClientVpnClientCertificateRevocationListInput, ...func(*ec2.Options)) (*ec2.ExportClientVpnClientCertificateRevocationListOutput, error)
	DescribeClientVpnEndpoints(context.Context, *ec2.DescribeClientVpnEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error)
}

// Provider implements provider.CertStore against AWS ACM and EC2 Client VPN.
type Provider struct {
	acm        acmAPI
	ec2        ec2API
	endpointID string
}

// LoadConfig returns the AWS SDK configuration for cfg's region and profile.
// It resolves credentials up front, so a missing profile or expired
// credentials fail before a command touches the PKI rather than at its first
// AWS call.
func LoadConfig(ctx context.Context, cfg *config.AWSConfig) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws: load config: %w", err)
	}
	if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
		return aws.Config{}, fmt.Errorf("aws: resolve credentials: %w", err)
	}
	return awsCfg, nil
}

// New returns a Provider configured from cfg.
func New(ctx context.Context, cfg *config.AWSConfig) (*Provider, error) {
	awsCfg, err := LoadConfig(ctx, cfg)
	if err != nil {
		return nil, err
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

// DeleteCert removes the certificate identified by arn from ACM. A
// certificate that is already gone counts as deleted, so an interrupted
// revoke or renew can simply be run again.
func (p *Provider) DeleteCert(ctx context.Context, arn string) error {
	_, err := p.acm.DeleteCertificate(ctx, &acm.DeleteCertificateInput{
		CertificateArn: aws.String(arn),
	})
	var notFound *acmtypes.ResourceNotFoundException
	if err != nil && !errors.As(err, &notFound) {
		return fmt.Errorf("aws: delete certificate %s: %w", arn, err)
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

// EndpointCerts returns the ARNs of the endpoint's server certificate and of
// the client root certificate chain used for mutual authentication.
func (p *Provider) EndpointCerts(ctx context.Context) (serverID, clientRootID string, err error) {
	out, err := p.ec2.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{
		ClientVpnEndpointIds: []string{p.endpointID},
	})
	if err != nil {
		return "", "", fmt.Errorf("aws: describe %s: %w", p.endpointID, err)
	}
	if len(out.ClientVpnEndpoints) == 0 {
		return "", "", fmt.Errorf("aws: endpoint %s not found", p.endpointID)
	}
	ep := out.ClientVpnEndpoints[0]
	for _, a := range ep.AuthenticationOptions {
		if a.MutualAuthentication != nil {
			clientRootID = aws.ToString(a.MutualAuthentication.ClientRootCertificateChain)
		}
	}
	return aws.ToString(ep.ServerCertificateArn), clientRootID, nil
}

// CertInfo returns the domain name and expiry of an ACM certificate.
func (p *Provider) CertInfo(ctx context.Context, arn string) (name string, notAfter time.Time, found bool, err error) {
	out, err := p.acm.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(arn)})
	var notFound *acmtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("aws: describe certificate %s: %w", arn, err)
	}
	return aws.ToString(out.Certificate.DomainName), aws.ToTime(out.Certificate.NotAfter), true, nil
}

// ExportCRL returns the CRL currently imported to the endpoint, or nil.
func (p *Provider) ExportCRL(ctx context.Context) ([]byte, error) {
	out, err := p.ec2.ExportClientVpnClientCertificateRevocationList(ctx,
		&ec2.ExportClientVpnClientCertificateRevocationListInput{ClientVpnEndpointId: aws.String(p.endpointID)},
	)
	if err != nil {
		return nil, fmt.Errorf("aws: export CRL from %s: %w", p.endpointID, err)
	}
	if crl := aws.ToString(out.CertificateRevocationList); crl != "" {
		return []byte(crl), nil
	}
	return nil, nil
}
