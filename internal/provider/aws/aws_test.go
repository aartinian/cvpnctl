package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

type fakeACM struct {
	acmAPI
	deleteErr error
	deleted   []string
	certs     map[string]*acmtypes.CertificateDetail
}

func (f *fakeACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	c, ok := f.certs[*in.CertificateArn]
	if !ok {
		return nil, wrapped(&acmtypes.ResourceNotFoundException{Message: new(string)})
	}
	return &acm.DescribeCertificateOutput{Certificate: c}, nil
}

type fakeEC2 struct {
	ec2API
	endpoint *ec2types.ClientVpnEndpoint
	crl      *string
}

func (f *fakeEC2) DescribeClientVpnEndpoints(_ context.Context, _ *ec2.DescribeClientVpnEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
	out := &ec2.DescribeClientVpnEndpointsOutput{}
	if f.endpoint != nil {
		out.ClientVpnEndpoints = []ec2types.ClientVpnEndpoint{*f.endpoint}
	}
	return out, nil
}

func (f *fakeEC2) ExportClientVpnClientCertificateRevocationList(_ context.Context, _ *ec2.ExportClientVpnClientCertificateRevocationListInput, _ ...func(*ec2.Options)) (*ec2.ExportClientVpnClientCertificateRevocationListOutput, error) {
	return &ec2.ExportClientVpnClientCertificateRevocationListOutput{CertificateRevocationList: f.crl}, nil
}

func (f *fakeACM) DeleteCertificate(_ context.Context, in *acm.DeleteCertificateInput, _ ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error) {
	f.deleted = append(f.deleted, *in.CertificateArn)
	return &acm.DeleteCertificateOutput{}, f.deleteErr
}

// The SDK wraps service errors; errors.As has to see through that.
func wrapped(err error) error {
	return &smithy.OperationError{ServiceID: "ACM", OperationName: "DeleteCertificate", Err: err}
}

func TestDeleteCert(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"deleted", nil, false},
		{"already gone", wrapped(&acmtypes.ResourceNotFoundException{Message: new(string)}), false},
		{"in use", wrapped(&acmtypes.ResourceInUseException{Message: new(string)}), true},
		{"other", errors.New("boom"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeACM{deleteErr: tt.err}
			err := (&Provider{acm: f}).DeleteCert(context.Background(), "arn:x")
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(f.deleted) != 1 || f.deleted[0] != "arn:x" {
				t.Errorf("DeleteCertificate called with %v", f.deleted)
			}
		})
	}
}

// With no credentials anywhere, New fails up front instead of at the first
// AWS call. Everything here is local: no AWS requests are made.
func TestNewChecksCredentials(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	_, err := LoadConfig(context.Background(), &config.AWSConfig{Region: "eu-central-1"})
	if err == nil || !strings.Contains(err.Error(), "resolve credentials") {
		t.Fatalf("err = %v, want a credentials error", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example")
	if _, err := LoadConfig(context.Background(), &config.AWSConfig{Region: "eu-central-1"}); err != nil {
		t.Errorf("with static credentials: %v", err)
	}
}

func TestEndpointCerts(t *testing.T) {
	ec2f := &fakeEC2{endpoint: &ec2types.ClientVpnEndpoint{
		ServerCertificateArn: aws.String("arn:server"),
		AuthenticationOptions: []ec2types.ClientVpnAuthentication{
			{Type: ec2types.ClientVpnAuthenticationTypeCertificateAuthentication,
				MutualAuthentication: &ec2types.CertificateAuthentication{ClientRootCertificateChain: aws.String("arn:root")}},
		},
	}}
	server, root, err := (&Provider{ec2: ec2f, endpointID: "cvpn-endpoint-x"}).EndpointCerts(context.Background())
	if err != nil || server != "arn:server" || root != "arn:root" {
		t.Errorf("EndpointCerts() = %q, %q, %v", server, root, err)
	}

	if _, _, err := (&Provider{ec2: &fakeEC2{}, endpointID: "cvpn-endpoint-x"}).EndpointCerts(context.Background()); err == nil {
		t.Error("missing endpoint: expected an error")
	}
}

func TestCertInfo(t *testing.T) {
	exp := time.Date(2032, 9, 30, 0, 0, 0, 0, time.UTC)
	p := &Provider{acm: &fakeACM{certs: map[string]*acmtypes.CertificateDetail{
		"arn:server": {DomainName: aws.String("vpn-server"), NotAfter: &exp},
	}}}
	name, notAfter, found, err := p.CertInfo(context.Background(), "arn:server")
	if err != nil || !found || name != "vpn-server" || !notAfter.Equal(exp) {
		t.Errorf("CertInfo() = %q, %v, %v, %v", name, notAfter, found, err)
	}
	if _, _, found, err := p.CertInfo(context.Background(), "arn:gone"); found || err != nil {
		t.Errorf("missing certificate: found=%v err=%v, want not found and no error", found, err)
	}
}

func TestExportCRL(t *testing.T) {
	p := &Provider{ec2: &fakeEC2{crl: aws.String("-----BEGIN X509 CRL-----")}}
	if crl, err := p.ExportCRL(context.Background()); err != nil || string(crl) != "-----BEGIN X509 CRL-----" {
		t.Errorf("ExportCRL() = %q, %v", crl, err)
	}
	p = &Provider{ec2: &fakeEC2{}}
	if crl, err := p.ExportCRL(context.Background()); err != nil || crl != nil {
		t.Errorf("no CRL: ExportCRL() = %q, %v, want nil, nil", crl, err)
	}
}
