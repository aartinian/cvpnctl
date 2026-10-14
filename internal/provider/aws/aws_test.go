package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/smithy-go"
)

type fakeACM struct {
	acmAPI
	deleteErr error
	deleted   []string
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

	_, err := New(context.Background(), &config.AWSConfig{Region: "eu-central-1"})
	if err == nil || !strings.Contains(err.Error(), "resolve credentials") {
		t.Fatalf("err = %v, want a credentials error", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example")
	if _, err := New(context.Background(), &config.AWSConfig{Region: "eu-central-1"}); err != nil {
		t.Errorf("with static credentials: %v", err)
	}
}
