package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aartinian/cvpnctl/internal/app/command"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{command.ErrNeedsAttention, 2},
		{fmt.Errorf("status: %w", command.ErrNeedsAttention), 2},
		{errors.New("aws: resolve credentials: …"), 1},
	}
	for _, tt := range tests {
		if got := ExitCode(tt.err); got != tt.want {
			t.Errorf("ExitCode(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

// awsTestEnv isolates the AWS SDK from this machine's real configuration and
// gives it static credentials. Nothing here contacts AWS.
func awsTestEnv(t *testing.T) {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example")
}

func s3Config() *config.Config {
	return &config.Config{
		AWS:   config.AWSConfig{Region: "eu-central-1"},
		Store: &config.StoreConfig{Bucket: "acme-vpn-pki", Prefix: "cvpnctl/", KMSKeyID: "alias/cvpnctl", LinkHours: 24},
	}
}

func TestNewS3(t *testing.T) {
	awsTestEnv(t)
	client, caller, err := newS3(context.Background(), s3Config())
	if err != nil {
		t.Fatalf("newS3: %v", err)
	}
	if client == nil || caller == nil {
		t.Fatal("newS3 returned a nil client or caller lookup")
	}
	// The caller lookup is lazy: constructing the client made no STS call.
}

// A presigned link from the real wiring uses the configured region and
// bucket, signed with the configured credentials.
func TestNewPresigner(t *testing.T) {
	awsTestEnv(t)
	p, err := newPresigner(context.Background(), s3Config())
	if err != nil {
		t.Fatal(err)
	}
	req, err := p.PresignGetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("acme-vpn-pki"), Key: aws.String("cvpnctl/delivery/x.ovpn")},
		s3.WithPresignExpires(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://acme-vpn-pki.s3.eu-central-1.amazonaws.com/", "X-Amz-Credential=AKIAEXAMPLE", "X-Amz-Expires=3600"} {
		if !strings.Contains(req.URL, want) {
			t.Errorf("link lacks %q: %s", want, req.URL)
		}
	}
}

func TestNewS3MissingProfile(t *testing.T) {
	awsTestEnv(t)
	cfg := s3Config()
	cfg.AWS.Profile = "does-not-exist"
	if _, _, err := newS3(context.Background(), cfg); err == nil {
		t.Error("a missing AWS profile was accepted")
	}
}
