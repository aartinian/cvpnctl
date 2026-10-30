package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/delivery"
	"github.com/aartinian/cvpnctl/internal/provider"
	awsprovider "github.com/aartinian/cvpnctl/internal/provider/aws"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// awsSession builds every AWS client a command needs from one AWS config,
// so credentials are resolved once per run (one SSO refresh or AssumeRole,
// not one per client).
type awsSession struct {
	mu   sync.Mutex
	cfgs map[config.AWSConfig]aws.Config
}

// config returns the AWS SDK config for cfg's region and profile, loading it
// on first use.
func (s *awsSession) config(ctx context.Context, cfg *config.Config) (aws.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cfgs[cfg.AWS]; ok {
		return c, nil
	}
	c, err := awsprovider.LoadConfig(ctx, &cfg.AWS)
	if err != nil {
		return aws.Config{}, err
	}
	if s.cfgs == nil {
		s.cfgs = map[config.AWSConfig]aws.Config{}
	}
	s.cfgs[cfg.AWS] = c
	return c, nil
}

// newProvider returns the CertStore for the provider named in cfg.
func (s *awsSession) newProvider(ctx context.Context, cfg *config.Config) (provider.CertStore, error) {
	if cfg.Provider != "aws" {
		return nil, fmt.Errorf("provider %q is not supported (supported: aws)", cfg.Provider)
	}
	awsCfg, err := s.config(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return awsprovider.NewFromConfig(awsCfg, cfg.AWS.VPNEndpointID), nil
}

// newS3 returns the S3 client for the store, in aws.region with aws.profile,
// and a lookup of the caller's IAM ARN. The lookup calls STS only when a
// command needs it (to record who took the lock); GetCallerIdentity needs no
// IAM permission.
func (s *awsSession) newS3(ctx context.Context, cfg *config.Config) (store.S3API, func(context.Context) (string, error), error) {
	awsCfg, err := s.config(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	caller := func(ctx context.Context) (string, error) {
		out, err := sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", fmt.Errorf("aws: find out who is calling: %w", err)
		}
		return aws.ToString(out.Arn), nil
	}
	return s3.NewFromConfig(awsCfg), caller, nil
}

// newPresigner returns the signer for .ovpn download links. Links are signed
// with the admin's credentials and stop working if those are deactivated or
// expire.
func (s *awsSession) newPresigner(ctx context.Context, cfg *config.Config) (delivery.Presigner, error) {
	awsCfg, err := s.config(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return presigner{s3.NewPresignClient(s3.NewFromConfig(awsCfg)), awsCfg.Credentials}, nil
}

var _ delivery.CredentialExpirer = presigner{}

// presigner is an S3 presign client that also reports when its credentials
// expire (delivery.CredentialExpirer).
type presigner struct {
	*s3.PresignClient
	creds aws.CredentialsProvider
}

func (p presigner) CredentialsExpire(ctx context.Context) (time.Time, bool, error) {
	c, err := p.creds.Retrieve(ctx)
	return c.Expires, c.CanExpire, err
}
