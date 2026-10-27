package app

import (
	"context"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/delivery"
	awsprovider "github.com/aartinian/cvpnctl/internal/provider/aws"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// newS3 returns the S3 client for the store, in aws.region with aws.profile,
// and a lookup of the caller's IAM ARN. The lookup calls STS only when a
// command needs it (to record who took the lock); GetCallerIdentity needs no
// IAM permission.
func newS3(ctx context.Context, cfg *config.Config) (store.S3API, func(context.Context) (string, error), error) {
	awsCfg, err := awsprovider.LoadConfig(ctx, &cfg.AWS)
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
// with the admin's credentials and stop working if those are deactivated.
func newPresigner(ctx context.Context, cfg *config.Config) (delivery.Presigner, error) {
	awsCfg, err := awsprovider.LoadConfig(ctx, &cfg.AWS)
	if err != nil {
		return nil, err
	}
	return s3.NewPresignClient(s3.NewFromConfig(awsCfg)), nil
}
