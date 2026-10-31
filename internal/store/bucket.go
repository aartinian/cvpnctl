package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// BucketProblem is a bucket setting that doesn't match what the shared PKI
// needs.
type BucketProblem struct {
	What   string // e.g. "versioning"
	Detail string
}

// CheckBucket reports the bucket settings that don't match the reference
// setup: versioning (the PKI's history), default encryption with KMS, and
// all four public access blocks. It returns an error only if the settings
// can't be read at all.
func CheckBucket(ctx context.Context, client S3API, sc config.StoreConfig) ([]BucketProblem, error) {
	bucket := aws.String(sc.Bucket)
	var ps []BucketProblem

	v, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket})
	if err != nil {
		return nil, fmt.Errorf("store: read the bucket's versioning: %w", err)
	}
	if v.Status != types.BucketVersioningStatusEnabled {
		ps = append(ps, BucketProblem{"versioning", "is off; without it there is no history to restore"})
	}

	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket})
	switch {
	case IsNotFound(err):
		ps = append(ps, BucketProblem{"encryption", "has no default encryption"})
	case err != nil:
		return nil, fmt.Errorf("store: read the bucket's encryption: %w", err)
	default:
		if p := checkEncryption(enc, sc.KMSKeyID); p != nil {
			ps = append(ps, *p)
		}
	}

	pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket})
	switch {
	case IsNotFound(err):
		ps = append(ps, BucketProblem{"public access", "isn't blocked (no public access block configured)"})
	case err != nil:
		return nil, fmt.Errorf("store: read the bucket's public access block: %w", err)
	default:
		c := pab.PublicAccessBlockConfiguration
		if c == nil || !aws.ToBool(c.BlockPublicAcls) || !aws.ToBool(c.BlockPublicPolicy) || !aws.ToBool(c.IgnorePublicAcls) || !aws.ToBool(c.RestrictPublicBuckets) {
			ps = append(ps, BucketProblem{"public access", "isn't fully blocked (all four settings must be on)"})
		}
	}
	return ps, nil
}

func checkEncryption(enc *s3.GetBucketEncryptionOutput, want string) *BucketProblem {
	if enc.ServerSideEncryptionConfiguration == nil || len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
		return &BucketProblem{"encryption", "has no default encryption"}
	}
	d := enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
	if d == nil || (d.SSEAlgorithm != types.ServerSideEncryptionAwsKms && d.SSEAlgorithm != types.ServerSideEncryptionAwsKmsDsse) {
		return &BucketProblem{"encryption", "isn't KMS by default"}
	}
	gotKind, gotName := kmsKeyRef(aws.ToString(d.KMSMasterKeyID))
	wantKind, wantName := kmsKeyRef(want)
	// An alias and a key ID name the same key or not; telling them apart
	// would need a KMS call. Uploads set the configured key explicitly, so
	// only a mismatch in the same form is reported.
	if gotName != "" && gotKind == wantKind && gotName != wantName {
		return &BucketProblem{"encryption", fmt.Sprintf("uses KMS key %s by default, not %s", aws.ToString(d.KMSMasterKeyID), want)}
	}
	return nil
}

// kmsKeyRef reduces a KMS key reference (key ID, key ARN, alias name, alias
// ARN) to its kind ("key" or "alias") and name.
func kmsKeyRef(ref string) (kind, name string) {
	if i := strings.LastIndex(ref, ":"); i >= 0 && strings.HasPrefix(ref, "arn:") {
		ref = ref[i+1:]
	}
	if n, ok := strings.CutPrefix(ref, "alias/"); ok {
		return "alias", n
	}
	if n, ok := strings.CutPrefix(ref, "key/"); ok {
		return "key", n
	}
	return "key", ref
}
