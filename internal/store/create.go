package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ErrStoreExists means the bucket already holds a PKI.
var ErrStoreExists = errors.New("the store already holds a PKI")

// Head returns the current archive's version, or ok=false if there is none.
func Head(ctx context.Context, client S3API, sc config.StoreConfig) (version string, ok bool, err error) {
	out, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(archiveKey))})
	if IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: look for an existing PKI: %w", err)
	}
	return aws.ToString(out.VersionId), true, nil
}

// Create uploads archive as the store's first PKI, only if none exists yet
// (If-None-Match), then downloads it again and checks it arrived intact. It
// never overwrites an existing archive. An upload that fails without a clear
// answer counts as done if the stored archive is exactly archive, as when the
// SDK's retry got 412 from the upload that landed.
func Create(ctx context.Context, client S3API, sc config.StoreConfig, archive []byte, caller string) (version string, err error) {
	out, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(sc.Bucket),
		Key:                  aws.String(sc.Key(archiveKey)),
		Body:                 bytes.NewReader(archive),
		IfNoneMatch:          aws.String("*"),
		ContentType:          aws.String("application/gzip"),
		Metadata:             map[string]string{"cvpnctl-arn": caller},
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String(sc.KMSKeyID),
		ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
	})
	if err == nil {
		version = aws.ToString(out.VersionId)
	} else {
		head, headErr := landedHead(ctx, client, sc, archive)
		switch {
		case head != nil:
			version = aws.ToString(head.VersionId)
		case headErr != nil:
			return "", fmt.Errorf("store: upload the PKI: %w; checking whether it reached S3 failed too (%v): run cvpnctl status before migrating again", err, headErr)
		case IsPreconditionFailed(err):
			return "", ErrStoreExists
		default:
			return "", fmt.Errorf("store: upload the PKI: %w", err)
		}
	}

	got, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(archiveKey)), VersionId: aws.String(version)})
	if err != nil {
		return version, fmt.Errorf("store: read the uploaded PKI back: %w", err)
	}
	defer func() { _ = got.Body.Close() }()
	data, err := io.ReadAll(got.Body)
	if err != nil {
		return version, fmt.Errorf("store: read the uploaded PKI back: %w", err)
	}
	if !bytes.Equal(data, archive) {
		return version, fmt.Errorf("store: the uploaded PKI (version %s) differs from what was sent", version)
	}
	return version, nil
}
