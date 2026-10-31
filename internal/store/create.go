package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// ErrStoreExists means the bucket already holds a PKI.
var ErrStoreExists = errors.New("the store already holds a PKI")

// Create uploads archive as the store's first PKI, only if none exists yet
// (If-None-Match), then downloads it again and checks it arrived intact. It
// never overwrites an existing archive. An upload that fails without a clear
// answer counts as done if the stored archive is exactly archive, as when the
// SDK's retry got 412 from the upload that landed.
func Create(ctx context.Context, client S3API, sc config.StoreConfig, archive []byte, caller string) (version string, err error) {
	in := archivePut(sc, archive, caller)
	in.IfNoneMatch = aws.String("*")
	out, err := client.PutObject(ctx, in)
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

	got, err := Download(ctx, client, sc, version)
	if err != nil {
		return version, fmt.Errorf("store: read the uploaded PKI back: %w", err)
	}
	if !bytes.Equal(got, archive) {
		return version, fmt.Errorf("store: the uploaded PKI (version %s) differs from what was sent", version)
	}
	return version, nil
}
