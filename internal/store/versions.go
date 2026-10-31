package store

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// headConcurrency bounds the HEAD requests Versions has in flight.
const headConcurrency = 8

// Version is one stored state of the PKI.
type Version struct {
	ID       string
	Modified time.Time
	Size     int64
	Current  bool
	Writer   string // IAM ARN recorded by the command that wrote it, if any
}

// Deleted reports whether the archive has no current version but earlier
// ones, as after someone deleted it in the versioned bucket.
func Deleted(ctx context.Context, client S3API, sc config.StoreConfig) (bool, error) {
	key := sc.Key(archiveKey)
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(sc.Bucket), Prefix: aws.String(key)}
	for { // delete markers fill pages too, so the versions may come later
		out, err := client.ListObjectVersions(ctx, in)
		if err != nil {
			return false, fmt.Errorf("store: list versions: %w", err)
		}
		for _, v := range out.Versions {
			if aws.ToString(v.Key) == key {
				// Newest first: the first version is current unless deleted.
				return !aws.ToBool(v.IsLatest), nil
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return false, nil
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
}

// Versions lists the archive's versions, newest first, as S3 lists them.
func Versions(ctx context.Context, client S3API, sc config.StoreConfig) ([]Version, error) {
	key := sc.Key(archiveKey)
	var all []types.ObjectVersion
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(sc.Bucket), Prefix: aws.String(key)}
	for { // the SDK has no paginator for this call
		out, err := client.ListObjectVersions(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("store: list versions: %w", err)
		}
		all = append(all, out.Versions...)
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	var vs []Version
	for _, v := range all {
		if aws.ToString(v.Key) == key {
			vs = append(vs, Version{ID: aws.ToString(v.VersionId), Modified: aws.ToTime(v.LastModified), Size: aws.ToInt64(v.Size), Current: aws.ToBool(v.IsLatest)})
		}
	}
	// The writer is only in each version's metadata: one HEAD per version,
	// a few at a time. Best-effort: a failed HEAD leaves Writer empty.
	var wg sync.WaitGroup
	sem := make(chan struct{}, headConcurrency)
	for i := range vs {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(key), VersionId: aws.String(vs[i].ID)})
			if err == nil {
				vs[i].Writer = head.Metadata["cvpnctl-arn"]
			}
		})
	}
	wg.Wait()
	return vs, nil
}

// Download returns one version of the archive.
func Download(ctx context.Context, client S3API, sc config.StoreConfig, version string) ([]byte, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(archiveKey)), VersionId: aws.String(version)})
	if IsNotFound(err) {
		return nil, fmt.Errorf("store: there is no version %s; see cvpnctl store versions", version)
	}
	if err != nil {
		return nil, fmt.Errorf("store: download version %s: %w", version, err)
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(io.LimitReader(out.Body, maxArchiveSize+1))
}

// Current returns the current archive version, or ok=false if there is none.
func Current(ctx context.Context, client S3API, sc config.StoreConfig) (v Version, ok bool, err error) {
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(archiveKey))})
	if IsNotFound(err) {
		return Version{}, false, nil
	}
	if err != nil {
		return Version{}, false, fmt.Errorf("store: read the current version: %w", err)
	}
	return Version{
		ID: aws.ToString(head.VersionId), Modified: aws.ToTime(head.LastModified), Size: aws.ToInt64(head.ContentLength),
		Current: true, Writer: head.Metadata["cvpnctl-arn"],
	}, true, nil
}
