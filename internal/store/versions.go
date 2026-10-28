package store

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Version is one stored state of the PKI.
type Version struct {
	ID       string
	Modified time.Time
	Size     int64
	Current  bool
	Writer   string // IAM ARN recorded by the command that wrote it, if any
}

// Versions lists the archive's versions, newest first.
// Deleted reports whether the archive has no current version but earlier
// ones, as after someone deleted it in the versioned bucket.
func Deleted(ctx context.Context, client S3API, sc config.StoreConfig) (bool, error) {
	key := sc.Key(archiveKey)
	out, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(sc.Bucket), Prefix: aws.String(key)})
	if err != nil {
		return false, fmt.Errorf("store: list versions: %w", err)
	}
	// The key sorts first, so its versions are on this page if anywhere.
	earlier := false
	for _, v := range out.Versions {
		if aws.ToString(v.Key) != key {
			continue
		}
		if aws.ToBool(v.IsLatest) {
			return false, nil // there is a current version
		}
		earlier = true
	}
	return earlier, nil
}

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
		if aws.ToString(v.Key) != key {
			continue
		}
		version := Version{ID: aws.ToString(v.VersionId), Modified: aws.ToTime(v.LastModified), Size: aws.ToInt64(v.Size), Current: aws.ToBool(v.IsLatest)}
		head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(key), VersionId: v.VersionId})
		if err == nil {
			version.Writer = head.Metadata["cvpnctl-arn"]
		}
		vs = append(vs, version)
	}
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].Modified.After(vs[j].Modified) })
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
