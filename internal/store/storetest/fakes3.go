// Package storetest provides an in-memory S3 for tests. It models the parts
// of S3 the store relies on: versioned objects, ETags, SHA-256 checksums,
// conditional writes and deletes (If-Match, If-None-Match), and the error
// wrapping the AWS SDK uses, so error classification is tested as it runs
// against AWS. It is not a general-purpose S3 emulator.
package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Settings are the bucket-level settings the fake reports.
type Settings struct {
	Versioning   bool
	KMSKeyID     string // default encryption key; "" means SSE-S3
	PublicAccess types.PublicAccessBlockConfiguration
}

type version struct {
	id           string
	body         []byte
	etag         string
	checksum     string
	deleteMarker bool
	modified     time.Time
	metadata     map[string]string
	disposition  string
}

// FakeS3 is an in-memory, versioned bucket. It is safe for concurrent use.
type FakeS3 struct {
	Settings Settings

	// AfterPut, if set, runs after each successful PutObject with its key,
	// outside the fake's lock, so it may call the fake (e.g. to simulate
	// another admin acting right after a checkpoint).
	AfterPut func(key string)

	mu        sync.Mutex
	objects   map[string][]*version // oldest first
	nextID    int
	clock     time.Time
	events    []string
	failNext  error
	failLand  bool
	failHead  error
	conflicts int
}

// New returns an empty bucket with the settings a correctly configured store
// has: versioning on, KMS encryption, all public access blocked.
func New() *FakeS3 {
	return &FakeS3{
		Settings: Settings{
			Versioning: true,
			KMSKeyID:   "arn:aws:kms:eu-central-1:111122223333:key/test",
			PublicAccess: types.PublicAccessBlockConfiguration{
				BlockPublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(true),
				IgnorePublicAcls: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true),
			},
		},
		objects: map[string][]*version{},
		clock:   time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC),
	}
}

// Checksum returns the base64 SHA-256 that S3 reports for body.
func Checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// FailNextPut makes the next PutObject return err. With land, the object is
// stored first, as when a response is lost after S3 accepted the write.
func (f *FakeS3) FailNextPut(err error, land bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext, f.failLand = err, land
}

// FailNextHead makes the next HeadObject return err.
func (f *FakeS3) FailNextHead(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failHead = err
}

// ConflictNextPuts makes the next n PutObject calls fail with 409 Conflict.
func (f *FakeS3) ConflictNextPuts(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conflicts = n
}

// Events returns the successful writes so far, e.g. "put pki.tar.gz" or
// "delete lock", in order.
func (f *FakeS3) Events() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

// Object returns the current body of key, if it exists.
func (f *FakeS3) Object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v := f.current(key); v != nil {
		return v.body, true
	}
	return nil, false
}

// current returns the latest version of key, or nil if it has none or the
// latest is a delete marker. f.mu must be held.
func (f *FakeS3) current(key string) *version {
	vs := f.objects[key]
	if len(vs) == 0 || vs[len(vs)-1].deleteMarker {
		return nil
	}
	return vs[len(vs)-1]
}

func (f *FakeS3) add(key string, v *version) *version {
	f.nextID++
	f.clock = f.clock.Add(time.Second)
	v.id, v.modified = fmt.Sprintf("v%d", f.nextID), f.clock
	f.objects[key] = append(f.objects[key], v)
	return v
}

func (f *FakeS3) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	out, err := f.putObject(ctx, in, opts...)
	if err == nil && f.AfterPut != nil {
		f.AfterPut(aws.ToString(in.Key))
	}
	return out, err
}

func (f *FakeS3) putObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := aws.ToString(in.Key)
	if f.conflicts > 0 {
		f.conflicts--
		return nil, apiError("PutObject", http.StatusConflict, "ConditionalRequestConflict")
	}
	cur := f.current(key)
	if aws.ToString(in.IfNoneMatch) == "*" && cur != nil {
		return nil, apiError("PutObject", http.StatusPreconditionFailed, "PreconditionFailed")
	}
	if m := aws.ToString(in.IfMatch); m != "" {
		if cur == nil {
			return nil, apiError("PutObject", http.StatusNotFound, "NoSuchKey")
		}
		if m != cur.etag {
			return nil, apiError("PutObject", http.StatusPreconditionFailed, "PreconditionFailed")
		}
	}

	var body []byte
	if in.Body != nil {
		var err error
		if body, err = io.ReadAll(in.Body); err != nil {
			return nil, err
		}
	}
	if failed := f.failNext; failed != nil {
		f.failNext = nil
		if !f.failLand {
			return nil, failed
		}
		f.store(key, body, in)
		return nil, failed
	}
	v := f.store(key, body, in)
	return &s3.PutObjectOutput{ETag: aws.String(v.etag), VersionId: aws.String(v.id), ChecksumSHA256: aws.String(v.checksum)}, nil
}

func (f *FakeS3) store(key string, body []byte, in *s3.PutObjectInput) *version {
	sum := sha256.Sum256(body)
	v := f.add(key, &version{
		body:        body,
		etag:        `"` + hex.EncodeToString(sum[:16]) + `"`,
		checksum:    Checksum(body),
		metadata:    in.Metadata,
		disposition: aws.ToString(in.ContentDisposition),
	})
	f.events = append(f.events, "put "+key)
	return v
}

// lookup returns the requested version of key: a specific one, or the current.
func (f *FakeS3) lookup(op, key string, versionID *string) (*version, error) {
	if id := aws.ToString(versionID); id != "" {
		for _, v := range f.objects[key] {
			if v.id == id && !v.deleteMarker {
				return v, nil
			}
		}
		return nil, apiError(op, http.StatusNotFound, "NoSuchVersion")
	}
	if v := f.current(key); v != nil {
		return v, nil
	}
	return nil, apiError(op, http.StatusNotFound, "NoSuchKey")
}

func (f *FakeS3) GetObject(ctx context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if err := ctx.Err(); err != nil { // as the SDK does for a cancelled request
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, err := f.lookup("GetObject", aws.ToString(in.Key), in.VersionId)
	if err != nil {
		return nil, err
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(v.body)), ETag: aws.String(v.etag), VersionId: aws.String(v.id),
		ContentLength: aws.Int64(int64(len(v.body))), LastModified: aws.Time(v.modified), Metadata: v.metadata,
	}, nil
}

func (f *FakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failHead; err != nil {
		f.failHead = nil
		return nil, err
	}
	v, err := f.lookup("HeadObject", aws.ToString(in.Key), in.VersionId)
	if err != nil {
		return nil, err
	}
	out := &s3.HeadObjectOutput{
		ETag: aws.String(v.etag), VersionId: aws.String(v.id), ContentLength: aws.Int64(int64(len(v.body))),
		LastModified: aws.Time(v.modified), Metadata: v.metadata, ContentDisposition: aws.String(v.disposition),
	}
	if in.ChecksumMode == types.ChecksumModeEnabled {
		out.ChecksumSHA256 = aws.String(v.checksum)
	}
	return out, nil
}

func (f *FakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := aws.ToString(in.Key)
	cur := f.current(key)
	if m := aws.ToString(in.IfMatch); m != "" && (cur == nil || (m != "*" && m != cur.etag)) {
		return nil, apiError("DeleteObject", http.StatusPreconditionFailed, "PreconditionFailed")
	}
	if cur == nil {
		return &s3.DeleteObjectOutput{}, nil // deleting a missing key succeeds in S3
	}
	m := f.add(key, &version{deleteMarker: true})
	f.events = append(f.events, "delete "+key)
	return &s3.DeleteObjectOutput{DeleteMarker: aws.Bool(true), VersionId: aws.String(m.id)}, nil
}

func (f *FakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &s3.ListObjectsV2Output{}
	for _, key := range f.keys(aws.ToString(in.Prefix)) {
		if v := f.current(key); v != nil {
			out.Contents = append(out.Contents, types.Object{Key: aws.String(key), ETag: aws.String(v.etag), LastModified: aws.Time(v.modified), Size: aws.Int64(int64(len(v.body)))})
		}
	}
	out.KeyCount = aws.Int32(int32(len(out.Contents)))
	return out, nil
}

func (f *FakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &s3.ListObjectVersionsOutput{}
	for _, key := range f.keys(aws.ToString(in.Prefix)) {
		vs := f.objects[key]
		for i := len(vs) - 1; i >= 0; i-- { // newest first, as S3 lists them
			v := vs[i]
			latest := i == len(vs)-1
			if v.deleteMarker {
				out.DeleteMarkers = append(out.DeleteMarkers, types.DeleteMarkerEntry{Key: aws.String(key), VersionId: aws.String(v.id), IsLatest: aws.Bool(latest), LastModified: aws.Time(v.modified)})
				continue
			}
			out.Versions = append(out.Versions, types.ObjectVersion{Key: aws.String(key), VersionId: aws.String(v.id), IsLatest: aws.Bool(latest), ETag: aws.String(v.etag), LastModified: aws.Time(v.modified), Size: aws.Int64(int64(len(v.body)))})
		}
	}
	return out, nil
}

func (f *FakeS3) keys(prefix string) []string {
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func (f *FakeS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Settings.Versioning {
		return &s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled}, nil
	}
	return &s3.GetBucketVersioningOutput{}, nil
}

func (f *FakeS3) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rule := types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAes256}
	if f.Settings.KMSKeyID != "" {
		rule = types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(f.Settings.KMSKeyID)}
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
		Rules: []types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &rule, BucketKeyEnabled: aws.Bool(true)}},
	}}, nil
}

func (f *FakeS3) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg := f.Settings.PublicAccess
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &cfg}, nil
}

// APIError builds an S3 service error with the given status, e.g. for
// FailNextPut.
func APIError(op string, status int, code string) error { return apiError(op, status, code) }

// apiError builds an error the way the AWS SDK returns S3 service errors, so
// that classification by HTTP status works on it exactly as on a real one.
func apiError(op string, status int, code string) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: op,
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      &smithy.GenericAPIError{Code: code, Message: http.StatusText(status)},
			},
		},
	}
}
