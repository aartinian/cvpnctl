package storetest_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// The fake must satisfy the interface the store uses.
var _ store.S3API = (*storetest.FakeS3)(nil)

var ctx = context.Background()

func put(f *storetest.FakeS3, key, body string, mod func(*s3.PutObjectInput)) (*s3.PutObjectOutput, error) {
	in := &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String(key), Body: bytes.NewReader([]byte(body))}
	if mod != nil {
		mod(in)
	}
	return f.PutObject(ctx, in)
}

func TestIfNoneMatch(t *testing.T) {
	f := storetest.New()
	ifNone := func(in *s3.PutObjectInput) { in.IfNoneMatch = aws.String("*") }
	if _, err := put(f, "lock", "a", ifNone); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if _, err := put(f, "lock", "b", ifNone); !store.IsPreconditionFailed(err) {
		t.Fatalf("second put: err = %v, want 412", err)
	}
	if _, err := f.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("lock")}); err != nil {
		t.Fatal(err)
	}
	// After a delete, the current version is a delete marker, which counts as absent.
	if _, err := put(f, "lock", "c", ifNone); err != nil {
		t.Fatalf("put after delete: %v", err)
	}
}

func TestIfMatch(t *testing.T) {
	f := storetest.New()
	out, _ := put(f, "pki.tar.gz", "v1", nil)
	if _, err := put(f, "pki.tar.gz", "v2", func(in *s3.PutObjectInput) { in.IfMatch = out.ETag }); err != nil {
		t.Fatalf("put with current ETag: %v", err)
	}
	if _, err := put(f, "pki.tar.gz", "v3", func(in *s3.PutObjectInput) { in.IfMatch = out.ETag }); !store.IsPreconditionFailed(err) {
		t.Fatalf("put with stale ETag: err = %v, want 412", err)
	}
	if _, err := put(f, "absent", "x", func(in *s3.PutObjectInput) { in.IfMatch = out.ETag }); !store.IsNotFound(err) {
		t.Fatalf("If-Match on a missing key: err = %v, want 404", err)
	}
}

func TestConditionalDelete(t *testing.T) {
	f := storetest.New()
	out, _ := put(f, "lock", "a", nil)
	stale := aws.String(`"stale"`)
	if _, err := f.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("lock"), IfMatch: stale}); !store.IsPreconditionFailed(err) {
		t.Fatalf("delete with stale ETag: err = %v, want 412", err)
	}
	if _, err := f.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("lock"), IfMatch: out.ETag}); err != nil {
		t.Fatalf("delete with current ETag: %v", err)
	}
	if _, ok := f.Object("lock"); ok {
		t.Error("lock still present")
	}
}

func TestGetVersionsAndChecksum(t *testing.T) {
	f := storetest.New()
	v1, _ := put(f, "pki.tar.gz", "one", nil)
	put(f, "pki.tar.gz", "two", nil)

	old, err := f.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("b"), Key: aws.String("pki.tar.gz"), VersionId: v1.VersionId})
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(old.Body); string(body) != "one" {
		t.Errorf("version 1 body = %q", body)
	}

	head, err := f.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("b"), Key: aws.String("pki.tar.gz"), ChecksumMode: types.ChecksumModeEnabled})
	if err != nil || aws.ToString(head.ChecksumSHA256) != storetest.Checksum([]byte("two")) {
		t.Errorf("HeadObject checksum = %v, %v", aws.ToString(head.ChecksumSHA256), err)
	}

	vs, _ := f.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String("b"), Prefix: aws.String("pki")})
	if len(vs.Versions) != 2 || !aws.ToBool(vs.Versions[0].IsLatest) {
		t.Errorf("versions = %+v, want 2, newest first", vs.Versions)
	}

	if _, err := f.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("b"), Key: aws.String("nope")}); !store.IsNotFound(err) {
		t.Errorf("missing key: err = %v, want 404", err)
	}
}

func TestFailNextPut(t *testing.T) {
	boom := errors.New("connection reset")
	f := storetest.New()
	f.FailNextPut(boom, true)
	if _, err := put(f, "k", "landed", nil); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the injected error", err)
	}
	if got, ok := f.Object("k"); !ok || string(got) != "landed" {
		t.Errorf("object = %q, %v; want it stored despite the error", got, ok)
	}

	f.FailNextPut(boom, false)
	put(f, "j", "lost", nil)
	if _, ok := f.Object("j"); ok {
		t.Error("object stored although the put was meant to be lost")
	}
}

func TestConflictNextPuts(t *testing.T) {
	f := storetest.New()
	f.ConflictNextPuts(1)
	if _, err := put(f, "k", "a", nil); !store.IsConflict(err) {
		t.Fatalf("err = %v, want 409", err)
	}
	if _, err := put(f, "k", "a", nil); err != nil {
		t.Fatalf("next put: %v", err)
	}
}

func TestListAndEvents(t *testing.T) {
	f := storetest.New()
	put(f, "delivery/max-1.ovpn", "a", nil)
	put(f, "delivery/bob-1.ovpn", "b", nil)
	put(f, "pki.tar.gz", "p", nil)
	out, _ := f.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("b"), Prefix: aws.String("delivery/")})
	if len(out.Contents) != 2 {
		t.Errorf("listed %d objects under delivery/, want 2", len(out.Contents))
	}
	if ev := f.Events(); len(ev) != 3 || ev[2] != "put pki.tar.gz" {
		t.Errorf("events = %v", ev)
	}
}

func TestBucketSettings(t *testing.T) {
	f := storetest.New()
	f.Settings.Versioning = false
	v, _ := f.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String("b")})
	if v.Status == types.BucketVersioningStatusEnabled {
		t.Error("versioning reported enabled")
	}
	enc, _ := f.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String("b")})
	if got := aws.ToString(enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID); got != f.Settings.KMSKeyID {
		t.Errorf("KMS key = %q", got)
	}
}

// Listing versions page by page yields every version and delete marker once,
// across keys, in the same order as one unlimited listing.
func TestListObjectVersionsPages(t *testing.T) {
	f := storetest.New()
	put := func(key string) {
		f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String(key), Body: strings.NewReader("x")})
	}
	put("p/a")
	put("p/a")
	f.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("p/a")})
	put("p/b")
	put("p/b")

	entries := func() []string {
		var got []string
		in := &s3.ListObjectVersionsInput{Bucket: aws.String("b"), Prefix: aws.String("p/")}
		for {
			out, err := f.ListObjectVersions(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range out.Versions {
				got = append(got, aws.ToString(v.Key)+"@"+aws.ToString(v.VersionId))
			}
			for _, m := range out.DeleteMarkers {
				got = append(got, aws.ToString(m.Key)+"@"+aws.ToString(m.VersionId))
			}
			if !aws.ToBool(out.IsTruncated) {
				return got
			}
			in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
		}
	}
	whole := entries()
	sort.Strings(whole)
	for _, size := range []int{1, 2, 3} {
		f.PageSize = size
		paged := entries()
		sort.Strings(paged)
		if strings.Join(paged, " ") != strings.Join(whole, " ") {
			t.Errorf("page size %d: %v, want %v", size, paged, whole)
		}
	}
	if len(whole) != 5 {
		t.Errorf("%d entries, want 5: %v", len(whole), whole)
	}
}
