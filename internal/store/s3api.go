package store

import (
	"context"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// S3API is the part of the S3 client the store uses. Tests substitute
// storetest.FakeS3 for it.
type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// IsPreconditionFailed reports whether err is S3's 412: a conditional write
// or delete whose If-Match or If-None-Match did not hold.
func IsPreconditionFailed(err error) bool { return httpStatus(err) == http.StatusPreconditionFailed }

// IsConflict reports whether err is S3's 409: a conditional request that
// collided with a concurrent one, and may be retried.
func IsConflict(err error) bool { return httpStatus(err) == http.StatusConflict }

// IsNotFound reports whether err is S3's 404: no such key or version.
func IsNotFound(err error) bool { return httpStatus(err) == http.StatusNotFound }

// httpStatus extracts the HTTP status code from an SDK error, which wraps it
// in an OperationError and an AWS ResponseError; 0 if there is none.
func httpStatus(err error) int {
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) && re.Response != nil {
		return re.HTTPStatusCode()
	}
	return 0
}
