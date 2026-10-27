package store

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// The helpers must recognise errors produced by the real SDK client, not just
// the fake's imitation of them. A local server answers every request with a
// fixed status and an S3-style error body.
func TestHelpersOnRealSDKErrors(t *testing.T) {
	tests := []struct {
		status       int
		code         string
		precondition bool
		conflict     bool
		notFound     bool
	}{
		{http.StatusPreconditionFailed, "PreconditionFailed", true, false, false},
		{http.StatusConflict, "ConditionalRequestConflict", false, true, false},
		{http.StatusNotFound, "NoSuchKey", false, false, true},
		{http.StatusForbidden, "AccessDenied", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(tt.status)
				fmt.Fprintf(w, `<?xml version="1.0"?><Error><Code>%s</Code><Message>m</Message></Error>`, tt.code)
			}))
			defer srv.Close()

			client := s3.New(s3.Options{
				Region:           "eu-central-1",
				BaseEndpoint:     aws.String(srv.URL),
				UsePathStyle:     true,
				Credentials:      credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
				RetryMaxAttempts: 1,
			})
			_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
				Bucket: aws.String("b"), Key: aws.String("k"), Body: bytes.NewReader([]byte("x")), IfNoneMatch: aws.String("*"),
			})
			if err == nil {
				t.Fatal("expected an error")
			}
			if IsPreconditionFailed(err) != tt.precondition || IsConflict(err) != tt.conflict || IsNotFound(err) != tt.notFound {
				t.Errorf("%T %v: precondition=%v conflict=%v notFound=%v", err, err, IsPreconditionFailed(err), IsConflict(err), IsNotFound(err))
			}
		})
	}
}
