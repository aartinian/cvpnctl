package store

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// More versions than fit on one list page (S3 returns at most 1000): all are
// listed, newest first, with the current one marked.
func TestVersionsFollowsPages(t *testing.T) {
	_, f := s3Env(t) // one archive version
	for i := range 6 {
		f.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("cvpnctl/pki.tar.gz"), Body: bytes.NewReader(fmt.Appendf(nil, "v%d", i))})
	}
	f.PageSize = 2

	vs, err := Versions(context.Background(), f, testStore)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 7 {
		t.Fatalf("%d versions, want 7", len(vs))
	}
	seen := map[string]bool{}
	for i, v := range vs {
		if seen[v.ID] {
			t.Errorf("version %s listed twice", v.ID)
		}
		seen[v.ID] = true
		if i > 0 && v.Modified.After(vs[i-1].Modified) {
			t.Errorf("not newest first at %d", i)
		}
		if v.Current != (i == 0) {
			t.Errorf("version %d: Current = %v", i, v.Current)
		}
	}
}
