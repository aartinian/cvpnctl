package store

import (
	"context"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func problems(t *testing.T, f *storetest.FakeS3, sc func(*testing.T) (s string)) []BucketProblem {
	t.Helper()
	st := testStore
	if sc != nil {
		st.KMSKeyID = sc(t)
	}
	ps, err := CheckBucket(context.Background(), f, st)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestCheckBucketGood(t *testing.T) {
	f := storetest.New()
	f.Settings.KMSKeyID = "arn:aws:kms:eu-central-1:111122223333:alias/cvpnctl"
	if ps := problems(t, f, nil); len(ps) != 0 {
		t.Errorf("a correctly set up bucket has problems: %+v", ps)
	}
}

func TestCheckBucketProblems(t *testing.T) {
	tests := map[string]struct {
		setup func(*storetest.FakeS3)
		want  string
	}{
		"versioning off": {func(f *storetest.FakeS3) { f.Settings.Versioning = false }, "versioning"},
		"not KMS":        {func(f *storetest.FakeS3) { f.Settings.KMSKeyID = "" }, "encryption"},
		"other key":      {func(f *storetest.FakeS3) { f.Settings.KMSKeyID = "arn:aws:kms:eu-central-1:111122223333:alias/other" }, "encryption"},
		"public access":  {func(f *storetest.FakeS3) { f.Settings.PublicAccess.BlockPublicPolicy = aws.Bool(false) }, "public access"},
		"public unset":   {func(f *storetest.FakeS3) { f.Settings.PublicAccess.RestrictPublicBuckets = nil }, "public access"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := storetest.New()
			f.Settings.KMSKeyID = "arn:aws:kms:eu-central-1:111122223333:alias/cvpnctl"
			tt.setup(f)
			ps := problems(t, f, nil)
			if len(ps) != 1 || !strings.Contains(ps[0].What, tt.want) {
				t.Errorf("problems = %+v, want one about %s", ps, tt.want)
			}
		})
	}
}

// An alias in the config and a key ARN on the bucket can't be compared
// without a KMS call; that's not reported as a problem.
func TestCheckBucketAliasVersusKeyARN(t *testing.T) {
	f := storetest.New() // the fake reports a key ARN (…:key/test)
	if ps := problems(t, f, nil); len(ps) != 0 {
		t.Errorf("alias vs key ARN flagged: %+v", ps)
	}
	if ps := problems(t, f, func(*testing.T) string { return "arn:aws:kms:eu-central-1:111122223333:key/other" }); len(ps) != 1 {
		t.Errorf("two different key ARNs not flagged: %+v", ps)
	}
	if ps := problems(t, f, func(*testing.T) string { return "test" }); len(ps) != 0 {
		t.Errorf("key ID matching the ARN's key flagged: %+v", ps)
	}
}
