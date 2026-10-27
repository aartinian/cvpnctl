package delivery

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/store/storetest"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var sc = config.StoreConfig{Bucket: "b", Prefix: "cvpnctl/", KMSKeyID: "alias/cvpnctl", LinkHours: 24}

// stubPresigner returns a fake URL and records the requested expiry.
type stubPresigner struct{ expires time.Duration }

func (p *stubPresigner) PresignGetObject(_ context.Context, in *s3.GetObjectInput, opts ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	var o s3.PresignOptions
	for _, f := range opts {
		f(&o)
	}
	p.expires = o.Expires
	return &v4.PresignedHTTPRequest{URL: "https://example.test/" + aws.ToString(in.Key), Method: "GET"}, nil
}

func keys(f *storetest.FakeS3) []string {
	out, _ := f.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String("b"), Prefix: aws.String("cvpnctl/delivery/")})
	var ks []string
	for _, o := range out.Contents {
		ks = append(ks, aws.ToString(o.Key))
	}
	return ks
}

var keyRE = regexp.MustCompile(`^cvpnctl/delivery/alice-[0-9a-f]{32}\.ovpn$`)

func TestPublish(t *testing.T) {
	f, p := storetest.New(), &stubPresigner{}
	before := time.Now()
	url, expires, err := New(f, p, sc).Publish(context.Background(), "alice", []byte("client"), 24)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	ks := keys(f)
	if len(ks) != 1 || !keyRE.MatchString(ks[0]) {
		t.Fatalf("keys = %v, want one matching %s", ks, keyRE)
	}
	if url != "https://example.test/"+ks[0] {
		t.Errorf("url = %q", url)
	}
	if p.expires != 24*time.Hour {
		t.Errorf("presigned for %v, want 24h", p.expires)
	}
	if expires.Before(before.Add(24*time.Hour)) || expires.After(time.Now().Add(24*time.Hour)) {
		t.Errorf("expires = %v, want about 24h from now", expires)
	}
	head, _ := f.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String("b"), Key: aws.String(ks[0])})
	if got := aws.ToString(head.ContentDisposition); got != `attachment; filename="alice.ovpn"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if body, _ := f.Object(ks[0]); string(body) != "client" {
		t.Errorf("body = %q", body)
	}
}

func TestPublishReplacesOldLink(t *testing.T) {
	f := storetest.New()
	d := New(f, &stubPresigner{}, sc)
	d.Publish(context.Background(), "alice", []byte("one"), 24)
	d.Publish(context.Background(), "alice", []byte("two"), 24)
	ks := keys(f)
	if len(ks) != 1 {
		t.Fatalf("keys = %v, want exactly one active link", ks)
	}
	if body, _ := f.Object(ks[0]); string(body) != "two" {
		t.Errorf("the remaining link holds %q, want the newest", body)
	}
}

func TestPublishKeysAreUnguessable(t *testing.T) {
	f := storetest.New()
	d := New(f, &stubPresigner{}, sc)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		d.Publish(context.Background(), "alice", []byte("x"), 1)
		k := keys(f)[0]
		if seen[k] {
			t.Fatalf("key %s repeated", k)
		}
		seen[k] = true
	}
}

// Review focus: one user's name may be a prefix of another's.
func TestRemoveOnlyThatUser(t *testing.T) {
	f := storetest.New()
	d := New(f, &stubPresigner{}, sc)
	d.Publish(context.Background(), "bob", []byte("bob"), 24)
	d.Publish(context.Background(), "bob.smith", []byte("bob.smith"), 24)
	d.Publish(context.Background(), "bob-x", []byte("bob-x"), 24)

	if err := d.Remove(context.Background(), "bob"); err != nil {
		t.Fatal(err)
	}
	ks := strings.Join(keys(f), " ")
	if regexp.MustCompile(`/bob-[0-9a-f]{32}\.ovpn`).MatchString(ks) {
		t.Errorf("bob's link survived: %s", ks)
	}
	for _, other := range []string{"/bob.smith-", "/bob-x-"} {
		if !strings.Contains(ks, other) {
			t.Errorf("removing bob also removed %s: %s", other, ks)
		}
	}
}

func TestPublishHoursRange(t *testing.T) {
	d := New(storetest.New(), &stubPresigner{}, sc)
	for _, h := range []int{0, 169, -1} {
		if _, _, err := d.Publish(context.Background(), "alice", []byte("x"), h); err == nil || !strings.Contains(err.Error(), "1–168") {
			t.Errorf("hours %d: err = %v", h, err)
		}
	}
}

// The SDK's presigner fits the interface, and a 7-day link carries the right
// expiry and the SigV4 parameters. Presigning is local; nothing is sent.
func TestRealPresigner(t *testing.T) {
	var _ Presigner = (*s3.PresignClient)(nil)

	client := s3.New(s3.Options{Region: "eu-central-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")})
	real := sc
	real.Bucket = "acme-vpn-pki" // a valid DNS name, as real buckets are
	url, _, err := New(storetest.New(), s3.NewPresignClient(client), real).Publish(context.Background(), "alice", []byte("x"), MaxHours)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://acme-vpn-pki.s3.eu-central-1.amazonaws.com/cvpnctl/delivery/alice-", "X-Amz-Expires=604800", "X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Signature="} {
		if !strings.Contains(url, want) {
			t.Errorf("link lacks %q:\n%s", want, url)
		}
	}
}
