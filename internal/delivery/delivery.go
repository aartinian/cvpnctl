// Package delivery hands .ovpn files to users through expiring links: the
// file is uploaded to the store's bucket and a presigned GET URL is returned.
// Users need no AWS access; whoever holds the link can download the file
// until it expires.
package delivery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Presigner signs download URLs. *s3.PresignClient implements it.
type Presigner interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

// CredentialExpirer is implemented by a Presigner that knows when the
// credentials it signs with expire. Temporary credentials (SSO, an assumed
// role) end a link early: it stops working when they expire.
type CredentialExpirer interface {
	CredentialsExpire(context.Context) (expires time.Time, canExpire bool, err error)
}

// Deliverer publishes and removes users' .ovpn files.
type Deliverer struct {
	s3      store.S3API
	presign Presigner
	sc      config.StoreConfig
}

// New returns a Deliverer for the store's bucket.
func New(client store.S3API, p Presigner, sc config.StoreConfig) *Deliverer {
	return &Deliverer{s3: client, presign: p, sc: sc}
}

// Publish uploads user's .ovpn and returns a link valid for hours (1 to
// config.MaxLinkHours), and when it really expires: earlier, if the signing
// credentials expire first. Any earlier link for user is deleted first: each
// user has at most one.
func (d *Deliverer) Publish(ctx context.Context, user string, ovpn []byte, hours int) (url string, expires time.Time, err error) {
	if hours < 1 || hours > config.MaxLinkHours {
		return "", time.Time{}, fmt.Errorf("delivery: link_hours must be 1–%d, got %d", config.MaxLinkHours, hours)
	}
	if err := d.Remove(ctx, user); err != nil {
		return "", time.Time{}, err
	}
	key, err := d.newKey(user)
	if err != nil {
		return "", time.Time{}, err
	}
	if _, err := d.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(d.sc.Bucket),
		Key:                  aws.String(key),
		Body:                 bytes.NewReader(ovpn),
		ContentType:          aws.String("application/x-openvpn-profile"),
		ContentDisposition:   aws.String(fmt.Sprintf(`attachment; filename="%s.ovpn"`, user)),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String(d.sc.KMSKeyID),
		ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("delivery: upload %s's .ovpn: %w", user, err)
	}

	validity := time.Duration(hours) * time.Hour
	expires = time.Now().Add(validity)
	req, err := d.presign.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(d.sc.Bucket), Key: aws.String(key)},
		s3.WithPresignExpires(validity))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("delivery: sign the link: %w", err)
	}
	if ce, ok := d.presign.(CredentialExpirer); ok {
		if until, can, err := ce.CredentialsExpire(ctx); err == nil && can && until.Before(expires) {
			expires = until
		}
	}
	return req.URL, expires, nil
}

// Remove deletes every published .ovpn of user, which makes their links stop
// working at once.
func (d *Deliverer) Remove(ctx context.Context, user string) error {
	prefix := d.sc.Key("delivery/" + user + "-")
	// Listing by prefix also finds users whose names start with user plus a
	// hyphen (bob → bob-x); the exact pattern keeps only user's own files.
	own := regexp.MustCompile("^" + regexp.QuoteMeta(prefix) + "[0-9a-f]{32}\\.ovpn$")
	pages := s3.NewListObjectsV2Paginator(d.s3, &s3.ListObjectsV2Input{Bucket: aws.String(d.sc.Bucket), Prefix: aws.String(prefix)})
	for pages.HasMorePages() {
		out, err := pages.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("delivery: list %s's links: %w", user, err)
		}
		for _, o := range out.Contents {
			key := aws.ToString(o.Key)
			if !own.MatchString(key) {
				continue
			}
			if _, err := d.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(d.sc.Bucket), Key: aws.String(key)}); err != nil {
				return fmt.Errorf("delivery: delete %s: %w", key, err)
			}
		}
	}
	return nil
}

// newKey returns delivery/<user>-<32 hex>.ovpn: 128 random bits, so a key
// can't be guessed even by someone who can list nothing.
func (d *Deliverer) newKey(user string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("delivery: %w", err)
	}
	return d.sc.Key(fmt.Sprintf("delivery/%s-%s.ovpn", user, hex.EncodeToString(b))), nil
}
