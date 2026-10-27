package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// lockKey is the object whose existence means "a command is changing the PKI".
const lockKey = "lock"

// lockRetries is how often Acquire retries after a 409 Conflict, which S3
// returns when two conditional writes race; lockBackoff is the base delay,
// multiplied by the attempt number.
const lockRetries = 3

var lockBackoff = 200 * time.Millisecond

// LockInfo is the content of the lock object: who holds it and since when.
type LockInfo struct {
	ARN     string    `json:"arn"`
	Host    string    `json:"host"`
	PID     int       `json:"pid"`
	Command string    `json:"command"`
	Started time.Time `json:"started"`
}

// LockedError reports that another command holds the lock.
type LockedError struct{ Info LockInfo }

func (e *LockedError) Error() string {
	started := e.Info.Started.Local()
	when := started.Format("15:04")
	if y, m, d := started.Date(); !sameDay(y, m, d, time.Now()) {
		when = started.Format("2006-01-02 15:04")
	}
	return fmt.Sprintf("locked by %s on %s since %s (%s)", e.Info.ARN, e.Info.Host, when, e.Info.Command)
}

func sameDay(y int, m time.Month, d int, t time.Time) bool {
	ty, tm, td := t.Local().Date()
	return y == ty && m == tm && d == td
}

// ErrLockLost is returned by Release when the lock is no longer ours: it was
// force-removed, and possibly taken by someone else since. Callers warn about
// it rather than fail, because the work is already saved or abandoned.
var ErrLockLost = errors.New("the lock was removed or taken over while this command ran")

// Lock is a held lock. Release it exactly once.
type Lock struct {
	s3   S3API
	sc   config.StoreConfig
	etag string
}

// Acquire takes the lock by creating the lock object only if none exists
// (If-None-Match: *). If another command holds it, it returns a *LockedError
// describing that command. It never waits for a lock to be released.
func Acquire(ctx context.Context, client S3API, sc config.StoreConfig, info LockInfo) (*Lock, error) {
	body, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	for attempt := 0; ; attempt++ {
		out, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:               aws.String(sc.Bucket),
			Key:                  aws.String(sc.Key(lockKey)),
			Body:                 bytes.NewReader(body),
			IfNoneMatch:          aws.String("*"),
			ContentType:          aws.String("application/json"),
			ServerSideEncryption: types.ServerSideEncryptionAwsKms,
			SSEKMSKeyId:          aws.String(sc.KMSKeyID),
			ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
		})
		switch {
		case err == nil:
			return &Lock{s3: client, sc: sc, etag: aws.ToString(out.ETag)}, nil
		case IsPreconditionFailed(err):
			held, ok, rerr := ReadLock(ctx, client, sc)
			if rerr != nil {
				return nil, rerr
			}
			if !ok { // released between our write and our read: try again, a bounded number of times
				if attempt < lockRetries {
					continue
				}
				return nil, errors.New("store: could not take the lock: it kept changing hands; try again")
			}
			return nil, &LockedError{Info: *held}
		case IsConflict(err) && attempt < lockRetries:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(lockBackoff * time.Duration(attempt+1)):
			}
		case IsConflict(err):
			return nil, errors.New("store: could not take the lock: concurrent requests kept conflicting; try again")
		default:
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("store: take the lock: %w", err)
		}
	}
}

// Release deletes the lock, but only if it is still the one we created
// (If-Match on its ETag). If it isn't, it returns ErrLockLost and leaves the
// current lock alone.
func (l *Lock) Release(ctx context.Context) error {
	_, err := l.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:  aws.String(l.sc.Bucket),
		Key:     aws.String(l.sc.Key(lockKey)),
		IfMatch: aws.String(l.etag),
	})
	switch {
	case err == nil:
		return nil
	case IsPreconditionFailed(err), IsNotFound(err):
		return ErrLockLost
	default:
		return fmt.Errorf("store: release the lock: %w", err)
	}
}

// ReadLock returns the current lock's content, and whether a lock is held.
func ReadLock(ctx context.Context, client S3API, sc config.StoreConfig) (*LockInfo, bool, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(lockKey))})
	if IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: read the lock: %w", err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, false, fmt.Errorf("store: read the lock: %w", err)
	}
	var info LockInfo
	if err := json.Unmarshal(body, &info); err != nil {
		// An unreadable lock still blocks; describe it rather than fail.
		info = LockInfo{ARN: "(unreadable lock)", Host: "?", Command: "?"}
	}
	return &info, true, nil
}

// ForceUnlock deletes the lock unconditionally, for `cvpnctl unlock` after a
// crash. A command still running under the removed lock fails at its next
// checkpoint, because the archive's If-Match no longer holds once anyone else
// writes it.
func ForceUnlock(ctx context.Context, client S3API, sc config.StoreConfig) error {
	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(lockKey))})
	if err != nil {
		return fmt.Errorf("store: remove the lock: %w", err)
	}
	return nil
}
