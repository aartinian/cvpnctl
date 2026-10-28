package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// archiveKey is the object holding the PKI, the state and the template.
const archiveKey = "pki.tar.gz"

// pidFile records, in the workspace's temp folder, the process using it, so
// that Sweep never removes the workspace of a command that is still running.
// It sits outside pki/, state/ and template/, so Pack leaves it out.
const pidFile = ".pid"

// closeTimeout bounds the clean-up in Close, which runs with a fresh context
// so that it still works after the command's own context was cancelled.
const closeTimeout = 30 * time.Second

// remote is the workspace of S3 mode.
type remote struct {
	s3      S3API
	sc      config.StoreConfig
	mode    Mode
	caller  string
	root    string // private temp folder holding pki/, state/, template/, out/
	lock    *Lock  // nil in Read mode
	etag    string // of the archive version last read or written
	version string
	closed  bool
}

func openRemote(ctx context.Context, sc config.StoreConfig, mode Mode, d Deps) (_ *remote, err error) {
	Sweep(os.TempDir(), os.Getuid(), staleAfter)
	r := &remote{s3: d.S3, sc: sc, mode: mode, caller: d.Caller}
	if mode == Write {
		lock, err := Acquire(ctx, d.S3, sc, LockInfo{ARN: d.Caller, Host: d.Host, PID: os.Getpid(), Command: d.Command, Started: time.Now().UTC()})
		if err != nil {
			return nil, err
		}
		r.lock = lock
	}
	// From here on, anything that fails must not leave the lock or the temp
	// folder behind.
	defer func() {
		if err != nil {
			_ = r.Close(ctx)
		}
	}()

	if r.root, err = TempDir(); err != nil {
		return nil, err
	}

	out, err := d.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(sc.Bucket), Key: aws.String(sc.Key(archiveKey))})
	if IsNotFound(err) {
		return nil, ErrStoreEmpty
	}
	if err != nil {
		return nil, fmt.Errorf("store: download the PKI: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(out.Body, maxArchiveSize+1))
	_ = out.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("store: download the PKI: %w", err)
	}
	if err := Unpack(data, r.root); err != nil {
		return nil, err
	}
	r.etag, r.version = aws.ToString(out.ETag), aws.ToString(out.VersionId)

	if _, err := os.Stat(filepath.Join(r.PKIDir(), "ca.crt")); err != nil {
		return nil, fmt.Errorf("store: the stored archive has no pki/ca.crt (version %s); restore a good version with cvpnctl store restore", r.version)
	}
	for _, dir := range []string{r.StateDir(), filepath.Dir(r.TemplatePath()), r.OutDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
	}
	return r, nil
}

// TempDir creates a private cvpnctl-* folder in the system temp directory
// (mode 0700) that records this process in a .pid file, so that Sweep leaves
// it alone for as long as the process runs. Every folder that may hold a copy
// of the CA key is made with it; the caller removes it.
func TempDir() (string, error) {
	dir, err := os.MkdirTemp("", "cvpnctl-*")
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err == nil {
		err = os.WriteFile(filepath.Join(dir, pidFile), []byte(strconv.Itoa(os.Getpid())), 0o600)
		if err == nil {
			return dir, nil
		}
	}
	_ = os.RemoveAll(dir)
	return "", fmt.Errorf("store: prepare %s: %w", dir, err)
}

func (r *remote) PKIDir() string       { return filepath.Join(r.root, "pki") }
func (r *remote) StateDir() string     { return filepath.Join(r.root, "state") }
func (r *remote) TemplatePath() string { return filepath.Join(r.root, "template", "base.ovpn") }
func (r *remote) OutDir() string       { return filepath.Join(r.root, "out") }
func (r *remote) Remote() bool         { return true }
func (r *remote) Version() string      { return r.version }

// Checkpoint uploads the workspace as the new archive version, with If-Match
// on the version this command last read or wrote, so it never overwrites
// someone else's change.
//
// If the upload fails without a clear answer (a network error, a timeout),
// S3 may still have stored it. The archive's SHA-256 checksum then decides:
// if S3's current version is exactly what we sent, the checkpoint counts as
// done; otherwise it failed, and the caller must treat its changes as not
// recorded.
func (r *remote) Checkpoint(ctx context.Context) error {
	if r.mode != Write {
		return errors.New("store: checkpoint in a read-only workspace")
	}
	data, err := Pack(r.root)
	if err != nil {
		return err
	}
	out, err := r.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(r.sc.Bucket),
		Key:                  aws.String(r.sc.Key(archiveKey)),
		Body:                 bytes.NewReader(data),
		IfMatch:              aws.String(r.etag),
		ContentType:          aws.String("application/gzip"),
		Metadata:             map[string]string{"cvpnctl-arn": r.caller},
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String(r.sc.KMSKeyID),
		ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
	})
	if err == nil {
		r.etag, r.version = aws.ToString(out.ETag), aws.ToString(out.VersionId)
		return nil
	}
	// Even a 412 is checked: when the SDK retries an upload whose response
	// was lost, the retry fails its If-Match against the upload that landed.
	landed, headErr := r.landed(ctx, data)
	switch {
	case landed:
		return nil
	case headErr != nil:
		return fmt.Errorf("%w: the upload failed (%v), and checking whether it reached S3 failed too (%v); run cvpnctl status before retrying", ErrUploadUnknown, err, headErr)
	case IsPreconditionFailed(err), IsNotFound(err):
		return ErrStoreChanged
	}
	return fmt.Errorf("store: the upload did not reach S3: %w", err)
}

// landed reports whether the stored archive is data, by comparing its checksum
// with the one we sent, and adopts its ETag if so. It uses its own context,
// because the failed upload may be the caller's context ending.
func (r *remote) landed(ctx context.Context, data []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
	defer cancel()
	head, err := r.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:       aws.String(r.sc.Bucket),
		Key:          aws.String(r.sc.Key(archiveKey)),
		ChecksumMode: types.ChecksumModeEnabled,
	})
	switch {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, err
	}
	sum := sha256.Sum256(data)
	if aws.ToString(head.ChecksumSHA256) != base64.StdEncoding.EncodeToString(sum[:]) {
		return false, nil
	}
	r.etag, r.version = aws.ToString(head.ETag), aws.ToString(head.VersionId)
	return true, nil
}

func (r *remote) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	r.closed = true
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
	defer cancel()

	var errs []error
	if r.root != "" {
		if err := os.RemoveAll(r.root); err != nil {
			errs = append(errs, fmt.Errorf("store: remove %s: %w", r.root, err))
		}
	}
	if r.lock != nil {
		switch err := r.lock.Release(ctx); {
		case errors.Is(err, ErrLockLost):
			ui.Warn("%v", err)
		case err != nil:
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
