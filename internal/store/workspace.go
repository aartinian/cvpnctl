package store

import (
	"context"
	"errors"
	"os"

	"github.com/aartinian/cvpnctl/internal/config"
)

// Mode says whether a command changes the PKI (Write: takes the lock and can
// checkpoint) or only reads it (Read). Recover is Write for store restore: if
// the current archive is unusable, it opens an empty workspace instead of
// failing, and Damaged says why.
type Mode int

const (
	Read Mode = iota
	Write
	Recover
)

// Workspace is where a command finds the PKI, the state and the template. In
// local mode it is the configured directories. In S3 mode it is a private
// temp folder holding a downloaded copy, which Checkpoint uploads and Close
// deletes.
type Workspace interface {
	PKIDir() string       // the EasyRSA PKI
	StateDir() string     // holds .cvpnctl-state.json
	TemplatePath() string // the .ovpn template
	OutDir() string       // where .ovpn files are rendered
	Remote() bool         // true in S3 mode
	Version() string      // the S3 version last read or written; "" locally
	Damaged() error       // in Recover mode, why the archive was unusable; else nil

	// Checkpoint saves the workspace: in S3 mode it uploads the archive, but
	// only if nobody else changed it since this command last read or wrote
	// it. Locally it does nothing, because the files are already on disk.
	Checkpoint(ctx context.Context) error

	// Close deletes the temp folder and releases the lock. It works even if
	// ctx is already cancelled (after Ctrl-C), and may be called more than once.
	Close(ctx context.Context) error
}

// Deps are what an S3 workspace needs besides the config.
type Deps struct {
	S3      S3API
	Caller  string // IAM ARN of the admin, recorded in the lock and the archive
	Host    string // machine name for the lock; os.Hostname() if empty
	Command string // e.g. "revoke bob", recorded in the lock
}

// ErrStoreEmpty means the bucket holds no PKI yet.
var ErrStoreEmpty = errors.New("store is empty; run cvpnctl store migrate")

// ErrStoreChanged means someone else wrote the archive since this command
// read it, so its upload was refused and nothing after it may run.
var ErrStoreChanged = errors.New("the stored PKI changed since this command read it (was the lock forced?); nothing after this point ran")

// ErrUploadUnknown means a checkpoint's upload failed in a way that may or
// may not have stored the archive, and checking afterwards failed too. The
// caller must not undo anything the stored PKI might already record.
var ErrUploadUnknown = errors.New("store: unknown whether the upload reached S3")

// Open returns the workspace for cfg: the configured directories in local
// mode, a downloaded copy in S3 mode (locked in Write mode).
func Open(ctx context.Context, cfg *config.Config, mode Mode, d Deps) (Workspace, error) {
	if !cfg.S3Mode() {
		return &local{cfg: cfg}, nil
	}
	if d.Host == "" {
		d.Host, _ = os.Hostname()
	}
	return openRemote(ctx, *cfg.Store, mode, d)
}

// local is the workspace of local mode: the configured directories.
type local struct{ cfg *config.Config }

func (l *local) PKIDir() string                   { return l.cfg.EasyRSA.PKIDir }
func (l *local) StateDir() string                 { return l.cfg.Certs.OutputDir }
func (l *local) TemplatePath() string             { return l.cfg.OVPN.Template }
func (l *local) OutDir() string                   { return l.cfg.OVPN.OutputDir }
func (l *local) Remote() bool                     { return false }
func (l *local) Version() string                  { return "" }
func (l *local) Damaged() error                   { return nil }
func (l *local) Checkpoint(context.Context) error { return nil }
func (l *local) Close(context.Context) error      { return nil }
