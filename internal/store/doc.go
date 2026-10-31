// Package store keeps cvpnctl's PKI, state and template either in local
// directories or, in S3 mode, in an S3 bucket shared by several admins.
//
// Commands see both through a Workspace: a set of directories to work in.
// Locally those are the configured directories. In S3 mode:
//
//   - The PKI, the state file and the .ovpn template are one gzipped tar,
//     pki.tar.gz (see Pack and Unpack). A command downloads it into a
//     private temp folder, works there, and uploads it again (Checkpoint).
//   - A command that changes anything first creates the lock object, only if
//     none exists (If-None-Match: *). A second admin gets a LockedError.
//   - Every upload carries If-Match on the archive version the command read,
//     so even after a forced unlock nobody overwrites newer work: the upload
//     fails with ErrStoreChanged instead.
//   - The bucket is versioned: every checkpoint is a version that
//     store versions lists and store restore brings back.
//
// A write whose response is lost may still have landed. Wherever that
// matters (taking the lock, the first upload, a checkpoint), the outcome is
// settled by reading back what S3 holds rather than by guessing.
package store
