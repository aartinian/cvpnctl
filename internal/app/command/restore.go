package command

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/aartinian/cvpnctl/internal/config"
	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/state"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
)

func runVersions(ctx context.Context, opts *Options, details string) error {
	cfg, err := opts.loadConfig()
	if err != nil {
		return err
	}
	if !cfg.S3Mode() {
		return errors.New("store versions requires `store` in the config")
	}
	client, _, err := opts.NewS3(ctx, cfg)
	if err != nil {
		return err
	}
	if details != "" {
		return showVersion(ctx, client, *cfg.Store, details)
	}
	vs, err := store.Versions(ctx, client, *cfg.Store)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "VERSION\tWRITTEN\tSIZE\tBY\t")
	for _, v := range vs {
		mark := ""
		if v.Current {
			mark = "current"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%d KB\t%s\t%s\n", v.ID, v.Modified.Local().Format("2006-01-02 15:04"), (v.Size+1023)/1024, orDash(v.Writer), mark)
	}
	return w.Flush()
}

// showVersion prints the users and revocations held by one version.
func showVersion(ctx context.Context, client store.S3API, sc config.StoreConfig, version string) error {
	dir, cleanup, err := unpackVersion(ctx, client, sc, version)
	if err != nil {
		return err
	}
	defer cleanup()
	users, revoked, err := readState(dir)
	if err != nil {
		return err
	}
	fmt.Printf("version %s: %d users, %d revoked\n", version, len(users), len(revoked))
	for _, u := range users {
		fmt.Printf("  %s\n", u)
	}
	return nil
}

func runRestore(ctx context.Context, opts *Options, version string, yes bool) error {
	cfg, err := opts.loadConfig()
	if err != nil {
		return err
	}
	if !cfg.S3Mode() {
		return errors.New("store restore requires `store` in the config")
	}
	e, err := opts.load(ctx, store.Write, "store restore "+version)
	if err != nil {
		return err
	}
	defer e.close()
	if version == e.ws.Version() {
		return fmt.Errorf("version %s is already the current version", version)
	}

	target, cleanup, err := unpackVersion(ctx, e.s3, *cfg.Store, version)
	if err != nil {
		return err
	}
	defer cleanup()

	d, err := e.diffWith(ctx, target)
	if err != nil {
		return err
	}
	ui.Title("Restoring version %s", version)
	d.print()

	switch {
	case d.dangerous() && yes:
		return errors.New("--yes is not accepted when a restore would un-revoke certificates or lose track of valid ones")
	case d.dangerous():
		ok, err := confirmTyped("Type 'restore' to restore anyway; any other answer aborts:", "restore")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	case !yes:
		ok, err := confirm("Restore this version?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}

	if err := step("restoring", "restored", func() (string, error) {
		return "", replaceWorkspace(e.ws, target)
	}); err != nil {
		return err
	}
	if err := e.ws.Checkpoint(ctx); err != nil {
		return err
	}
	e.saved()
	if d.dangerous() {
		ui.Done("Run 'cvpnctl status'. Revoke %s again before anything pushes a CRL; certificates the PKI no longer knows (%s) can only be stopped by a new CA.",
			orDash(strings.Join(d.unrevoked, ", ")), orDash(strings.Join(d.untracked, ", ")))
		return nil
	}
	ui.Done("Run 'cvpnctl status' to check that ACM and the endpoint match the restored PKI. No CRL was pushed.")
	return nil
}

// stateDiff is what a restore changes, compared with the current state and
// the endpoint's CRL.
type stateDiff struct {
	added, removed []string // users
	unrevoked      []string // revoked now (locally or on the endpoint), valid in the target
	untracked      []string // valid now, absent from the target's PKI: could never be revoked
	revoked        []string // valid now, revoked in the target
}

// dangerous reports whether the restore would let someone keep or regain
// access that the restored PKI can't take away again.
func (d stateDiff) dangerous() bool { return len(d.unrevoked) > 0 || len(d.untracked) > 0 }

func (d stateDiff) print() {
	line := func(label string, names []string) {
		if len(names) == 0 {
			fmt.Printf("  %-14s –\n", label)
			return
		}
		fmt.Printf("  %-14s %s\n", label, strings.Join(names, ", "))
	}
	line("users added", d.added)
	line("users removed", d.removed)
	line("revoked", d.revoked)
	// On stdout, right next to the prompt that asks to type 'restore'.
	if len(d.unrevoked) > 0 {
		fmt.Printf("  ! revocations lost: %s would be able to connect again after the next CRL push\n", strings.Join(d.unrevoked, ", "))
	}
	if len(d.untracked) > 0 {
		fmt.Printf("  ! certificates lost: %s would keep a valid certificate that the restored PKI doesn't know, so it could never be revoked; revoke them before restoring\n", strings.Join(d.untracked, ", "))
	}
}

// diffWith compares the current workspace (and the endpoint's CRL) with the
// state unpacked in target.
func (e *env) diffWith(ctx context.Context, target string) (stateDiff, error) {
	var d stateDiff
	curUsers := names(e.users.All())
	tgtUsers, tgtRevoked, err := readState(target)
	if err != nil {
		return d, err
	}
	d.added, d.removed = minus(tgtUsers, curUsers), minus(curUsers, tgtUsers)

	curIndex, err := e.pki.Index()
	if err != nil {
		return d, err
	}
	nameOf := map[string]string{}
	curRevoked := map[string]bool{}
	curValid := map[string]bool{}
	for _, x := range curIndex {
		nameOf[x.Serial] = x.Name
		switch x.Status {
		case "R":
			curRevoked[x.Serial] = true
		case "V":
			curValid[x.Serial] = true
		}
	}
	tgtIndex, err := easyrsa.New(&config.EasyRSAConfig{PKIDir: filepath.Join(target, "pki")}, false).Index()
	if err != nil {
		return d, err
	}
	inTarget := map[string]bool{}
	for _, x := range tgtIndex {
		inTarget[x.Serial] = true
	}
	for serial := range curValid {
		if !inTarget[serial] {
			d.untracked = append(d.untracked, orDefault(nameOf[serial], "serial "+serial))
		}
	}
	onEndpoint, err := e.endpointRevoked(ctx)
	if err != nil {
		return d, err
	}
	seen := map[string]bool{}
	for serial := range union(curRevoked, onEndpoint) {
		if !tgtRevoked[serial] {
			name := nameOf[serial]
			if name == "" {
				name = "serial " + serial
			}
			if !seen[name] {
				d.unrevoked, seen[name] = append(d.unrevoked, name), true
			}
		}
	}
	for serial := range tgtRevoked {
		if !curRevoked[serial] {
			d.revoked = append(d.revoked, orDefault(nameOf[serial], "serial "+serial))
		}
	}
	sort.Strings(d.unrevoked)
	sort.Strings(d.untracked)
	sort.Strings(d.revoked)
	return d, nil
}

// endpointRevoked returns the serials the endpoint's current CRL revokes.
func (e *env) endpointRevoked(ctx context.Context) (map[string]bool, error) {
	data, err := e.cloud.ExportCRL(ctx)
	if err != nil || data == nil {
		return map[string]bool{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the endpoint's CRL is unreadable")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the endpoint's CRL is unreadable: %w", err)
	}
	out := map[string]bool{}
	for _, r := range crl.RevokedCertificateEntries {
		out[easyrsa.NormSerial(r.SerialNumber.Text(16))] = true
	}
	return out, nil
}

// unpackVersion downloads and unpacks one archive version into a temp folder.
func unpackVersion(ctx context.Context, client store.S3API, sc config.StoreConfig, version string) (string, func(), error) {
	data, err := store.Download(ctx, client, sc, version)
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "cvpnctl-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := store.Unpack(data, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

// readState returns the users and revoked serials of an unpacked archive.
func readState(dir string) ([]string, map[string]bool, error) {
	st, err := state.Load(filepath.Join(dir, "state"))
	if err != nil {
		return nil, nil, err
	}
	revoked, err := easyrsa.New(&config.EasyRSAConfig{PKIDir: filepath.Join(dir, "pki")}, false).RevokedSerials()
	if err != nil {
		return nil, nil, err
	}
	return names(st.All()), revoked, nil
}

// replaceWorkspace swaps the workspace's PKI, state and template for those
// unpacked in src.
func replaceWorkspace(ws store.Workspace, src string) error {
	for _, pair := range []struct{ from, to string }{
		{filepath.Join(src, "pki"), ws.PKIDir()},
		{filepath.Join(src, "state"), ws.StateDir()},
		{filepath.Join(src, "template"), filepath.Dir(ws.TemplatePath())},
	} {
		if err := os.RemoveAll(pair.to); err != nil {
			return err
		}
		if _, err := os.Stat(pair.from); errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(pair.to, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := copyTree(pair.from, pair.to); err != nil {
			return err
		}
	}
	return nil
}

func names(rs []state.UserRecord) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.User)
	}
	return out
}

func minus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func union(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func orDash(s string) string { return orDefault(s, "–") }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
