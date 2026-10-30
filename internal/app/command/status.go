package command

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aartinian/cvpnctl/internal/easyrsa"
	"github.com/aartinian/cvpnctl/internal/store"
	"github.com/aartinian/cvpnctl/internal/ui"
	"github.com/spf13/cobra"
)

// ErrNeedsAttention is returned by status when something has expired, expires
// within warnDays, or is out of step with the PKI. main exits with code 2 for
// it, so a scheduled job can tell "needs attention" apart from "failed" (1).
var ErrNeedsAttention = errors.New("needs attention")

// warnDays is how far ahead status warns about expiry.
const warnDays = 30

// NewStatusCmd returns the status subcommand.
func NewStatusCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show what expires when, and whether the endpoint's CRL matches the PKI",
		Long: `Show the CA, the endpoint's server certificate and client root, the CRL
(on this machine and on the endpoint) and every user's certificate, with how
long each has left.

status only reads: it never needs the CA passphrase and changes nothing.
Exit codes: 0 all fine, 1 the check itself failed, 2 something needs
attention (expired, expiring within 30 days, or a CRL out of step).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.Context(), opts, time.Now())
		},
	}
}

// row is one line of the status table.
type row struct {
	what, name string
	expires    time.Time // zero: no expiry to show
	level      ui.Level
	note       string
}

func runStatus(ctx context.Context, opts *Options, now time.Time) error {
	e, err := opts.load(ctx, store.Read, "status")
	if err != nil {
		return err
	}
	defer e.close()

	fmt.Printf("config     %s\n", ui.Path(e.cfg.Path))
	fmt.Printf("easyrsa    %s (%s)\n", e.easyrsaVersion, ui.Path(e.pki.Dir()))
	fmt.Printf("endpoint   %s (%s)\n", e.cfg.AWS.VPNEndpointID, e.cfg.AWS.Region)
	if e.ws.Remote() {
		fmt.Printf("store      s3://%s/%s\n", e.cfg.Store.Bucket, e.cfg.Store.Prefix)
	}
	fmt.Println()

	var rows []row
	if e.ws.Remote() {
		storeRows, err := e.storeRows(ctx, now)
		if err != nil {
			return err
		}
		rows = append(rows, storeRows...)
	}

	ca, err := e.pki.CACert()
	if err != nil {
		return err
	}
	rows = append(rows, expiryRow("CA", ca.Subject.CommonName, ca.NotAfter, now))

	serverID, rootID, err := e.cloud.EndpointCerts(ctx)
	if err != nil {
		return err
	}
	for _, c := range []struct{ what, id string }{{"server cert", serverID}, {"client root", rootID}} {
		if c.id == "" {
			continue
		}
		name, notAfter, found, err := e.cloud.CertInfo(ctx, c.id)
		if err != nil {
			return err
		}
		if !found {
			rows = append(rows, row{what: c.what, level: ui.Critical, note: "ACM entry missing: " + shortID(c.id)})
			continue
		}
		rows = append(rows, expiryRow(c.what, name, notAfter, now))
	}

	switch n, next, err := e.pki.CRLInfo(); {
	case errors.Is(err, fs.ErrNotExist):
		// A fresh PKI has no CRL until the first revocation or push-crl.
		rows = append(rows, row{what: "CRL (PKI)", note: "none yet"})
	case err != nil:
		return err
	default:
		local := expiryRow("CRL (PKI)", "", next, now)
		if local.note == "" {
			local.note = fmt.Sprintf("%d revoked", n)
		}
		rows = append(rows, local)
	}

	endpoint, err := e.endpointCRLRow(ctx, ca, now)
	if err != nil {
		return err
	}
	rows = append(rows, endpoint)

	for _, r := range e.users.All() {
		exp, err := e.pki.Expiry(r.User)
		if errors.Is(err, fs.ErrNotExist) {
			rows = append(rows, row{what: "user", name: r.User, level: ui.Critical, note: "no certificate in the PKI (revoked outside cvpnctl?)"})
			continue
		}
		if err != nil {
			rows = append(rows, row{what: "user", name: r.User, level: ui.Critical, note: "certificate unreadable: " + err.Error()})
			continue
		}
		ur := expiryRow("user", r.User, exp, now)
		if r.ProviderID != "" {
			if _, _, found, err := e.cloud.CertInfo(ctx, r.ProviderID); err != nil {
				return err
			} else if !found {
				ur.level, ur.note = ui.Critical, "ACM entry missing: "+shortID(r.ProviderID)
			}
		}
		rows = append(rows, ur)
	}

	attention := printStatus(rows, now)
	if attention > 0 {
		fmt.Printf("\n%d %s attention.\n", attention, plural(attention, "item needs", "items need"))
		return ErrNeedsAttention
	}
	fmt.Println("\nAll good.")
	return nil
}

// endpointCRLRow checks the endpoint's CRL: its expiry, that your CA signed
// it, and that it revokes exactly what the PKI's index.txt has revoked.
func (e *env) endpointCRLRow(ctx context.Context, ca *x509.Certificate, now time.Time) (row, error) {
	data, err := e.cloud.ExportCRL(ctx)
	if err != nil {
		return row{}, err
	}
	revoked, err := e.pki.RevokedSerials()
	if err != nil {
		return row{}, err
	}

	if data == nil {
		if len(revoked) == 0 {
			return row{what: "CRL (endpoint)", note: "none (nothing revoked yet)"}, nil
		}
		return row{what: "CRL (endpoint)", level: ui.Critical,
			note: fmt.Sprintf("none: %d revoked %s can still connect; run cvpnctl push-crl", len(revoked), plural(len(revoked), "certificate", "certificates"))}, nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return row{what: "CRL (endpoint)", level: ui.Critical, note: "unreadable"}, nil
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return row{what: "CRL (endpoint)", level: ui.Critical, note: "unreadable"}, nil
	}

	// Collect every problem, so one (say, a mismatch) never hides another
	// (say, that the CRL has expired).
	r := expiryRow("CRL (endpoint)", "", crl.NextUpdate, now)
	var notes []string
	if r.note != "" {
		notes = append(notes, r.note)
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		r.level, r.note = ui.Critical, strings.Join(append(notes, "not signed by your CA"), "; ")
		return r, nil
	}

	onEndpoint := make(map[string]bool)
	for _, entry := range crl.RevokedCertificateEntries {
		onEndpoint[easyrsa.NormSerial(entry.SerialNumber.Text(16))] = true
	}
	var extra, missing int
	for s := range onEndpoint {
		if !revoked[s] {
			extra++
		}
	}
	for s := range revoked {
		if !onEndpoint[s] {
			missing++
		}
	}

	if extra > 0 {
		// Another copy of the PKI, or a manual import, revoked these. A push
		// from this PKI would let them connect again.
		notes = append(notes, fmt.Sprintf("revokes %d %s your PKI doesn't", extra, plural(extra, "certificate", "certificates")))
		r.level = ui.Critical
	}
	if missing > 0 {
		notes = append(notes, fmt.Sprintf("%d %s not pushed yet (they can still connect): run cvpnctl push-crl", missing, plural(missing, "revocation", "revocations")))
		r.level = ui.Critical
	}
	if extra == 0 && missing == 0 {
		notes = append(notes, "matches your PKI")
	}
	r.note = strings.Join(notes, "; ")
	return r, nil
}

// expiryRow rates an expiry date: critical once expired, attention within
// warnDays.
func expiryRow(what, name string, expires, now time.Time) row {
	r := row{what: what, name: name, expires: expires}
	switch left := expires.Sub(now); {
	case left <= 0:
		r.level, r.note = ui.Critical, "expired"
	case left < warnDays*24*time.Hour:
		r.level, r.note = ui.Attention, "expires soon"
	}
	return r
}

// printStatus prints the table and returns how many rows need attention.
func printStatus(rows []row, now time.Time) int {
	// tabwriter buffers until Flush, which reports any write error, so the
	// individual row writes need no checks of their own.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "  %s\tWHAT\tNAME\tEXPIRES\tLEFT\t\n", ui.Cell(" ", ui.Normal))
	attention := 0
	for _, r := range rows {
		if r.level != ui.Normal {
			attention++
		}
		expires, left := "", ""
		if !r.expires.IsZero() {
			expires = r.expires.Format(time.DateOnly)
			left = fmt.Sprintf("%d days", int(r.expires.Sub(now).Hours()/24))
			if r.expires.Before(now) {
				left = "-"
			}
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n", ui.Mark(r.level), r.what, r.name, expires, left, r.note)
	}
	_ = w.Flush()
	return attention
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// storeRows describes the shared store: whether the bucket is set up as the
// shared PKI needs, the current archive version, and the lock, if held.
func (e *env) storeRows(ctx context.Context, now time.Time) ([]row, error) {
	sc := *e.cfg.Store
	var rows []row

	problems, err := store.CheckBucket(ctx, e.s3, sc)
	if err != nil {
		return nil, err
	}
	bucket := row{what: "bucket", name: sc.Bucket, note: "versioning, KMS, public access blocked"}
	if len(problems) > 0 {
		var notes []string
		for _, p := range problems {
			notes = append(notes, p.What+" "+p.Detail)
		}
		bucket.level, bucket.note = ui.Critical, strings.Join(notes, "; ")
	}
	rows = append(rows, bucket)

	if v, ok, err := store.Current(ctx, e.s3, sc); err != nil {
		return nil, err
	} else if ok {
		rows = append(rows, row{what: "store", name: "version " + shortVersion(v.ID),
			note: fmt.Sprintf("written %s by %s", v.Modified.Local().Format("2006-01-02 15:04"), orDash(v.Writer))})
	}

	info, held, err := store.ReadLock(ctx, e.s3, sc)
	if err != nil {
		return nil, err
	}
	if held {
		lock := row{what: "lock", name: info.Host,
			note: fmt.Sprintf("held by %s for '%s', taken %s ago", info.ARN, info.Command, age(now.Sub(info.Started)))}
		if now.Sub(info.Started) > time.Hour {
			lock.level = ui.Attention
			lock.note += "; if that command crashed: cvpnctl unlock"
		}
		rows = append(rows, lock)
	}
	return rows, nil
}
