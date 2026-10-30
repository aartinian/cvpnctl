package store

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aartinian/cvpnctl/internal/store/storetest"
)

func TestCreate(t *testing.T) {
	archive := []byte("the PKI")
	landed412 := storetest.APIError("PutObject", http.StatusPreconditionFailed, "PreconditionFailed")
	tests := map[string]struct {
		setup   func(f *storetest.FakeS3)
		wantErr string // "" means success
	}{
		"uploads": {setup: func(*storetest.FakeS3) {}},
		"refuses an existing PKI": {
			setup: func(f *storetest.FakeS3) {
				_, _ = Create(context.Background(), f, testStore, []byte("another PKI"), "")
			},
			wantErr: ErrStoreExists.Error(),
		},
		// The SDK's retry got 412 from our own upload: it is there, so done.
		"retry hit its own upload": {setup: func(f *storetest.FakeS3) { f.FailNextPut(landed412, true) }},
		"lost response, landed":    {setup: func(f *storetest.FakeS3) { f.FailNextPut(errors.New("connection reset"), true) }},
		"lost response, not landed": {
			setup:   func(f *storetest.FakeS3) { f.FailNextPut(errors.New("connection reset"), false) },
			wantErr: "connection reset",
		},
		"can't tell": {
			setup: func(f *storetest.FakeS3) {
				f.FailNextPut(errors.New("connection reset"), true)
				f.FailNextHead(errors.New("timeout"))
			},
			wantErr: "run cvpnctl status",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := storetest.New()
			tt.setup(f)
			version, err := Create(context.Background(), f, testStore, archive, "arn:aws:iam::111122223333:user/ari")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || version == "" {
				t.Fatalf("Create = %q, %v", version, err)
			}
			if got, _ := Download(context.Background(), f, testStore, version); !bytes.Equal(got, archive) {
				t.Errorf("version %s holds %q, want the archive", version, got)
			}
		})
	}
}
