// Package state persists the mapping of managed users to their cloud provider
// certificate IDs in a JSON file next to the per-user certificate folders.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aartinian/cvpnctl/internal/fsutil"
)

// Filename is the name of the state file inside certs.output_dir.
const Filename = ".cvpnctl-state.json"

// UserRecord holds the provider certificate ID and timestamps for a managed user.
type UserRecord struct {
	User       string    `json:"user"`
	ProviderID string    `json:"provider_id"` // e.g. the ACM certificate ARN
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Store is an in-memory map of users backed by a JSON file.
type Store struct {
	path    string
	records map[string]UserRecord
}

// Load reads the state file from dir. A missing file yields an empty store.
func Load(dir string) (*Store, error) {
	s := &Store{
		path:    filepath.Join(dir, Filename),
		records: make(map[string]UserRecord),
	}

	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read: %w", err)
	}
	if err := json.Unmarshal(data, &s.records); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", s.path, err)
	}
	if s.records == nil { // the file held JSON null
		s.records = make(map[string]UserRecord)
	}
	return s, nil
}

// Save writes the store to disk atomically, creating the directory if needed.
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := fsutil.WriteFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}

// Set upserts a user record with the given provider certificate ID.
func (s *Store) Set(user, providerID string) {
	now := time.Now().UTC()
	r, ok := s.records[user]
	if !ok {
		r = UserRecord{User: user, CreatedAt: now}
	}
	r.ProviderID = providerID
	r.UpdatedAt = now
	s.records[user] = r
}

// Get returns the record for user and whether it was found.
func (s *Store) Get(user string) (UserRecord, bool) {
	r, ok := s.records[user]
	return r, ok
}

// Delete removes user from the store.
func (s *Store) Delete(user string) {
	delete(s.records, user)
}

// All returns all records sorted by username.
func (s *Store) All() []UserRecord {
	out := make([]UserRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b UserRecord) int { return strings.Compare(a.User, b.User) })
	return out
}
