package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("load empty store: %v", err)
	}
	s.Set("carol", "arn:3")
	s.Set("max", "arn:1")
	s.Set("bob", "arn:2")
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	s2, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	r, ok := s2.Get("max")
	if !ok || r.ProviderID != "arn:1" {
		t.Fatalf("Get(max) = %+v, %v", r, ok)
	}

	var names []string
	for _, r := range s2.All() {
		names = append(names, r.User)
	}
	if got := filepath.Join(names...); got != filepath.Join("bob", "carol", "max") {
		t.Errorf("All() not sorted by user: %v", names)
	}

	fi, err := os.Stat(filepath.Join(dir, Filename))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestSetKeepsCreatedAt(t *testing.T) {
	s, _ := Load(t.TempDir())
	s.Set("max", "arn:1")
	created := s.records["max"].CreatedAt
	s.Set("max", "arn:2")
	r, _ := s.Get("max")
	if !r.CreatedAt.Equal(created) || r.ProviderID != "arn:2" {
		t.Errorf("upsert changed CreatedAt or dropped ProviderID: %+v", r)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	s, _ := Load(dir)
	s.Set("bob", "arn:2")
	s.Delete("bob")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, _ := Load(dir)
	if _, ok := s2.Get("bob"); ok {
		t.Error("bob still present after delete")
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not", "yet")
	s, _ := Load(dir)
	s.Set("max", "arn:1")
	if err := s.Save(); err != nil {
		t.Fatalf("save into missing directory: %v", err)
	}
}

// A state file holding JSON null loads as empty, and can be written to.
func TestLoadNull(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, Filename), []byte("null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Set("max", "cert-1") // panicked on a nil map
	if _, ok := s.Get("max"); !ok {
		t.Error("max not set")
	}
}
