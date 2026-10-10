package command

import "testing"

func TestValidateUser(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "-rf", "--batch", "../etc", "a/b", "a b", "ä"} {
		if err := validateUser(bad); err == nil {
			t.Errorf("validateUser(%q) should fail", bad)
		}
	}
	for _, good := range []string{"max.mustermann", "bob", "a_b-c.1", "x-"} {
		if err := validateUser(good); err != nil {
			t.Errorf("validateUser(%q) = %v", good, err)
		}
	}
}
