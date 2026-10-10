package command

import (
	"fmt"
	"regexp"
	"strings"
)

// validUsername is the safe subset for both filesystem paths and EasyRSA names.
var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validateUser rejects usernames that are unsafe as a path element or as an
// argument to the easyrsa script. The character set alone is not enough: "."
// and ".." pass it but would resolve to the output directory or its parent,
// and a leading hyphen would be parsed as an easyrsa option.
func validateUser(user string) error {
	switch {
	case !validUsername.MatchString(user):
		return fmt.Errorf("invalid username %q: only letters, digits, dots, hyphens, and underscores are allowed", user)
	case user == "." || user == "..":
		return fmt.Errorf("invalid username %q", user)
	case strings.HasPrefix(user, "-"):
		return fmt.Errorf("invalid username %q: must not start with a hyphen", user)
	}
	return nil
}
