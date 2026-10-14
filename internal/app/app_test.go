package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aartinian/cvpnctl/internal/app/command"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{command.ErrNeedsAttention, 2},
		{fmt.Errorf("status: %w", command.ErrNeedsAttention), 2},
		{errors.New("aws: resolve credentials: …"), 1},
	}
	for _, tt := range tests {
		if got := ExitCode(tt.err); got != tt.want {
			t.Errorf("ExitCode(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}
