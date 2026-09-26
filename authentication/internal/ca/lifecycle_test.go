package ca_test

import (
	"errors"
	"testing"
	"time"

	"github.com/qredin/qredin/authentication/internal/ca"
)

func TestAuthorityLifecycleRequiresOverlapAndTwoApprovals(t *testing.T) {
	t.Parallel()
	if _, err := ca.NewLifecycle(time.Hour, 30*time.Minute); !errors.Is(err, ca.ErrOverlapTooShort) {
		t.Fatalf("short overlap error = %v", err)
	}
	lifecycle, err := ca.NewLifecycle(time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate("operator-a", "operator-a"); !errors.Is(err, ca.ErrApprovalRequired) {
		t.Fatalf("same approval error = %v", err)
	}
	if err := lifecycle.Activate("operator-a", "operator-b"); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Retire(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Taint(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Revoke(); err != nil {
		t.Fatal(err)
	}
	if lifecycle.State() != ca.AuthorityRevoked {
		t.Fatalf("state = %q, want revoked", lifecycle.State())
	}
}
