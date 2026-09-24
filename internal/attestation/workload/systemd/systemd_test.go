package systemd_test

import (
	"errors"
	"os"
	"testing"

	"github.com/qredin/qredin/internal/attestation"
	"github.com/qredin/qredin/internal/attestation/workload/systemd"
)

func TestAttestUsesResolverMetadata(t *testing.T) {
	fragment := t.TempDir() + "/qredin-api.service"
	if err := os.WriteFile(fragment, []byte("[Service]\nExecStart=/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	selectors, err := systemd.Attest(42, fakeResolver{fragment: fragment})
	if err != nil {
		t.Fatal(err)
	}
	if !selectors.Contains(attestation.Selector{Type: "systemd.unit", Value: "qredin-api.service"}) {
		t.Fatal("missing unit selector")
	}
}

func TestAttestFailsClosedWithoutResolver(t *testing.T) {
	if _, err := systemd.Attest(42, nil); !errors.Is(err, systemd.ErrUnitUnavailable) {
		t.Fatalf("error = %v, want ErrUnitUnavailable", err)
	}
}

type fakeResolver struct{ fragment string }

func (r fakeResolver) UnitForPID(int) (string, string, error) {
	return "qredin-api.service", r.fragment, nil
}
