package ca

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLifecycleMarshalRoundTrip(t *testing.T) {
	lc, err := NewLifecycle(time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.Activate("admin-1", "admin-2"); err != nil {
		t.Fatal(err)
	}

	state := lc.MarshalState()
	if state.State != AuthorityActive {
		t.Fatalf("expected active, got %s", state.State)
	}

	// Serialize to JSON and back
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}

	var restored LifecycleState
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}

	lc2, err := UnmarshalState(restored)
	if err != nil {
		t.Fatal(err)
	}
	if lc2.State() != AuthorityActive {
		t.Fatalf("round-trip: expected active, got %s", lc2.State())
	}
	if lc2.Overlap() != 2*time.Hour {
		t.Fatalf("round-trip: expected 2h overlap, got %s", lc2.Overlap())
	}
}

func TestUnmarshalStateRejectsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		state LifecycleState
	}{
		{"zero TTL", LifecycleState{State: AuthorityPrepared, MaxSVIDTTL: 0, Overlap: time.Hour}},
		{"overlap too short", LifecycleState{State: AuthorityPrepared, MaxSVIDTTL: 2 * time.Hour, Overlap: time.Hour}},
		{"unknown state", LifecycleState{State: "bogus", MaxSVIDTTL: time.Hour, Overlap: 2 * time.Hour}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalState(tt.state)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLifecycleStateTransitionsPersist(t *testing.T) {
	lc, err := NewLifecycle(time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Test each state persists correctly
	states := []struct {
		action func() error
		expect AuthorityState
	}{
		{func() error { return lc.Activate("a", "b") }, AuthorityActive},
		{func() error { return lc.Retire() }, AuthorityOld},
		{func() error { return lc.Revoke() }, AuthorityRevoked},
	}

	for _, s := range states {
		if err := s.action(); err != nil {
			t.Fatalf("transition to %s: %v", s.expect, err)
		}
		ms := lc.MarshalState()
		restored, err := UnmarshalState(ms)
		if err != nil {
			t.Fatalf("unmarshal at %s: %v", s.expect, err)
		}
		if restored.State() != s.expect {
			t.Fatalf("expected %s, got %s", s.expect, restored.State())
		}
	}
}
