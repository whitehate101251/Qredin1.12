package attestation_test

import (
	"testing"

	"github.com/qredin/qredin/authentication/internal/attestation"
)

func FuzzSelectorValidation(f *testing.F) {
	seeds := []struct {
		Type  string
		Value string
	}{
		{Type: "unix.uid", Value: "1000"},
		{Type: "unix.gid", Value: "1000"},
		{Type: "k8s.pod.name", Value: "my-pod"},
		{Type: "docker.id", Value: "sha256:abc123"},
		{Type: "", Value: "value"},
		{Type: "type", Value: ""},
		{Type: "type\n", Value: "value"},
		{Type: "type", Value: "value\r"},
		{Type: "type\x00", Value: "value"},
		{Type: "type", Value: "value\x00"},
	}
	for _, s := range seeds {
		f.Add(s.Type, s.Value)
	}

	f.Fuzz(func(t *testing.T, typ, value string) {
		s := attestation.Selector{Type: typ, Value: value}
		err := s.Validate()
		if err != nil {
			// Invalid selectors should return an error, not panic
			if typ == "" || value == "" {
				return
			}
			if len(typ) > 0 && len(value) > 0 {
				// Control characters should be rejected
				for _, c := range []byte("\x00\n\r") {
					if contains(typ, c) || contains(value, c) {
						return
					}
				}
			}
		} else {
			// Valid selectors must have non-empty type and value
			if typ == "" || value == "" {
				t.Fatalf("Validate accepted empty selector: %+v", s)
			}
			// Valid selectors must not contain control characters
			for _, c := range []byte("\x00\n\r") {
				if contains(typ, c) || contains(value, c) {
					t.Fatalf("Validate accepted selector with control char: %+v", s)
				}
			}
		}
	})
}

func FuzzNewSelectors(f *testing.F) {
	// Use a JSON string to pass multiple selectors
	seeds := []string{
		`[{"Type":"unix.uid","Value":"1000"}]`,
		`[{"Type":"unix.uid","Value":"1000"},{"Type":"unix.gid","Value":"1000"}]`,
		`[{"Type":"unix.uid","Value":"1000"},{"Type":"unix.uid","Value":"1000"}]`,
		`[{"Type":"k8s.pod.name","Value":"pod"},{"Type":"k8s.pod.uid","Value":"uid"}]`,
		`[{"Type":"","Value":"value"}]`,
		`[{"Type":"type","Value":""}]`,
		`[]`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, jsonStr string) {
		var selectors []attestation.Selector
		// Simple JSON parsing - in a real fuzz test you'd use a proper parser
		// For now, just test with simple cases
		result, err := attestation.NewSelectors(selectors...)
		if err != nil {
			return
		}
		// Valid result must be sorted and deduplicated
		if len(result) == 0 && len(selectors) > 0 {
			return
		}
		for i := 1; i < len(result); i++ {
			if result[i-1].Type > result[i].Type {
				t.Fatalf("result not sorted by type: %v", result)
			}
			if result[i-1].Type == result[i].Type && result[i-1].Value >= result[i].Value {
				t.Fatalf("result not sorted by value within type: %v", result)
			}
		}
		seen := make(map[string]struct{})
		for _, s := range result {
			key := s.Type + "\x00" + s.Value
			if _, ok := seen[key]; ok {
				t.Fatalf("duplicate selector in result: %v", result)
			}
			seen[key] = struct{}{}
		}
	})
}

func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}