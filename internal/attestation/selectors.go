// Package attestation contains the trusted output of node/workload attestors.
//
// An attestor produces selectors from out-of-band evidence such as kernel or
// orchestrator state. Callers must not be able to construct an attestation
// result from a claimed SPIFFE ID or selector metadata.
package attestation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Selector is one independently verified platform fact.
type Selector struct {
	Type  string
	Value string
}

// Validate rejects ambiguous or empty selector facts.
func (s Selector) Validate() error {
	if strings.TrimSpace(s.Type) == "" {
		return errors.New("attestation: selector type is required")
	}
	if strings.TrimSpace(s.Value) == "" {
		return errors.New("attestation: selector value is required")
	}
	if strings.ContainsAny(s.Type, "\x00\n\r") || strings.ContainsAny(s.Value, "\x00\n\r") {
		return errors.New("attestation: selector contains a control character")
	}
	return nil
}

// Selectors is an immutable-by-convention collection of verified facts.
type Selectors []Selector

// NewSelectors validates and canonicalizes attestor output. Duplicate facts
// are rejected so registration matching cannot depend on caller ordering.
func NewSelectors(values ...Selector) (Selectors, error) {
	seen := make(map[string]struct{}, len(values))
	out := append(Selectors(nil), values...)
	for _, selector := range out {
		if err := selector.Validate(); err != nil {
			return nil, err
		}
		key := selector.Type + "\x00" + selector.Value
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("attestation: duplicate selector %q", selector.Type)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Value < out[j].Value
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// Contains reports whether this attestation includes an exact verified fact.
func (s Selectors) Contains(want Selector) bool {
	for _, have := range s {
		if have == want {
			return true
		}
	}
	return false
}

// ContainsType reports whether a selector of the given type is present.
func (s Selectors) ContainsType(selectorType string) bool {
	for _, selector := range s {
		if selector.Type == selectorType {
			return true
		}
	}
	return false
}

// Matches reports whether all required selectors are present.
func (s Selectors) Matches(required Selectors) bool {
	for _, selector := range required {
		if !s.Contains(selector) {
			return false
		}
	}
	return true
}
