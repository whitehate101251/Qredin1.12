package spiffeid_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qredin/qredin/pkg/spiffeid"
)

func TestFromString_Valid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in       string
		wantTD   string
		wantPath string
	}{
		{"spiffe://example.org", "example.org", ""},
		{"spiffe://example.org/workload", "example.org", "/workload"},
		{"spiffe://example.org/ns/prod/sa/api", "example.org", "/ns/prod/sa/api"},
		{"spiffe://prod.identity.qredin.example.com/agent/data", "prod.identity.qredin.example.com", "/agent/data"},
		{"spiffe://customer-8f3a1c.identity.qredin.example.com/svc/billing", "customer-8f3a1c.identity.qredin.example.com", "/svc/billing"},

		// Trust domains permit dots, dashes and underscores.
		{"spiffe://a-b_c.d", "a-b_c.d", ""},
		{"spiffe://1", "1", ""},

		// Path segments are case-sensitive and permit uppercase, unlike the
		// trust domain. This asymmetry is specified, not accidental.
		{"spiffe://example.org/MixedCase", "example.org", "/MixedCase"},
		{"spiffe://example.org/a.b-c_d", "example.org", "/a.b-c_d"},

		// A segment may contain dots as long as it is not exactly "." or "..".
		{"spiffe://example.org/...", "example.org", "/..."},
		{"spiffe://example.org/a./b", "example.org", "/a./b"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()

			id, err := spiffeid.FromString(tc.in)
			if err != nil {
				t.Fatalf("FromString(%q) unexpected error: %v", tc.in, err)
			}
			if got := id.TrustDomain().Name(); got != tc.wantTD {
				t.Errorf("trust domain = %q, want %q", got, tc.wantTD)
			}
			if got := id.Path(); got != tc.wantPath {
				t.Errorf("path = %q, want %q", got, tc.wantPath)
			}
			if got := id.String(); got != tc.in {
				t.Errorf("String() = %q, want exact round-trip of %q", got, tc.in)
			}
		})
	}
}

func TestFromString_Invalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", spiffeid.ErrEmpty},

		// Scheme.
		{"no scheme", "example.org/workload", spiffeid.ErrWrongScheme},
		{"bare name", "example.org", spiffeid.ErrWrongScheme},
		{"http scheme", "http://example.org/workload", spiffeid.ErrWrongScheme},
		{"single slash", "spiffe:/example.org", spiffeid.ErrWrongScheme},
		{"no slashes", "spiffe:example.org", spiffeid.ErrWrongScheme},
		// Case-sensitive scheme: RFC 3986 says schemes are case-insensitive,
		// but SPIFFE specifies lowercase and accepting both would give one
		// identity two textual forms. Documented in docs/assumptions.md A-01.
		{"uppercase scheme", "SPIFFE://example.org/workload", spiffeid.ErrWrongScheme},
		{"mixed case scheme", "Spiffe://example.org/workload", spiffeid.ErrWrongScheme},

		// Trust domain.
		{"missing trust domain", "spiffe://", spiffeid.ErrMissingTrustDomain},
		{"missing trust domain with path", "spiffe:///workload", spiffeid.ErrMissingTrustDomain},
		{"uppercase trust domain", "spiffe://Example.org/workload", spiffeid.ErrBadTrustDomainChar},
		{"userinfo", "spiffe://user@example.org/workload", spiffeid.ErrBadTrustDomainChar},
		{"userinfo with password", "spiffe://u:p@example.org/w", spiffeid.ErrBadTrustDomainChar},
		{"port", "spiffe://example.org:8443/workload", spiffeid.ErrBadTrustDomainChar},
		{"query in authority", "spiffe://example.org?a=1", spiffeid.ErrBadTrustDomainChar},
		{"fragment in authority", "spiffe://example.org#frag", spiffeid.ErrBadTrustDomainChar},
		{"percent encoded trust domain", "spiffe://example%2eorg/workload", spiffeid.ErrBadTrustDomainChar},
		{"space in trust domain", "spiffe://exa mple.org/w", spiffeid.ErrBadTrustDomainChar},
		{"backslash", "spiffe://example.org\\workload", spiffeid.ErrBadTrustDomainChar},
		{"unicode trust domain", "spiffe://exämple.org/w", spiffeid.ErrBadTrustDomainChar},
		{"null byte", "spiffe://example.org\x00/w", spiffeid.ErrBadTrustDomainChar},

		// Path.
		{"trailing slash", "spiffe://example.org/workload/", spiffeid.ErrTrailingSlash},
		{"root path only", "spiffe://example.org/", spiffeid.ErrEmptySegment},
		{"double slash", "spiffe://example.org//workload", spiffeid.ErrEmptySegment},
		{"double slash mid path", "spiffe://example.org/a//b", spiffeid.ErrEmptySegment},
		{"dot segment", "spiffe://example.org/./workload", spiffeid.ErrDotSegment},
		{"dotdot segment", "spiffe://example.org/../workload", spiffeid.ErrDotSegment},
		{"trailing dotdot", "spiffe://example.org/a/..", spiffeid.ErrDotSegment},
		{"trailing dot", "spiffe://example.org/a/.", spiffeid.ErrDotSegment},
		{"percent encoded path", "spiffe://example.org/work%2Fload", spiffeid.ErrBadPathSegmentChar},
		{"percent encoded dotdot", "spiffe://example.org/%2e%2e/admin", spiffeid.ErrBadPathSegmentChar},
		{"query in path", "spiffe://example.org/workload?a=1", spiffeid.ErrBadPathSegmentChar},
		{"fragment in path", "spiffe://example.org/workload#f", spiffeid.ErrBadPathSegmentChar},
		{"space in path", "spiffe://example.org/work load", spiffeid.ErrBadPathSegmentChar},
		{"colon in path", "spiffe://example.org/work:load", spiffeid.ErrBadPathSegmentChar},
		{"newline in path", "spiffe://example.org/work\nload", spiffeid.ErrBadPathSegmentChar},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id, err := spiffeid.FromString(tc.in)
			if err == nil {
				t.Fatalf("FromString(%q) = %q, want error %v", tc.in, id, tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("FromString(%q) error = %v, want %v", tc.in, err, tc.want)
			}
			if !id.IsZero() {
				t.Errorf("FromString(%q) returned non-zero ID alongside an error", tc.in)
			}
		})
	}
}

// Length limits are specification maxima, and also bound the work an attacker
// can make the parser do.
func TestFromString_LengthLimits(t *testing.T) {
	t.Parallel()

	t.Run("trust domain at limit", func(t *testing.T) {
		t.Parallel()
		name := strings.Repeat("a", spiffeid.MaxTrustDomainLength)
		if _, err := spiffeid.FromString("spiffe://" + name); err != nil {
			t.Fatalf("trust domain of exactly %d bytes should be valid: %v", len(name), err)
		}
	})

	t.Run("trust domain over limit", func(t *testing.T) {
		t.Parallel()
		name := strings.Repeat("a", spiffeid.MaxTrustDomainLength+1)
		_, err := spiffeid.FromString("spiffe://" + name)
		if !errors.Is(err, spiffeid.ErrTrustDomainTooLong) {
			t.Fatalf("error = %v, want ErrTrustDomainTooLong", err)
		}
	})

	t.Run("id over limit", func(t *testing.T) {
		t.Parallel()
		in := "spiffe://example.org/" + strings.Repeat("a", spiffeid.MaxIDLength)
		_, err := spiffeid.FromString(in)
		if !errors.Is(err, spiffeid.ErrIDTooLong) {
			t.Fatalf("error = %v, want ErrIDTooLong", err)
		}
	})
}

// MemberOf must be exact equality. A suffix or subdomain match would let a
// trust domain an attacker can register authenticate into its "parent".
func TestMemberOf_NoSuffixMatching(t *testing.T) {
	t.Parallel()

	parent := spiffeid.RequireTrustDomainFromString("example.org")

	hostile := []string{
		"spiffe://evil.example.org/w", // subdomain
		"spiffe://example.org.evil/w", // suffix extension
		"spiffe://xexample.org/w",     // prefix extension
		"spiffe://example.orgx/w",     // suffix extension, no dot
		"spiffe://example-org/w",      // dash substituted for dot
		"spiffe://example_org/w",      // underscore substituted for dot
	}
	for _, s := range hostile {
		id := spiffeid.RequireFromString(s)
		if id.MemberOf(parent) {
			t.Errorf("%q must NOT be a member of %q", s, parent)
		}
	}

	if !spiffeid.RequireFromString("spiffe://example.org/w").MemberOf(parent) {
		t.Error("exact trust domain match must succeed")
	}
	if (spiffeid.ID{}).MemberOf(spiffeid.TrustDomain{}) {
		t.Error("zero ID must not be a member of the zero trust domain")
	}
}

func TestSegments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want []string
	}{
		{"spiffe://example.org", nil},
		{"spiffe://example.org/a", []string{"a"}},
		{"spiffe://example.org/ns/prod/sa/api", []string{"ns", "prod", "sa", "api"}},
	}
	for _, tc := range cases {
		got := spiffeid.RequireFromString(tc.in).Segments()
		if len(got) != len(tc.want) {
			t.Fatalf("Segments(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("Segments(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}

func TestFromSegments(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("example.org")

	t.Run("joins segments", func(t *testing.T) {
		t.Parallel()
		id, err := spiffeid.FromSegments(td, "ns", "prod", "sa", "api")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := id.String(), "spiffe://example.org/ns/prod/sa/api"; got != want {
			t.Errorf("= %q, want %q", got, want)
		}
	})

	t.Run("no segments yields trust domain id", func(t *testing.T) {
		t.Parallel()
		id, err := spiffeid.FromSegments(td)
		if err != nil {
			t.Fatal(err)
		}
		if id.IsWorkload() {
			t.Error("expected a trust-domain ID with no path")
		}
	})

	// The important case. Selector values reach FromSegments from attested
	// platform metadata. A value containing '/' must be an error, not extra
	// path structure that silently produces a different identity.
	t.Run("rejects separator injection", func(t *testing.T) {
		t.Parallel()
		hostile := [][]string{
			{"ns", "prod/sa/admin"},
			{"ns", "../admin"},
			{"ns", ".."},
			{"ns", "."},
			{"ns", ""},
			{"ns", "a b"},
			{"ns", "a%2Fb"},
		}
		for _, segs := range hostile {
			if id, err := spiffeid.FromSegments(td, segs...); err == nil {
				t.Errorf("FromSegments(%q) = %q, want error", segs, id)
			}
		}
	})
}

func TestTrustDomainFromString(t *testing.T) {
	t.Parallel()

	t.Run("accepts bare name", func(t *testing.T) {
		t.Parallel()
		td, err := spiffeid.TrustDomainFromString("example.org")
		if err != nil {
			t.Fatal(err)
		}
		if td.Name() != "example.org" {
			t.Errorf("Name() = %q", td.Name())
		}
		if td.IDString() != "spiffe://example.org" {
			t.Errorf("IDString() = %q", td.IDString())
		}
	})

	t.Run("accepts full id and discards path", func(t *testing.T) {
		t.Parallel()
		td, err := spiffeid.TrustDomainFromString("spiffe://example.org/ns/prod")
		if err != nil {
			t.Fatal(err)
		}
		if td.Name() != "example.org" {
			t.Errorf("Name() = %q, want example.org", td.Name())
		}
	})

	t.Run("rejects bare name with path", func(t *testing.T) {
		t.Parallel()
		if _, err := spiffeid.TrustDomainFromString("example.org/ns/prod"); err == nil {
			t.Error("want error for a bare name containing a path")
		}
	})

	t.Run("zero value", func(t *testing.T) {
		t.Parallel()
		var td spiffeid.TrustDomain
		if !td.IsZero() {
			t.Error("zero TrustDomain should report IsZero")
		}
		if td.IDString() != "" {
			t.Errorf("zero TrustDomain IDString() = %q, want empty", td.IDString())
		}
	})
}

// Text unmarshalling is how IDs arrive from JSON, YAML and database columns.
// It must go through exactly the same parser as a certificate SAN.
func TestTextMarshalling(t *testing.T) {
	t.Parallel()

	type doc struct {
		ID spiffeid.ID          `json:"id"`
		TD spiffeid.TrustDomain `json:"td"`
	}

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		in := `{"id":"spiffe://example.org/ns/prod","td":"example.org"}`
		var d doc
		if err := json.Unmarshal([]byte(in), &d); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != in {
			t.Errorf("round trip = %s, want %s", out, in)
		}
	})

	t.Run("rejects invalid on unmarshal", func(t *testing.T) {
		t.Parallel()
		var d doc
		err := json.Unmarshal([]byte(`{"id":"spiffe://example.org/../admin"}`), &d)
		if err == nil {
			t.Fatal("want error unmarshalling an ID with a dot segment")
		}
	})
}

// ID is used as a map key throughout the policy and cache layers. That is only
// safe if equality is exact and there is no unnormalised alternative encoding
// that would produce a second key for the same identity.
func TestIDIsComparableAndCanonical(t *testing.T) {
	t.Parallel()

	a := spiffeid.RequireFromString("spiffe://example.org/ns/prod")
	b := spiffeid.RequireFromString("spiffe://example.org/ns/prod")
	c := spiffeid.RequireFromString("spiffe://example.org/ns/Prod")

	m := map[spiffeid.ID]int{a: 1}
	if m[b] != 1 {
		t.Error("equal IDs must hash to the same map key")
	}
	if _, ok := m[c]; ok {
		t.Error("path comparison must be case-sensitive")
	}
}

// Invariants that must hold for every input, valid or not.
func FuzzParseID(f *testing.F) {
	seeds := []string{
		"", "spiffe://example.org", "spiffe://example.org/w", "spiffe://example.org/",
		"spiffe:///w", "spiffe://ex%41mple.org", "spiffe://example.org/../a",
		"SPIFFE://example.org/w", "spiffe://example.org:443/w", "spiffe://a@b/c",
		"spiffe://example.org/a//b", "spiffe://example.org/\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		id, err := spiffeid.FromString(in)
		if err != nil {
			if !id.IsZero() {
				t.Fatalf("error return must yield the zero ID; got %q for input %q", id, in)
			}
			return
		}

		// 1. Canonical form: a parsed ID must serialise back to its exact input.
		//    If this ever fails, some input has two textual encodings and the
		//    aliasing risk described in the package doc is real.
		if got := id.String(); got != in {
			t.Fatalf("not canonical: FromString(%q).String() = %q", in, got)
		}

		// 2. Idempotent: re-parsing the serialised form yields an equal value.
		again, err := spiffeid.FromString(id.String())
		if err != nil {
			t.Fatalf("re-parsing %q failed: %v", id, err)
		}
		if again != id {
			t.Fatalf("re-parse not equal: %q vs %q", again, id)
		}

		// 3. A valid ID always has a valid, non-zero trust domain.
		if id.TrustDomain().IsZero() {
			t.Fatalf("valid ID %q has a zero trust domain", in)
		}

		// 4. Membership is reflexive and matches nothing else.
		if !id.MemberOf(id.TrustDomain()) {
			t.Fatalf("%q is not a member of its own trust domain", in)
		}

		// 5. Segments never contain a separator or a relative modifier, so
		//    downstream path-segment matching cannot be tricked.
		for _, seg := range id.Segments() {
			if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "/%") {
				t.Fatalf("invalid segment %q extracted from %q", seg, in)
			}
		}

		// 6. Specification bounds hold.
		if len(id.String()) > spiffeid.MaxIDLength {
			t.Fatalf("ID exceeds maximum length: %q", in)
		}
		if len(id.TrustDomain().Name()) > spiffeid.MaxTrustDomainLength {
			t.Fatalf("trust domain exceeds maximum length: %q", in)
		}
	})
}
