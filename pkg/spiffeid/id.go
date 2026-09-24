package spiffeid

import (
	"strings"
)

// TrustDomain is a validated SPIFFE trust domain name.
//
// A trust domain is the cryptographic and administrative root of an identity
// namespace. It is NOT a proof of DNS ownership, and Qredin never treats it as
// one: a trust domain named "example.com" says nothing about who controls the
// DNS zone. Authority comes from the bundle an operator explicitly configured
// for that name.
//
// TrustDomain is a comparable value type. The zero value is invalid; it is not
// a wildcard. Equality is exact byte equality of the name, never a suffix or
// subdomain relationship — "evil.example.org" is not a member of "example.org".
type TrustDomain struct {
	name string
}

// TrustDomainFromString parses a trust domain from either a bare name
// ("example.org") or a complete SPIFFE ID ("spiffe://example.org/workload"),
// in which case the path is discarded.
//
// The SPIFFE-ID form is accepted because trust domains routinely arrive
// embedded in IDs (certificate SANs, configuration, federation records) and
// forcing every call site to strip the scheme invites inconsistent hand-rolled
// stripping. Note that this means a caller cannot use this function to assert
// "this string is a bare name"; use TrustDomainFromName for that.
func TrustDomainFromString(s string) (TrustDomain, error) {
	if strings.HasPrefix(s, schemePrefix) {
		id, err := FromString(s)
		if err != nil {
			return TrustDomain{}, err
		}
		return id.TrustDomain(), nil
	}
	return TrustDomainFromName(s)
}

// TrustDomainFromName parses a bare trust domain name. A name containing a
// scheme or a path is rejected.
func TrustDomainFromName(name string) (TrustDomain, error) {
	if err := validateTrustDomainName(name); err != nil {
		return TrustDomain{}, err
	}
	return TrustDomain{name: name}, nil
}

// RequireTrustDomainFromString is TrustDomainFromString but panics on error.
//
// Intended for package-level constants in tests and for configuration that has
// already been validated during startup. Never call this on a value derived
// from a request, a certificate, or any other untrusted input.
func RequireTrustDomainFromString(s string) TrustDomain {
	td, err := TrustDomainFromString(s)
	if err != nil {
		panic("spiffeid: RequireTrustDomainFromString: " + err.Error())
	}
	return td
}

// Name returns the bare trust domain name, e.g. "prod.identity.example.com".
func (td TrustDomain) Name() string { return td.name }

// String returns the bare trust domain name, so that TrustDomain formats
// usefully in logs and error messages.
func (td TrustDomain) String() string { return td.name }

// IDString returns the trust domain in SPIFFE ID form, e.g.
// "spiffe://prod.identity.example.com". This form appears in the URI SAN of CA
// certificates, which legitimately carry a trust-domain ID with no path.
func (td TrustDomain) IDString() string {
	if td.name == "" {
		return ""
	}
	return schemePrefix + td.name
}

// ID returns the SPIFFE ID naming the trust domain itself (empty path).
func (td TrustDomain) ID() ID {
	return ID{td: td}
}

// IsZero reports whether td is the invalid zero value.
func (td TrustDomain) IsZero() bool { return td.name == "" }

// Compare returns an integer comparing two trust domains lexicographically.
// Used to impose a deterministic order on bundle and policy iteration so that
// output is reproducible.
func (td TrustDomain) Compare(other TrustDomain) int {
	return strings.Compare(td.name, other.name)
}

// MarshalText implements encoding.TextMarshaler, emitting the bare name.
func (td TrustDomain) MarshalText() ([]byte, error) {
	return []byte(td.name), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. It validates, so trust
// domains decoded from JSON, YAML or the database cannot bypass the parser.
func (td *TrustDomain) UnmarshalText(b []byte) error {
	parsed, err := TrustDomainFromString(string(b))
	if err != nil {
		return err
	}
	*td = parsed
	return nil
}

// ID is a validated SPIFFE ID.
//
// ID is a comparable value type, safe as a map key. Because the parser rejects
// every alternative textual encoding (percent-escapes, dot segments, uppercase
// authorities), byte equality of two parsed IDs is equivalent to semantic
// equality — there is no normalisation step that callers could forget.
//
// The zero value is invalid and is never a wildcard.
type ID struct {
	td   TrustDomain
	path string
}

// FromString parses a complete SPIFFE ID.
//
// This is the only entry point for IDs arriving from outside the process —
// certificate SANs, API requests, configuration, the database. It performs no
// normalisation: an ID either is already in canonical form or it is rejected.
func FromString(s string) (ID, error) {
	switch {
	case s == "":
		return ID{}, ErrEmpty
	case len(s) > MaxIDLength:
		// Checked before any scanning so that an oversized input cannot make
		// the parser do proportional work.
		return ID{}, ErrIDTooLong
	case !strings.HasPrefix(s, schemePrefix):
		return ID{}, ErrWrongScheme
	}

	rest := s[len(schemePrefix):]

	// The authority runs to the first '/', which also begins the path. Every
	// character that could introduce userinfo ('@'), a port (':'), a query
	// ('?') or a fragment ('#') is outside the permitted trust-domain charset,
	// so those forms are rejected by validateTrustDomainName rather than
	// needing separate handling.
	name, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		name, path = rest[:i], rest[i:]
	}

	if err := validateTrustDomainName(name); err != nil {
		return ID{}, err
	}
	if err := ValidatePath(path); err != nil {
		return ID{}, err
	}
	return ID{td: TrustDomain{name: name}, path: path}, nil
}

// RequireFromString is FromString but panics on error. Tests and validated
// configuration only; never untrusted input.
func RequireFromString(s string) ID {
	id, err := FromString(s)
	if err != nil {
		panic("spiffeid: RequireFromString: " + err.Error())
	}
	return id
}

// FromPath builds an ID from a trust domain and a path. The path must already
// be in "/a/b" form and is validated.
func FromPath(td TrustDomain, path string) (ID, error) {
	if td.IsZero() {
		return ID{}, ErrMissingTrustDomain
	}
	if err := ValidatePath(path); err != nil {
		return ID{}, err
	}
	id := ID{td: td, path: path}
	if len(id.String()) > MaxIDLength {
		return ID{}, ErrIDTooLong
	}
	return id, nil
}

// FromSegments builds an ID from a trust domain and individual path segments,
// joining them with '/'.
//
// This is the constructor to use when assembling an ID from attested selector
// values (a Kubernetes namespace and service account, say). Segments are
// validated individually, so a value containing '/' is rejected rather than
// silently creating extra path structure — that is the difference between a
// namespace called "a/b" being an error and it becoming a sibling identity.
func FromSegments(td TrustDomain, segments ...string) (ID, error) {
	if td.IsZero() {
		return ID{}, ErrMissingTrustDomain
	}
	if len(segments) == 0 {
		return td.ID(), nil
	}

	var b strings.Builder
	for _, seg := range segments {
		if err := checkSegment(seg); err != nil {
			return ID{}, err
		}
		for i := 0; i < len(seg); i++ {
			if !isValidPathSegmentChar(seg[i]) {
				return ID{}, ErrBadPathSegmentChar
			}
		}
		b.WriteByte('/')
		b.WriteString(seg)
	}
	return FromPath(td, b.String())
}

// TrustDomain returns the ID's trust domain.
func (id ID) TrustDomain() TrustDomain { return id.td }

// Path returns the path component, e.g. "/ns/prod/sa/api". Empty for an ID that
// names a trust domain rather than a workload.
func (id ID) Path() string { return id.path }

// Segments returns the path split into segments, without leading slashes.
// Returns nil for an empty path.
//
// Policy matching uses this rather than string prefixes: a path is a name, not
// a hierarchy, and "/ns/prod" being a textual prefix of "/ns/production" must
// not imply any relationship between the two identities.
func (id ID) Segments() []string {
	if id.path == "" {
		return nil
	}
	return strings.Split(id.path[1:], "/")
}

// String returns the complete SPIFFE ID, or "" for the zero value.
func (id ID) String() string {
	if id.td.IsZero() {
		return ""
	}
	return schemePrefix + id.td.name + id.path
}

// MemberOf reports whether the ID belongs to the given trust domain.
//
// Exact equality only. There is no notion of a parent or child trust domain in
// SPIFFE, and inventing one here would let "evil.example.org" authenticate as a
// member of "example.org".
func (id ID) MemberOf(td TrustDomain) bool {
	return !id.td.IsZero() && id.td == td
}

// IsZero reports whether id is the invalid zero value.
func (id ID) IsZero() bool { return id.td.IsZero() }

// IsWorkload reports whether the ID names a workload (has a non-empty path)
// rather than a trust domain.
//
// Leaf SVIDs must satisfy this; CA certificates need not. pkg/x509svid enforces
// the rule so that the check cannot be forgotten at a call site.
func (id ID) IsWorkload() bool { return id.path != "" }

// MarshalText implements encoding.TextMarshaler.
func (id ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, validating on the way in
// so that an ID read from JSON, YAML or a database column is parsed by exactly
// the same code as one read from a certificate.
func (id *ID) UnmarshalText(b []byte) error {
	parsed, err := FromString(string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}
