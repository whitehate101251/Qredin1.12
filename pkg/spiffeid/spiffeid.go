// Package spiffeid implements the SPIFFE ID specification.
//
// A SPIFFE ID is a URI of the form:
//
//	spiffe://<trust-domain>/<path>
//
// This package is the root of Qredin's trust decisions: every certificate, every
// policy lookup and every audit record is keyed on a value produced here. It is
// therefore written to a deliberately narrow contract.
//
// # Parsing strategy
//
// IDs are parsed directly from their raw bytes. net/url is NOT used, on purpose.
// net/url percent-decodes, performs path normalisation (resolving "." and ".."),
// and accepts constructs the SPIFFE specification forbids. Any of those
// behaviours turns a textual comparison into a semantic one and creates
// aliasing: two different byte strings that compare equal, or one byte string
// that means different things to two components. For an identity namespace that
// is a vulnerability class, not a convenience.
//
// Consequences of the raw-byte approach, all intentional:
//
//   - Percent-encoding is rejected outright ('%' is not in the permitted
//     charset). There is exactly one textual form for any given identity.
//   - "." and ".." segments are rejected rather than resolved.
//   - Userinfo, port, query and fragment are rejected as a side effect of
//     charset validation, since '@', ':', '?' and '#' are not permitted.
//   - String comparison of two parsed IDs is equivalent to semantic comparison,
//     so ID is a comparable value type safe to use as a map key.
//
// # Zero values
//
// The zero TrustDomain and the zero ID are invalid sentinels, never "any" and
// never "unknown-but-acceptable". Call IsZero before trusting a value that did
// not come from a constructor in this package.
package spiffeid

import "errors"

// Specification limits. These are the values mandated by the SPIFFE ID
// specification, not Qredin inventions, and they double as a cheap bound on
// attacker-controlled input reaching the parser.
const (
	// MaxIDLength is the maximum length in bytes of a complete SPIFFE ID.
	MaxIDLength = 2048

	// MaxTrustDomainLength is the maximum length in bytes of a trust domain name.
	MaxTrustDomainLength = 255

	// scheme and schemePrefix are matched case-sensitively. See the
	// "Deliberate strictness" note below.
	scheme       = "spiffe"
	schemePrefix = scheme + "://"
)

// Parse errors. These are sentinels: compare with errors.Is, never by string.
//
// Errors are deliberately coarse. They describe the class of violation, not the
// offending byte or its offset, because these values reach logs and API
// responses and we do not want to build an oracle that helps an attacker
// iterate towards a well-formed ID for a trust domain they cannot see.
var (
	// ErrEmpty is returned when the input string is empty.
	ErrEmpty = errors.New("spiffeid: empty")

	// ErrWrongScheme is returned when the ID does not begin with "spiffe://".
	ErrWrongScheme = errors.New("spiffeid: scheme must be \"spiffe://\"")

	// ErrIDTooLong is returned when the ID exceeds MaxIDLength bytes.
	ErrIDTooLong = errors.New("spiffeid: exceeds maximum length")

	// ErrMissingTrustDomain is returned when the authority component is empty.
	ErrMissingTrustDomain = errors.New("spiffeid: missing trust domain")

	// ErrTrustDomainTooLong is returned when the trust domain name exceeds
	// MaxTrustDomainLength bytes.
	ErrTrustDomainTooLong = errors.New("spiffeid: trust domain exceeds maximum length")

	// ErrBadTrustDomainChar is returned when the trust domain contains a
	// character outside [a-z0-9.\-_]. Uppercase input lands here.
	ErrBadTrustDomainChar = errors.New("spiffeid: trust domain contains an invalid character")

	// ErrNoLeadingSlash is returned when a non-empty path does not begin with '/'.
	ErrNoLeadingSlash = errors.New("spiffeid: path must begin with \"/\"")

	// ErrTrailingSlash is returned when a path ends with '/'.
	ErrTrailingSlash = errors.New("spiffeid: path must not end with \"/\"")

	// ErrEmptySegment is returned for a zero-length path segment, e.g. "//".
	ErrEmptySegment = errors.New("spiffeid: path contains an empty segment")

	// ErrDotSegment is returned for a "." or ".." path segment. These are
	// rejected rather than resolved.
	ErrDotSegment = errors.New("spiffeid: path contains a relative modifier segment")

	// ErrBadPathSegmentChar is returned when a path segment contains a
	// character outside [a-zA-Z0-9.\-_]. Percent-encoding lands here.
	ErrBadPathSegmentChar = errors.New("spiffeid: path contains an invalid character")

	// ErrEmptyPath is returned when a workload identity is required but the ID
	// has no path (i.e. it names a trust domain, not a workload).
	ErrEmptyPath = errors.New("spiffeid: missing workload path")
)

// isValidTrustDomainChar reports whether c is permitted in a trust domain name.
//
// Lowercase only: the specification defines trust domain names as lowercase and
// we do not case-fold. Case-folding would mean "Example.org" and "example.org"
// resolve to the same authority, which is a second textual form for one
// identity and therefore an aliasing risk.
func isValidTrustDomainChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_':
		return true
	default:
		return false
	}
}

// isValidPathSegmentChar reports whether c is permitted in a path segment.
// Unlike trust domains, path segments are case-sensitive and permit uppercase.
func isValidPathSegmentChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_':
		return true
	default:
		return false
	}
}

// ValidatePath reports whether path is a valid SPIFFE ID path component.
//
// The empty string is valid and denotes an ID that names a trust domain rather
// than a workload. That form is legitimate for CA/signing certificates but must
// never be accepted for a leaf SVID; see pkg/x509svid, which enforces the
// distinction rather than leaving it to callers.
func ValidatePath(path string) error {
	if path == "" {
		return nil
	}
	if path[0] != '/' {
		return ErrNoLeadingSlash
	}
	if len(path) > 1 && path[len(path)-1] == '/' {
		return ErrTrailingSlash
	}

	// segmentStart is the index of the '/' introducing the current segment.
	// path[0] is known to be '/', so scanning starts at 1.
	segmentStart := 0
	for i := 1; i < len(path); i++ {
		c := path[i]
		if c == '/' {
			if err := checkSegment(path[segmentStart+1 : i]); err != nil {
				return err
			}
			segmentStart = i
			continue
		}
		if !isValidPathSegmentChar(c) {
			return ErrBadPathSegmentChar
		}
	}
	return checkSegment(path[segmentStart+1:])
}

func checkSegment(seg string) error {
	switch seg {
	case "":
		return ErrEmptySegment
	case ".", "..":
		return ErrDotSegment
	}
	return nil
}

// validateTrustDomainName validates a bare trust domain name (no scheme).
func validateTrustDomainName(name string) error {
	switch {
	case name == "":
		return ErrMissingTrustDomain
	case len(name) > MaxTrustDomainLength:
		return ErrTrustDomainTooLong
	}
	for i := 0; i < len(name); i++ {
		if !isValidTrustDomainChar(name[i]) {
			return ErrBadTrustDomainChar
		}
	}
	return nil
}
