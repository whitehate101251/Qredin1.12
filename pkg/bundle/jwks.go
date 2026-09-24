package bundle

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// SPIFFE bundle document key uses, per the SPIFFE Trust Domain and Bundle
// specification.
const (
	useX509SVID = "x509-svid"
	useJWTSVID  = "jwt-svid"
)

// minRSABits is the smallest RSA modulus Qredin will accept in a bundle.
//
// The SPIFFE specification does not set a floor. 2048 is the current public
// baseline (NIST SP 800-57, CA/Browser Forum); accepting less would let a
// bundle publish a key that is cheaper to factor than to attack any other part
// of the system. Rejecting at parse time means a weak key can never enter a
// bundle in memory, rather than being caught at each use.
const minRSABits = 2048

// maxRefreshHintSeconds bounds the refresh hint Qredin will accept from a
// bundle document.
//
// The SPIFFE specification sets no upper bound, but the hint comes from a
// federated peer, and time.Duration is a nanosecond int64: a hint of 2^63
// seconds silently overflows to a *negative* duration, which a naive refresher
// would treat as "already due" and spin on. Bounding at parse time removes the
// overflow entirely and also caps how long a peer can ask us to go without
// noticing that it revoked a key — thirty days is already far beyond any
// defensible rotation interval.
//
// The lower bound is deliberately not applied here. A hint of zero is a valid
// statement ("refresh as often as you like"); clamping it to a sane minimum is
// a rate-limiting decision that belongs to the fetcher, which knows the
// endpoint and the budget.
const maxRefreshHintSeconds = 30 * 24 * 60 * 60

// Parse errors.
var (
	// ErrMalformedBundle indicates the document is not a valid SPIFFE bundle.
	ErrMalformedBundle = errors.New("bundle: malformed bundle document")

	// ErrDuplicateKeyID indicates two JWT authorities share a key ID. The
	// specification requires rejection: with a duplicate kid, which key
	// verifies a token becomes order-dependent.
	ErrDuplicateKeyID = errors.New("bundle: duplicate JWT key ID")

	// ErrUnsupportedKeyType indicates a key type this implementation does not
	// support.
	ErrUnsupportedKeyType = errors.New("bundle: unsupported key type")
)

// jwksDocument is the on-the-wire SPIFFE bundle: an RFC 7517 JWK Set with two
// SPIFFE-specific members.
//
// Pointer fields distinguish "absent" from "zero". That matters: a refresh hint
// of 0 means "refresh as often as you can" while an absent hint means "the
// publisher has no opinion, use your default". Collapsing the two would silently
// turn every bundle without a hint into a hot loop against the endpoint.
type jwksDocument struct {
	Sequence    *uint64 `json:"spiffe_sequence,omitempty"`
	RefreshHint *int64  `json:"spiffe_refresh_hint,omitempty"`
	Keys        []jwk   `json:"keys"`
}

// jwk is a single JSON Web Key. Only the members SPIFFE bundles use are
// modelled; unknown members are ignored by encoding/json, which is what
// forward compatibility requires.
type jwk struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Use string   `json:"use,omitempty"`
	Kid string   `json:"kid,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

// Parse decodes a SPIFFE bundle document for the given trust domain.
//
// The trust domain is supplied by the caller rather than read from the
// document, because a SPIFFE bundle document does not name its own trust
// domain. Authority comes from where the bundle was fetched from and which
// federation relationship it satisfies — both operator configuration. A
// document cannot assert which trust domain it speaks for; if it could, a
// compromised endpoint could reassign itself.
func Parse(td spiffeid.TrustDomain, doc []byte) (*Bundle, error) {
	if td.IsZero() {
		return nil, ErrNoTrustDomain
	}

	var parsed jwksDocument
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedBundle, err)
	}

	b := New(td)
	if parsed.Sequence != nil {
		b.sequence, b.sequenceSet = *parsed.Sequence, true
	}
	if parsed.RefreshHint != nil {
		if *parsed.RefreshHint < 0 {
			return nil, fmt.Errorf("%w: negative spiffe_refresh_hint", ErrMalformedBundle)
		}
		if *parsed.RefreshHint > maxRefreshHintSeconds {
			return nil, fmt.Errorf("%w: spiffe_refresh_hint of %ds exceeds the maximum of %ds",
				ErrMalformedBundle, *parsed.RefreshHint, maxRefreshHintSeconds)
		}
		b.refreshHint, b.refreshHintSet = time.Duration(*parsed.RefreshHint)*time.Second, true
	}

	for i, key := range parsed.Keys {
		switch key.Use {
		case useX509SVID:
			cert, err := parseX509Authority(key)
			if err != nil {
				return nil, fmt.Errorf("%w: key %d: %v", ErrMalformedBundle, i, err)
			}
			b.x509Authorities = append(b.x509Authorities, cert)

		case useJWTSVID:
			if key.Kid == "" {
				return nil, fmt.Errorf("%w: key %d: jwt-svid entry requires a kid", ErrMalformedBundle, i)
			}
			if _, dup := b.jwtAuthorities[key.Kid]; dup {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateKeyID, key.Kid)
			}
			pub, err := jwkToPublicKey(key)
			if err != nil {
				return nil, fmt.Errorf("%w: key %d (kid %q): %v", ErrMalformedBundle, i, key.Kid, err)
			}
			b.jwtAuthorities[key.Kid] = pub

		case "":
			// "use" is mandatory in a SPIFFE bundle. Without it we cannot tell
			// whether a key signs X.509-SVIDs or JWT-SVIDs, and guessing would
			// let a key be used for a purpose its publisher did not intend.
			return nil, fmt.Errorf("%w: key %d: missing \"use\"", ErrMalformedBundle, i)

		default:
			// Unrecognised uses are skipped rather than rejected, so that a
			// publisher can introduce a new key type without breaking older
			// consumers mid-rotation. See docs/assumptions.md A-02.
			continue
		}
	}

	return b, nil
}

// parseX509Authority extracts the certificate from an x509-svid JWK entry.
func parseX509Authority(key jwk) (*x509.Certificate, error) {
	// Exactly one certificate. The SPIFFE profile puts one authority per JWK
	// entry; a multi-element x5c would be an RFC 7517 chain, and silently
	// taking element zero of a chain someone else assembled means trusting
	// whatever they put first.
	if len(key.X5c) != 1 {
		return nil, fmt.Errorf("x509-svid entry must contain exactly one x5c element, got %d", len(key.X5c))
	}
	// kid is meaningless for X.509 authorities — certificates are selected by
	// subject and signature during chain building, not by key ID. Its presence
	// signals a producer that has conflated the two key types.
	if key.Kid != "" {
		return nil, errors.New("x509-svid entry must not set kid")
	}

	der, err := base64.StdEncoding.DecodeString(key.X5c[0])
	if err != nil {
		return nil, fmt.Errorf("decoding x5c: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing x5c certificate: %w", err)
	}

	// crypto/x509 tolerates certificates whose public key algorithm it does not
	// recognise: parsing succeeds and cert.PublicKey is left nil. Such an
	// authority can never verify a signature, but it would appear in the bundle
	// and in operator tooling as though it were trusted. Reject it here so that
	// "present in the bundle" always means "usable as an authority".
	//
	// Routing the check through publicKeyToJWK also guarantees that anything we
	// accept can be re-published: a bundle we can ingest but not marshal would
	// break the federation mirror path.
	if _, err := publicKeyToJWK(cert.PublicKey); err != nil {
		return nil, fmt.Errorf("unusable x509-svid authority: %w", err)
	}

	// Note: CA=true is deliberately not required here. Whether a certificate may
	// sign is decided during chain verification by the signing-certificate
	// profile in pkg/x509svid, which is the layer that can fail closed on it.
	// Enforcing it at parse time would make Qredin reject documents a conforming
	// publisher may legitimately produce, which ADR 0002 rules out.

	// If the entry also carries JWK key parameters, they must describe the
	// certificate's key. A mismatch means the document is internally
	// inconsistent and we cannot tell which the publisher meant, so we reject
	// rather than pick. See docs/assumptions.md A-03.
	if key.Kty != "" {
		advertised, err := jwkToPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("x509-svid key parameters: %w", err)
		}
		if !publicKeysEqual(advertised, cert.PublicKey) {
			return nil, errors.New("x509-svid key parameters do not match the x5c certificate")
		}
	}
	return cert, nil
}

// Marshal encodes the bundle as a SPIFFE bundle document.
//
// Output is deterministic: X.509 authorities keep insertion order and JWT
// authorities are sorted by key ID. Determinism is what makes the bundle
// digest usable as a change signal — a byte-identical bundle must serialise
// identically, or every publication looks like a rotation.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	doc := jwksDocument{Keys: make([]jwk, 0, len(b.x509Authorities)+len(b.jwtAuthorities))}

	if b.sequenceSet {
		seq := b.sequence
		doc.Sequence = &seq
	}
	if b.refreshHintSet {
		hint := int64(b.refreshHint / time.Second)
		if hint < 0 || hint > maxRefreshHintSeconds {
			// Publishing a document our own parser would reject is a bug worth
			// surfacing at the publish path, which has error handling, rather
			// than at every consumer that later fetches the bundle.
			return nil, fmt.Errorf("bundle: refresh hint %v is outside the publishable range (0..%ds)",
				b.refreshHint, maxRefreshHintSeconds)
		}
		doc.RefreshHint = &hint
	}

	for _, cert := range b.x509Authorities {
		key, err := publicKeyToJWK(cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("bundle: encoding X.509 authority %q: %w", cert.Subject, err)
		}
		key.Use = useX509SVID
		key.X5c = []string{base64.StdEncoding.EncodeToString(cert.Raw)}
		doc.Keys = append(doc.Keys, key)
	}

	kids := make([]string, 0, len(b.jwtAuthorities))
	for kid := range b.jwtAuthorities {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		key, err := publicKeyToJWK(b.jwtAuthorities[kid])
		if err != nil {
			return nil, fmt.Errorf("bundle: encoding JWT authority %q: %w", kid, err)
		}
		key.Use = useJWTSVID
		key.Kid = kid
		doc.Keys = append(doc.Keys, key)
	}

	return json.Marshal(doc)
}

// ecCurve associates a JWK curve name with everything needed to decode and
// validate a point on it.
type ecCurve struct {
	name  string
	curve elliptic.Curve
	ecdh  ecdh.Curve
	size  int // fixed coordinate length in bytes, per RFC 7518 §6.2.1.2
}

var ecCurves = []ecCurve{
	{"P-256", elliptic.P256(), ecdh.P256(), 32},
	{"P-384", elliptic.P384(), ecdh.P384(), 48},
	{"P-521", elliptic.P521(), ecdh.P521(), 66},
}

func ecCurveByName(name string) (ecCurve, bool) {
	for _, c := range ecCurves {
		if c.name == name {
			return c, true
		}
	}
	return ecCurve{}, false
}

func ecCurveByCurve(curve elliptic.Curve) (ecCurve, bool) {
	for _, c := range ecCurves {
		if c.curve == curve {
			return c, true
		}
	}
	return ecCurve{}, false
}

// jwkToPublicKey decodes the key parameters of a JWK into a public key.
func jwkToPublicKey(key jwk) (crypto.PublicKey, error) {
	switch key.Kty {
	case "EC":
		c, ok := ecCurveByName(key.Crv)
		if !ok {
			return nil, fmt.Errorf("%w: EC curve %q", ErrUnsupportedKeyType, key.Crv)
		}
		x, err := decodeFixedLengthB64(key.X, c.size, "x")
		if err != nil {
			return nil, err
		}
		y, err := decodeFixedLengthB64(key.Y, c.size, "y")
		if err != nil {
			return nil, err
		}

		// Validate that (x, y) is actually on the curve. crypto/ecdh's
		// NewPublicKey performs full point validation and rejects the point at
		// infinity; an unvalidated point can enable invalid-curve attacks
		// against code that later does arithmetic with it.
		point := make([]byte, 0, 1+2*c.size)
		point = append(point, 4) // uncompressed point indicator
		point = append(point, x...)
		point = append(point, y...)
		if _, err := c.ecdh.NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("invalid EC point: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: c.curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil

	case "RSA":
		nBytes, err := decodeB64(key.N, "n")
		if err != nil {
			return nil, err
		}
		eBytes, err := decodeB64(key.E, "e")
		if err != nil {
			return nil, err
		}
		if len(nBytes) == 0 || nBytes[0] == 0 {
			// RFC 7518 requires the minimal big-endian representation. A
			// leading zero byte gives one modulus two encodings, which would
			// let the same key appear under two distinct thumbprints.
			return nil, errors.New("RSA modulus must not have a leading zero byte")
		}
		if len(eBytes) == 0 || len(eBytes) > 8 || eBytes[0] == 0 {
			return nil, errors.New("invalid RSA exponent encoding")
		}

		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 {
			return nil, fmt.Errorf("invalid RSA public exponent %s", e)
		}
		if n.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA modulus is %d bits, minimum is %d", n.BitLen(), minRSABits)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "OKP":
		if key.Crv != "Ed25519" {
			return nil, fmt.Errorf("%w: OKP curve %q", ErrUnsupportedKeyType, key.Crv)
		}
		x, err := decodeFixedLengthB64(key.X, ed25519.PublicKeySize, "x")
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil

	case "":
		return nil, errors.New("missing kty")

	default:
		return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedKeyType, key.Kty)
	}
}

// publicKeyToJWK encodes a public key's parameters as a JWK.
func publicKeyToJWK(pub crypto.PublicKey) (jwk, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		c, ok := ecCurveByCurve(k.Curve)
		if !ok {
			return jwk{}, fmt.Errorf("%w: EC curve %v", ErrUnsupportedKeyType, k.Curve)
		}
		return jwk{
			Kty: "EC",
			Crv: c.name,
			X:   encodeFixedLengthB64(k.X, c.size),
			Y:   encodeFixedLengthB64(k.Y, c.size),
		}, nil

	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return jwk{}, fmt.Errorf("RSA modulus is %d bits, minimum is %d", k.N.BitLen(), minRSABits)
		}
		return jwk{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil

	case ed25519.PublicKey:
		return jwk{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k),
		}, nil

	default:
		return jwk{}, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, pub)
	}
}

func decodeB64(s, field string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("missing %q", field)
	}
	// RawURLEncoding: RFC 7515 base64url with padding stripped. Accepting
	// padded input as well would give one key two encodings.
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding %q: %w", field, err)
	}
	return b, nil
}

// decodeFixedLengthB64 decodes a base64url value that RFC 7518 requires to be
// a fixed number of octets, zero-padded on the left.
//
// The length check is not pedantry. Accepting a short value and left-padding it
// ourselves would mean the same key could be written several ways, so a key
// could appear twice in a bundle under different encodings, or a cache keyed on
// the encoded form could be made to miss.
func decodeFixedLengthB64(s string, size int, field string) ([]byte, error) {
	b, err := decodeB64(s, field)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("%q must be exactly %d bytes, got %d", field, size, len(b))
	}
	return b, nil
}

// encodeFixedLengthB64 encodes a coordinate as a fixed-length, left-zero-padded
// base64url string.
func encodeFixedLengthB64(v *big.Int, size int) string {
	buf := make([]byte, size)
	v.FillBytes(buf) // left-pads with zeroes; panics only if v overflows size
	return base64.RawURLEncoding.EncodeToString(buf)
}
