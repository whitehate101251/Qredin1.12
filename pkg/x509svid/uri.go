package x509svid

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// oidSubjectAltName is id-ce-subjectAltName (RFC 5280 §4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// asn1TagURI is the context-specific tag for the uniformResourceIdentifier
// alternative of GeneralName (RFC 5280 §4.2.1.6):
//
//	GeneralName ::= CHOICE {
//	    ...
//	    uniformResourceIdentifier  [6] IA5String,
//	    ...
//	}
const asn1TagURI = 6

// URISANs returns the raw uniformResourceIdentifier entries of the certificate's
// subjectAltName extension, exactly as they appear in the DER.
//
// # Why not cert.URIs
//
// crypto/x509 parses URI SANs with net/url, which percent-decodes and
// normalises. That is the right behaviour for a URL and the wrong behaviour for
// an identity: two byte sequences that net/url considers equivalent are two
// different SPIFFE IDs, and reading identity from a normalised view means
// validating one string while the peer's certificate contains another.
//
// pkg/spiffeid refuses to use net/url for the same reason. Reading the SAN back
// out of cert.URIs would reintroduce the problem one layer down, so this
// function goes to the DER instead and hands pkg/spiffeid the original bytes.
//
// A certificate that carries more than one subjectAltName extension is
// rejected: RFC 5280 permits each extension at most once, and a duplicate is a
// way of showing one identity to a parser that takes the first and another to a
// parser that takes the last.
func URISANs(cert *x509.Certificate) ([]string, error) {
	var raw []byte
	found := false
	for _, e := range cert.Extensions {
		if !e.Id.Equal(oidSubjectAltName) {
			continue
		}
		if found {
			return nil, errors.New("certificate carries more than one subjectAltName extension")
		}
		raw, found = e.Value, true
	}
	if !found {
		return nil, nil
	}

	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil {
		return nil, fmt.Errorf("parsing subjectAltName: %w", err)
	}
	if len(rest) != 0 {
		// Trailing bytes after a complete DER value are how the same extension
		// is made to mean different things to different parsers.
		return nil, errors.New("trailing data after subjectAltName")
	}
	if !seq.IsCompound || seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		return nil, errors.New("subjectAltName is not a SEQUENCE")
	}

	var uris []string
	remaining := seq.Bytes
	for len(remaining) > 0 {
		var name asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &name)
		if err != nil {
			return nil, fmt.Errorf("parsing GeneralName: %w", err)
		}
		if name.Class != asn1.ClassContextSpecific || name.Tag != asn1TagURI {
			continue // some other GeneralName; DNS and IP SANs are permitted
		}
		if name.IsCompound {
			return nil, errors.New("uniformResourceIdentifier must be a primitive IA5String")
		}
		for _, b := range name.Bytes {
			// IA5String is by definition 7-bit. Rejecting the high bit here
			// means pkg/spiffeid never sees a multi-byte sequence that could be
			// decoded as a permitted character by some other implementation.
			if b > 0x7F {
				return nil, errors.New("uniformResourceIdentifier contains a non-IA5 byte")
			}
		}
		uris = append(uris, string(name.Bytes))
	}
	return uris, nil
}

// IDFromCert extracts the SPIFFE ID from a certificate's URI SAN.
//
// Exactly one URI SAN is required. The SPIFFE X.509-SVID specification is
// explicit that an SVID has a single SPIFFE ID; a certificate bearing two would
// authenticate as either, and which one a peer used would depend on that peer's
// parser. DNS and IP SANs are unaffected and may appear alongside.
//
// This performs no validity, chain, or trust-domain checks. It answers only
// "what identity does this certificate claim", which is the question the
// verifier must answer first in order to know which bundle to validate against.
func IDFromCert(cert *x509.Certificate) (spiffeid.ID, error) {
	uris, err := URISANs(cert)
	if err != nil {
		return spiffeid.ID{}, &Error{Reason: ReasonMalformedSAN, err: err}
	}
	switch len(uris) {
	case 1:
	case 0:
		return spiffeid.ID{}, &Error{Reason: ReasonNoURISAN,
			err: errors.New("certificate has no URI SAN")}
	default:
		return spiffeid.ID{}, &Error{Reason: ReasonMultipleURISANs,
			err: fmt.Errorf("certificate has %d URI SANs, exactly one is required", len(uris))}
	}

	id, err := spiffeid.FromString(uris[0])
	if err != nil {
		return spiffeid.ID{}, &Error{Reason: ReasonBadSPIFFEID,
			err: fmt.Errorf("URI SAN %q is not a valid SPIFFE ID: %w", uris[0], err)}
	}
	return id, nil
}
