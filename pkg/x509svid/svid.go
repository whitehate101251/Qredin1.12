package x509svid

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// PEM block types used for SVID material.
const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypePrivateKey  = "PRIVATE KEY" // PKCS#8, as the Workload API uses
)

// SVID is an X.509-SVID: a certificate chain that carries a SPIFFE ID, together
// with the private key that proves possession of it.
//
// The ID field is derived from the leaf certificate during parsing and is never
// set from a caller-supplied value. That is the rule from plan §5: an identity
// is something a credential proves, not something its holder declares.
type SVID struct {
	// ID is the SPIFFE ID carried by the leaf certificate's URI SAN.
	ID spiffeid.ID

	// Certificates is the chain, leaf first. Intermediates follow; the root is
	// not included, because a verifier takes roots from the trust bundle and a
	// root arriving in the chain confers nothing.
	Certificates []*x509.Certificate

	// PrivateKey is the leaf's private key.
	//
	// Typed as crypto.Signer rather than a concrete key so that a key living in
	// a KMS or an HSM — which can sign but cannot be exported — is usable here
	// without a parallel code path.
	PrivateKey crypto.Signer

	// Hint is the optional operator-supplied label from the Workload API,
	// letting a workload holding several SVIDs choose between them.
	//
	// It is metadata for the workload's own use. It is never an input to
	// authentication or authorization, and nothing in Qredin makes a decision
	// based on it.
	Hint string
}

// New constructs an SVID from an already parsed leaf-first chain and signer.
// It is the non-exporting-key counterpart to ParseRaw: issuers backed by a
// KMS or HSM can provide signing capability without serializing a private key.
func New(certs []*x509.Certificate, signer crypto.Signer) (*SVID, error) {
	if signer == nil {
		return nil, errors.New("x509svid: a private key signer is required")
	}
	return newSVID(certs, signer)
}

// Leaf returns the leaf certificate.
func (s *SVID) Leaf() *x509.Certificate {
	if len(s.Certificates) == 0 {
		return nil
	}
	return s.Certificates[0]
}

// ParseRaw builds an SVID from DER: a concatenated certificate chain, leaf
// first, and a PKCS#8 private key. This is the Workload API's wire encoding.
func ParseRaw(certChainDER, keyDER []byte) (*SVID, error) {
	certs, err := x509.ParseCertificates(certChainDER)
	if err != nil {
		return nil, fmt.Errorf("x509svid: parsing certificate chain: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("x509svid: parsing private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("x509svid: private key of type %T cannot sign", key)
	}
	return newSVID(certs, signer)
}

// Parse builds an SVID from PEM-encoded material. Additional PEM blocks of
// other types are ignored, so a bundle-bearing file does not break parsing.
func Parse(certChainPEM, keyPEM []byte) (*SVID, error) {
	var certs []*x509.Certificate
	rest := certChainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509svid: parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, newError(ReasonEmptyChain, "no CERTIFICATE blocks found")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("x509svid: no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509svid: parsing private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("x509svid: private key of type %T cannot sign", key)
	}
	return newSVID(certs, signer)
}

// newSVID performs the checks that must hold for any SVID regardless of where
// it came from.
//
// Deliberately not a full profile check. An SVID is verified by a Verifier
// against a trust bundle; duplicating that here would mean a workload could not
// even load its own credential during an incident in which the profile was
// relaxed. What is checked here is the pair of invariants that make the struct
// meaningful at all: the leaf names a workload, and the private key is the one
// the certificate attests to.
func newSVID(certs []*x509.Certificate, signer crypto.Signer) (*SVID, error) {
	// x509.ParseCertificates returns an empty slice and no error for empty
	// input, so this guard is load-bearing rather than defensive: without it,
	// ParseRaw("", validKey) indexes into an empty slice and panics. A malformed
	// Workload API response must not be able to crash the process holding the
	// credential.
	if len(certs) == 0 {
		return nil, newError(ReasonEmptyChain, "no certificates in the SVID")
	}

	id, err := IDFromCert(certs[0])
	if err != nil {
		return nil, err
	}
	if !id.IsWorkload() {
		return nil, newError(ReasonNoWorkloadPath,
			"leaf SVID must name a workload, but its SPIFFE ID has no path")
	}

	// A mismatched key is a credential that authenticates as an identity its
	// holder cannot actually use. Caught here, it is a startup error; caught
	// later, it is a TLS handshake failure with no useful diagnostic.
	if err := checkKeyMatchesCert(signer, certs[0]); err != nil {
		return nil, err
	}

	return &SVID{ID: id, Certificates: certs, PrivateKey: signer}, nil
}

func checkKeyMatchesCert(signer crypto.Signer, cert *x509.Certificate) error {
	pub := signer.Public()
	type equaler interface{ Equal(crypto.PublicKey) bool }
	eq, ok := pub.(equaler)
	if !ok {
		return fmt.Errorf("x509svid: cannot compare public key of type %T with the certificate", pub)
	}
	if !eq.Equal(cert.PublicKey) {
		return errors.New("x509svid: private key does not match the leaf certificate")
	}
	return nil
}

// MarshalRaw returns the chain as concatenated DER and the private key as
// PKCS#8 DER.
//
// Returns an error for a key that cannot be exported, such as one held in a
// KMS. That is the correct outcome: the alternative is silently writing out a
// placeholder that looks like a key.
func (s *SVID) MarshalRaw() (certChainDER, keyDER []byte, err error) {
	if len(s.Certificates) == 0 {
		return nil, nil, newError(ReasonEmptyChain, "SVID has no certificates")
	}
	for _, cert := range s.Certificates {
		certChainDER = append(certChainDER, cert.Raw...)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("x509svid: marshalling private key: %w", err)
	}
	return certChainDER, keyDER, nil
}

// Marshal returns the chain and private key as PEM.
func (s *SVID) Marshal() (certChainPEM, keyPEM []byte, err error) {
	if len(s.Certificates) == 0 {
		return nil, nil, newError(ReasonEmptyChain, "SVID has no certificates")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("x509svid: marshalling private key: %w", err)
	}
	for _, cert := range s.Certificates {
		certChainPEM = append(certChainPEM,
			pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: cert.Raw})...)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: keyDER})
	return certChainPEM, keyPEM, nil
}

// TLSCertificate returns the SVID as a crypto/tls certificate.
//
// Leaf is populated so that crypto/tls does not re-parse the DER on every
// handshake, and so that a caller inspecting the returned value sees the same
// certificate this SVID was built from.
func (s *SVID) TLSCertificate() tls.Certificate {
	out := tls.Certificate{PrivateKey: s.PrivateKey, Leaf: s.Leaf()}
	for _, cert := range s.Certificates {
		out.Certificate = append(out.Certificate, cert.Raw)
	}
	return out
}
