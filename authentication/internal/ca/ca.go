// Package ca implements Qredin's X.509-SVID issuing authority.
package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/qredin/qredin/authentication/internal/keymanager"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

const defaultAlgorithm = "ECDSA_P256"

// Authority is a signing authority whose private key remains owned by the
// configured KeyManager.
type Authority struct {
	trustDomain spiffeid.TrustDomain
	certificate *x509.Certificate
	keyID       string
	manager     keymanager.Manager
}

// NewSelfSigned creates a root authority. The certificate is returned as
// public material; the signing key is accessed only through Manager.
func NewSelfSigned(ctx context.Context, manager keymanager.Manager, td spiffeid.TrustDomain, ttl time.Duration) (*Authority, error) {
	if manager == nil {
		return nil, errors.New("ca: key manager is required")
	}
	if td.IsZero() {
		return nil, errors.New("ca: trust domain is required")
	}
	if ttl <= 0 {
		return nil, errors.New("ca: authority TTL must be positive")
	}
	key, err := manager.Generate(ctx, keymanager.KeySpec{Algorithm: defaultAlgorithm})
	if err != nil {
		return nil, fmt.Errorf("ca: generating authority key: %w", err)
	}
	signer, err := manager.Signer(ctx, key.ID)
	if err != nil {
		return nil, fmt.Errorf("ca: resolving authority signer: %w", err)
	}
	now := time.Now()
	serial, err := serialNumber()
	if err != nil {
		return nil, fmt.Errorf("ca: generating authority serial: %w", err)
	}
	uri, err := spiffeURL(td.IDString())
	if err != nil {
		return nil, fmt.Errorf("ca: building authority identity: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: td.IDString()},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public, signer)
	if err != nil {
		return nil, fmt.Errorf("ca: creating authority certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing authority certificate: %w", err)
	}
	return &Authority{trustDomain: td, certificate: certificate, keyID: key.ID, manager: manager}, nil
}

// Certificate returns the public authority certificate.
func (a *Authority) Certificate() *x509.Certificate { return a.certificate }

// TrustDomain returns the authority's immutable trust domain.
func (a *Authority) TrustDomain() spiffeid.TrustDomain { return a.trustDomain }

// IssueSVID creates a workload certificate and keeps its private key behind
// the KeyManager. The returned SVID is ready for TLS use without key export.
func (a *Authority) IssueSVID(ctx context.Context, id spiffeid.ID, ttl time.Duration) (*x509svid.SVID, error) {
	if !id.IsWorkload() || !id.MemberOf(a.trustDomain) {
		return nil, errors.New("ca: workload ID must be a workload in the authority trust domain")
	}
	if ttl <= 0 {
		return nil, errors.New("ca: SVID TTL must be positive")
	}
	key, err := a.manager.Generate(ctx, keymanager.KeySpec{Algorithm: defaultAlgorithm})
	if err != nil {
		return nil, fmt.Errorf("ca: generating SVID key: %w", err)
	}
	leafSigner, err := a.manager.Signer(ctx, key.ID)
	if err != nil {
		return nil, fmt.Errorf("ca: resolving SVID signer: %w", err)
	}
	authoritySigner, err := a.manager.Signer(ctx, a.keyID)
	if err != nil {
		return nil, fmt.Errorf("ca: resolving authority signer: %w", err)
	}
	now := time.Now()
	serial, err := serialNumber()
	if err != nil {
		return nil, fmt.Errorf("ca: generating SVID serial: %w", err)
	}
	uri, err := spiffeURL(id.String())
	if err != nil {
		return nil, fmt.Errorf("ca: building SVID identity: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.String()},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, key.Public, authoritySigner)
	if err != nil {
		return nil, fmt.Errorf("ca: creating SVID certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing SVID certificate: %w", err)
	}
	return x509svid.New([]*x509.Certificate{leaf}, leafSigner)
}

// MarshalCertificatePEM returns public authority material for bundle
// publication. It never serializes a signing key.
func (a *Authority) MarshalCertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.certificate.Raw})
}

func serialNumber() (*big.Int, error) {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return value, nil
}

func spiffeURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	return u, nil
}
