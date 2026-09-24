package server

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/qredin/qredin/internal/ca"
	"github.com/qredin/qredin/internal/registration"
	"github.com/qredin/qredin/internal/store"
	"github.com/qredin/qredin/internal/workloadapi"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

// Resolver resolves a workload's credential state from registrations and the CA.
type Resolver struct {
	trustDomain spiffeid.TrustDomain
	store       *store.RegistrationService
	authority   *ca.Authority
}

// NewResolver creates a resolver that serves credentials for a trust domain.
func NewResolver(td spiffeid.TrustDomain, store *store.RegistrationService, authority *ca.Authority) *Resolver {
	return &Resolver{
		trustDomain: td,
		store:       store,
		authority:   authority,
	}
}

// Resolve returns the complete credential snapshot for a workload identity.
func (r *Resolver) Resolve(id spiffeid.ID) (*workloadapi.Snapshot, error) {
	if id.IsZero() || !id.MemberOf(r.trustDomain) {
		return nil, errors.New("server: workload identity is outside the trust domain")
	}

	entry, _, err := r.store.Get(context.Background(), id.String())
	if err != nil {
		return nil, err
	}
	if entry.Status != registration.StatusActive {
		return nil, errors.New("server: registration is not active")
	}
	if !entry.WorkloadID.IsWorkload() || !entry.WorkloadID.MemberOf(entry.TrustDomain) {
		return nil, errors.New("server: registration workload is invalid")
	}

	return r.issueSnapshot(context.Background(), entry)
}

// issueSnapshot issues a complete snapshot for a registration entry.
func (r *Resolver) issueSnapshot(ctx context.Context, entry registration.Entry) (*workloadapi.Snapshot, error) {
	svid, err := r.authority.IssueSVID(ctx, entry.WorkloadID, time.Hour)
	if err != nil {
		return nil, err
	}

	b := bundle.FromX509Authorities(entry.TrustDomain, []*x509.Certificate{r.authority.Certificate()})

	return &workloadapi.Snapshot{
		SVIDs:   []*x509svid.SVID{svid},
		Bundles: bundle.NewSet(b),
	}, nil
}

// Bundle returns the trust bundle for a trust domain.
func (r *Resolver) Bundle(td spiffeid.TrustDomain) (*bundle.Bundle, error) {
	if td != r.trustDomain {
		return nil, errors.New("server: trust domain mismatch")
	}
	return bundle.FromX509Authorities(td, []*x509.Certificate{r.authority.Certificate()}), nil
}

// Get returns a registration entry and its revision.
func (r *Resolver) Get(ctx context.Context, id string) (registration.Entry, int64, error) {
	return r.store.Get(ctx, id)
}

// Ensure compile-time conformance to the workloadapi.Resolver interface.
var _ workloadapi.Resolver = (*Resolver)(nil)
