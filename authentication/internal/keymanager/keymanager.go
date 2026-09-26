// Package keymanager defines the signing boundary used by Qredin authorities.
//
// Implementations return signer capabilities, never private-key bytes. This
// keeps certificate issuance usable with KMS and HSM-backed keys without
// creating a second issuance path for non-exportable keys.
package keymanager

import (
	"context"
	"crypto"
	"errors"
)

// Environment identifies the deployment safety boundary for a key manager.
type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

// ErrNotProductionSafe is returned when a manager that is only suitable for
// development or tests is selected for production.
var ErrNotProductionSafe = errors.New("keymanager: implementation is not production safe")

// KeySpec describes a key to create. Implementations may support additional
// algorithms, but P-256 is the portable default for Qredin authorities.
type KeySpec struct {
	Algorithm string
}

// Key is the non-secret result of key creation.
type Key struct {
	ID     string
	Public crypto.PublicKey
}

// Manager creates and resolves signing capabilities without exporting keys.
type Manager interface {
	Open(ctx context.Context, environment Environment) error
	Generate(ctx context.Context, spec KeySpec) (Key, error)
	Signer(ctx context.Context, keyID string) (crypto.Signer, error)
}
