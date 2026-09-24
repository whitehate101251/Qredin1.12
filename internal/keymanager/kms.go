package keymanager

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kmsAPI interface {
	CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSManager uses AWS KMS as the private-key boundary. Public keys are loaded
// once and cached; every signing operation remains a KMS API call.
type KMSManager struct {
	client kmsAPI
	mu     sync.RWMutex
	public map[string]crypto.PublicKey
	opened bool
}

func NewKMSManager(client *kms.Client) (*KMSManager, error) {
	if client == nil {
		return nil, errors.New("keymanager: KMS client is required")
	}
	return newKMSManager(client), nil
}

func newKMSManager(client kmsAPI) *KMSManager {
	return &KMSManager{client: client, public: make(map[string]crypto.PublicKey)}
}

func (m *KMSManager) Open(_ context.Context, _ Environment) error {
	m.mu.Lock()
	m.opened = true
	m.mu.Unlock()
	return nil
}

func (m *KMSManager) Generate(ctx context.Context, spec KeySpec) (Key, error) {
	if !m.isOpen() {
		return Key{}, errors.New("keymanager: KMS manager is not open")
	}
	if spec.Algorithm != "" && spec.Algorithm != "ECDSA_P256" {
		return Key{}, fmt.Errorf("keymanager: unsupported KMS key algorithm %q", spec.Algorithm)
	}
	out, err := m.client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:     types.KeySpecEccNistP256,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: stringPtr("Qredin signing authority key"),
	})
	if err != nil || out == nil || out.KeyMetadata == nil || out.KeyMetadata.KeyId == nil {
		return Key{}, fmt.Errorf("keymanager: creating KMS key: %w", err)
	}
	keyID := *out.KeyMetadata.KeyId
	public, err := m.loadPublic(ctx, keyID)
	if err != nil {
		return Key{}, err
	}
	return Key{ID: keyID, Public: public}, nil
}

func (m *KMSManager) Signer(ctx context.Context, keyID string) (crypto.Signer, error) {
	if !m.isOpen() {
		return nil, errors.New("keymanager: KMS manager is not open")
	}
	if keyID == "" {
		return nil, errors.New("keymanager: KMS key ID is required")
	}
	public, err := m.loadPublic(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return &kmsSigner{client: m.client, keyID: keyID, public: public}, nil
}

func (m *KMSManager) isOpen() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.opened
}

func (m *KMSManager) loadPublic(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	m.mu.RLock()
	public := m.public[keyID]
	m.mu.RUnlock()
	if public != nil {
		return public, nil
	}
	out, err := m.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("keymanager: getting KMS public key: %w", err)
	}
	if out == nil || len(out.PublicKey) == 0 {
		return nil, errors.New("keymanager: KMS returned no public key")
	}
	public, err = x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keymanager: parsing KMS public key: %w", err)
	}
	m.mu.Lock()
	m.public[keyID] = public
	m.mu.Unlock()
	return public, nil
}

type kmsSigner struct {
	client kmsAPI
	keyID  string
	public crypto.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey { return s.public }

func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != sha256.Size || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("keymanager: KMS signer requires a SHA-256 digest")
	}
	out, err := s.client.Sign(context.Background(), &kms.SignInput{
		KeyId: &s.keyID, Message: digest, MessageType: types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("keymanager: KMS signing: %w", err)
	}
	if out == nil || len(out.Signature) == 0 {
		return nil, errors.New("keymanager: KMS returned no signature")
	}
	return out.Signature, nil
}

func stringPtr(value string) *string { return &value }
