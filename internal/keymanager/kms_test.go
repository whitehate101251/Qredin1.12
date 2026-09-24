package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestKMSManagerCachesPublicKeyAndSignsDigests(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeKMS{key: key, publicDER: publicDER}
	manager := newKMSManager(fake)
	if err := manager.Open(context.Background(), EnvironmentProduction); err != nil {
		t.Fatal(err)
	}
	signer, err := manager.Signer(context.Background(), "kms-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Signer(context.Background(), "kms-key-1"); err != nil {
		t.Fatal(err)
	}
	if fake.publicCalls != 1 {
		t.Fatalf("GetPublicKey calls = %d, want 1", fake.publicCalls)
	}
	digest := sha256.Sum256([]byte("qredin"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if fake.signCalls != 1 {
		t.Fatalf("Sign calls = %d, want 1", fake.signCalls)
	}
}

type fakeKMS struct {
	key         *ecdsa.PrivateKey
	publicDER   []byte
	publicCalls int
	signCalls   int
}

func (f *fakeKMS) CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	id := "kms-key-1"
	return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &id}}, nil
}

func (f *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.publicCalls++
	return &kms.GetPublicKeyOutput{PublicKey: f.publicDER}, nil
}

func (f *fakeKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	signature, err := ecdsa.SignASN1(rand.Reader, f.key, input.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: signature}, nil
}
