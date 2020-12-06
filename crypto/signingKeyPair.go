package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
)

// SigningPrivateKey represents signing private key
type SigningPrivateKey struct {
	key ed25519.PrivateKey
}

// NewSigningPrivateKeyFrom initializes a private key with given value
func NewSigningPrivateKeyFrom(b []byte) *SigningPrivateKey {
	ensureKeyLength(b, ed25519.SignatureSize)
	var key [ed25519.PrivateKeySize]byte
	copy(key[:], b)
	k := &SigningPrivateKey{
		key: key[:],
	}
	return k
}

// Key returns the value of signing private key
func (k *SigningPrivateKey) Key() []byte {
	return k.key
}

// ToBase64String returns base64 string.
func (k *SigningPrivateKey) ToBase64String() string {
	return base64.StdEncoding.EncodeToString(k.Key())
}

// Sign returns signature using Ed25519
func (k *SigningPrivateKey) Sign(message []byte) []byte {
	signature := ed25519.Sign(k.key, []byte(message))
	return signature
}

// SigningPublicKey represents signing public key for verification
type SigningPublicKey struct {
	key ed25519.PublicKey
}

// NewSigningPublicKeyFrom initializes a public key with the given value
func NewSigningPublicKeyFrom(b []byte) *SigningPublicKey {
	ensureKeyLength(b, ed25519.PublicKeySize)
	var key [ed25519.PublicKeySize]byte
	copy(key[:], b)
	k := &SigningPublicKey{
		key: key[:],
	}
	return k
}

// SigningKeyPair is a pair of private and public signing keys
type SigningKeyPair struct {
	PrivateKey *SigningPrivateKey
	PublicKey  *SigningPublicKey
}

// NewSigningKeyPair creates new signing key pair
func NewSigningKeyPair() *SigningKeyPair {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	return &SigningKeyPair{
		PrivateKey: &SigningPrivateKey{privateKey},
		PublicKey:  &SigningPublicKey{publicKey},
	}
}

// IsValidSignature checks if the message has valid signature using Ed25519
func (k *SigningPublicKey) IsValidSignature(signature []byte, message []byte) bool {
	return ed25519.Verify(k.key, message, signature)
}

// Key returns value of signing public key
func (k *SigningPublicKey) Key() []byte {
	return k.key
}

// ToBase64String returns base64 string.
func (k *SigningPublicKey) ToBase64String() string {
	return base64.StdEncoding.EncodeToString(k.Key())
}
