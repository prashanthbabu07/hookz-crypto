package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"io"

	"golang.org/x/crypto/curve25519"
)

// Const byte sizes for key, signature
const (
	KeyAgreementSize = 32
	RandomLimit      = 256
)

// KeyAgreementPrivateKey represents a 256 bit Curve25519 private key for key exchange (KX).
type KeyAgreementPrivateKey struct {
	key [KeyAgreementSize]byte
}

// NewKeyAgreementPrivateKeyFrom initializes a private key with the given value
func NewKeyAgreementPrivateKeyFrom(b []byte) *KeyAgreementPrivateKey {
	ensureKeyLength(b, KeyAgreementSize)
	k := &KeyAgreementPrivateKey{}
	copy(k.key[:], b)
	return k
}

// Key returns the value of the private key.
func (k *KeyAgreementPrivateKey) Key() []byte {
	return k.key[:]
}

// ToBase64String returns base64 string.
func (k *KeyAgreementPrivateKey) ToBase64String() string {
	return base64.StdEncoding.EncodeToString(k.Key())
}

// NewKeyAgreementPrivateKeyFromBase64String init's a private key from base64 string
func NewKeyAgreementPrivateKeyFromBase64String(value string) (*KeyAgreementPrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return NewKeyAgreementPrivateKeyFrom(b), nil
}

// KeyAgreementPublicKey represents a 256 bit Curve25519 public key for key exchange (KX)
type KeyAgreementPublicKey struct {
	key [KeyAgreementSize]byte
}

// Key returns the value of the public key.
func (k *KeyAgreementPublicKey) Key() []byte {
	return k.key[:]
}

// ToBase64String returns base64 string.
func (k *KeyAgreementPublicKey) ToBase64String() string {
	return base64.StdEncoding.EncodeToString(k.Key())
}

// NewKeyAgreementPublicKeyFrom initializes a public key with the given value
func NewKeyAgreementPublicKeyFrom(b []byte) *KeyAgreementPublicKey {
	ensureKeyLength(b, KeyAgreementSize)
	k := &KeyAgreementPublicKey{}
	copy(k.key[:], b)
	return k
}

// NewKeyAgreementPublicKeyFromBase64String initilizes a public key from base64 string
func NewKeyAgreementPublicKeyFromBase64String(value string) (*KeyAgreementPublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return NewKeyAgreementPublicKeyFrom(b), nil
}

func ensureKeyLength(key []byte, size int) {
	if len(key) != size {
		panic(fmt.Sprintf("Key length is not 32 but %d\n", len(key)))
	}
}

func randomBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	// for i := range data[:] {
	// 	data[i] = byte(rand.Intn(256))
	// }
}

// KeyAgreementKeyPair is a pair of private and public key agreement keys
type KeyAgreementKeyPair struct {
	PrivateKey *KeyAgreementPrivateKey
	PublicKey  *KeyAgreementPublicKey
}

// NewKeyAgreementKeyPair creates new ECKeyPair
func NewKeyAgreementKeyPair() *KeyAgreementKeyPair {
	privateKey := KeyAgreementPrivateKey{}
	randomBytes(privateKey.key[:])
	privateKey.key[0] &= 248
	privateKey.key[31] &= 127
	privateKey.key[31] |= 64

	publicKey := KeyAgreementPublicKey{}
	curve25519.ScalarBaseMult(&publicKey.key, &privateKey.key)

	return &KeyAgreementKeyPair{
		PrivateKey: &privateKey,
		PublicKey:  &publicKey,
	}
}

// SharedSecretFrom computes a shared secret with the provided public key from another party.
func (k *KeyAgreementPrivateKey) SharedSecretFrom(theirPublicKey *KeyAgreementPublicKey) []byte {
	var sharedKey [KeyAgreementSize]byte
	curve25519.ScalarMult(&sharedKey, &k.key, &theirPublicKey.key)
	return sharedKey[:]
}
