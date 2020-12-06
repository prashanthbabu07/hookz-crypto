package crypto

import (
	"crypto/sha256"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SealedMessage contain sealed info
type SealedMessage struct {
	EphemeralPublicKey *KeyAgreementPublicKey
	Signature          []byte
	Cipher             []byte
}

// Encrypt data
func Encrypt(data []byte, theirPublicKey *KeyAgreementPublicKey, ourSigningKey *SigningKeyPair) (*SealedMessage, error) {
	ephimeralKey := NewKeyAgreementKeyPair()
	shared := ephimeralKey.PrivateKey.SharedSecretFrom(theirPublicKey)
	additionalInfo := append(ephimeralKey.PublicKey.Key(), theirPublicKey.Key()...)
	additionalInfo = append(additionalInfo, ourSigningKey.PublicKey.Key()...)
	key, err := HKDF(sha256.New, shared, additionalInfo)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())

	cipher := aead.Seal(nonce, nonce, data, additionalInfo)
	signature := ourSigningKey.PrivateKey.Sign(cipher)

	return &SealedMessage{
		EphemeralPublicKey: ephimeralKey.PublicKey,
		Cipher:             cipher,
		Signature:          signature,
	}, nil
}

// Decrypt data
func Decrypt(sealedMessage *SealedMessage, ourEncryptionKey *KeyAgreementKeyPair, theirSigningKey *SigningPublicKey) ([]byte, error) {
	if theirSigningKey.IsValidSignature(sealedMessage.Signature, sealedMessage.Cipher) == false {
		return nil, errors.New("Invalid Signature")
	}
	shared := ourEncryptionKey.PrivateKey.SharedSecretFrom(sealedMessage.EphemeralPublicKey)
	additionalInfo := append(sealedMessage.EphemeralPublicKey.Key(), ourEncryptionKey.PublicKey.Key()...)
	additionalInfo = append(additionalInfo, theirSigningKey.Key()...)
	key, err := HKDF(sha256.New, shared, additionalInfo)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if len(sealedMessage.Cipher) < aead.NonceSize() {
		return nil, errors.New("Ciphertext too short")
	}
	// Split nonce and ciphertext.
	nonce, ciphertext := sealedMessage.Cipher[:aead.NonceSize()], sealedMessage.Cipher[aead.NonceSize():]
	if err != nil {
		return nil, err
	}

	// Decrypt the message and check it wasn't tampered with.
	data, err := aead.Open(nil, nonce, ciphertext, additionalInfo)
	if err != nil {
		return nil, err
	}
	return data, nil
}

const salt = "putta hakki gudi ninda inuki nodithu, kalu kandu hari bandu maneya hekithu."

// HKDF creates 256 bit derived key
func HKDF(hash func() hash.Hash, secret []byte, additionalInfo []byte) ([]byte, error) {
	hkdf := hkdf.New(hash, secret, []byte(salt), additionalInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}
