package crypto

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeys(t *testing.T) {
	alice := NewKeyAgreementKeyPair()
	bob := NewKeyAgreementKeyPair()

	var abs = alice.PrivateKey.SharedSecretFrom(bob.PublicKey)
	var bas = bob.PrivateKey.SharedSecretFrom(alice.PublicKey)
	t.Log("abs")
	assert.Equal(t, abs, bas, "The shared secret should be the same.")
}

func TestMessageSigning(t *testing.T) {
	signingKey := NewSigningKeyPair()
	var message = []byte("Hello World!")
	var signature = signingKey.PrivateKey.Sign(message)
	var isValid = signingKey.PublicKey.IsValidSignature(signature, message)
	assert.Equal(t, isValid, true, "The signature should be valid.")
}

func TestSharedSecret(t *testing.T) {
	alice := NewKeyAgreementKeyPair()
	bob := NewKeyAgreementKeyPair()
	abs := alice.PrivateKey.SharedSecretFrom(bob.PublicKey)
	bas := bob.PrivateKey.SharedSecretFrom(alice.PublicKey)
	assert.Equal(t, abs, bas, "the shared secret should be equal")

}

func TestHKDF(t *testing.T) {
	theirKey := NewKeyAgreementKeyPair()
	ephimeralKey := NewKeyAgreementKeyPair()
	shared := ephimeralKey.PrivateKey.SharedSecretFrom(theirKey.PublicKey)
	additionalInfo := append(ephimeralKey.PublicKey.Key(), theirKey.PublicKey.Key()...)

	ourSigningKey := NewSigningKeyPair()
	additionalInfo = append(additionalInfo, ourSigningKey.PublicKey.Key()...)
	key, _ := HKDF(sha256.New, shared, additionalInfo)
	println("Symmetric Key ", key)
}

func TestSomething(t *testing.T) {
	var a string = "Hello"
	var b string = "Hello"
	assert.Equal(t, a, b, "The two words should be the same.")
}
