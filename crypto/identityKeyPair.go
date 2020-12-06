package crypto

// IdentityKeyPair is a pair of signign and key agreement
type IdentityKeyPair struct {
	Signing      *SigningKeyPair
	KeyAgreement *KeyAgreementKeyPair
}

// NewIdentityKeyPair create a new identity key pair for signing and key agreement
func NewIdentityKeyPair() *IdentityKeyPair {
	signing := NewSigningKeyPair()
	keyAgreement := NewKeyAgreementKeyPair()
	return &IdentityKeyPair{
		Signing:      signing,
		KeyAgreement: keyAgreement,
	}
}
