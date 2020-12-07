# Hookz Crypto
 A crypto library for ios, android and web (wasm). Provides functions for end to end encryption (E2EE) across platforms.

 ---

## Why
 Code sharing between different platforms.

## 
- Signing keypair
- Key agreement keypair
- Key exchange for shared secret
- Message signing

# Examples

## Shared Secret

 ```go

	alice := NewKeyAgreementKeyPair()
	bob   := NewKeyAgreementKeyPair()

	var abs = alice.PrivateKey.SharedSecretFrom(bob.PublicKey)
	var bas = bob.PrivateKey.SharedSecretFrom(alice.PublicKey)
	
 ```

## Message Signing

 ```go

	signingKey := NewSigningKeyPair()
	var message = []byte("Hello World!")
	var signature = signingKey.PrivateKey.Sign(message)
	var isValid = signingKey.PublicKey.IsValidSignature(signature, message)

```

## Key Derivation Function (HKDF)

```go

	theirKey := NewKeyAgreementKeyPair()
	ephimeralKey := NewKeyAgreementKeyPair()
	shared := ephimeralKey.PrivateKey.SharedSecretFrom(theirKey.PublicKey)
	additionalInfo := append(ephimeralKey.PublicKey.Key(), theirKey.PublicKey.Key()...)
	ourSigningKey := NewSigningKeyPair()
	additionalInfo = append(additionalInfo, ourSigningKey.PublicKey.Key()...)
	key, _ := HKDF(sha256.New, shared, additionalInfo)
	println("Symmetric Key ", key)

```

## Encryption
```go

	func Encrypt(data []byte, theirPublicKey *KeyAgreementPublicKey, ourSigningKey *SigningKeyPair) (*SealedMessage, error)

```

## Decryption
```go

	func Decrypt(sealedMessage *SealedMessage, ourEncryptionKey *KeyAgreementKeyPair, theirSigningKey *SigningPublicKey) ([]byte, error)

```

## More examples 
 Work in progress 