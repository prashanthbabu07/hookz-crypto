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

## Shared secret example

 ```go
	alice := NewKeyAgreementKeyPair()
	bob   := NewKeyAgreementKeyPair()

	var abs = alice.PrivateKey.SharedSecretFrom(bob.PublicKey)
	var bas = bob.PrivateKey.SharedSecretFrom(alice.PublicKey)
 ```

## Message signing

 ```go
	signingKey := NewSigningKeyPair()
	var message = []byte("Hello World!")
	var signature = signingKey.PrivateKey.Sign(message)
	var isValid = signingKey.PublicKey.IsValidSignature(signature, message)
```

## More examples work in progress 