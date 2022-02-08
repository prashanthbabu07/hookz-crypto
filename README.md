# Building from source

```
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

```
sudo xcode-select --switch /Volumes/Sandisk/Applications/Xcode.app
```

```
make
```


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
- Encryption & Decryption

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

## Encryption & Decryption
```go

var message = []byte("Hello World!")
theirKey := NewKeyAgreementKeyPair()
ourSigningKey := NewSigningKeyPair()
sealedMessage, err := Encrypt(message, theirKey.PublicKey, ourSigningKey)
if err != nil {
	fmt.Print(err)
}
decryptedMessage, err := Decrypt(sealedMessage, theirKey, ourSigningKey.PublicKey)
if err != nil {
	fmt.Println(err)
}
fmt.Println(string(decryptedMessage))
```

## Testing
```go
cd crypto
go test -timeout 30s -run ^TestKeys

go test -timeout 30s -run ^(TestKeys|TestMessageSigning|TestSharedSecret|TestHKDF|TestEncryption|TestSomething)
```