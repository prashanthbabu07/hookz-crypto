package cryptoweb

import (
	"encoding/base64"
	"fmt"
	"syscall/js"

	crypto "github.com/prashanthbabu07/hookzcrypto/crypto"
)

func NewKeyAgreementKeyPair() js.Func {
	newKeyAgreementKeyPairFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		keyPair := crypto.NewKeyAgreementKeyPair()
		keys := keyPair.PrivateKey.ToBase64String()
		keys = keys + ":" + keyPair.PublicKey.ToBase64String()
		return keys
	})
	return newKeyAgreementKeyPairFunc
}

func NewSigningKeyPair() js.Func {
	newSigningKeyPairFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		keyPair := crypto.NewSigningKeyPair()
		keys := keyPair.PrivateKey.ToBase64String()
		keys = keys + ":" + keyPair.PublicKey.ToBase64String()
		return keys
	})
	return newSigningKeyPairFunc
}

func NewIdentityKeyPair() js.Func {
	identityKeyPairFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		keyPair := crypto.NewIdentityKeyPair()
		keys := keyPair.KeyAgreement.PrivateKey.ToBase64String()
		keys = keys + ":" + keyPair.KeyAgreement.PublicKey.ToBase64String()
		keys = keys + ":" + keyPair.Signing.PrivateKey.ToBase64String()
		keys = keys + ":" + keyPair.Signing.PublicKey.ToBase64String()
		return keys
	})
	return identityKeyPairFunc
}

func SharedSecret() js.Func {
	sharedSecretFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			panic(fmt.Sprintf("Arguments length is not 2 but %d\n", len(args)))
		}
		ourPrivateKey, _ := crypto.NewKeyAgreementPrivateKeyFromBase64String(args[0].String())
		theirPublickKey, _ := crypto.NewKeyAgreementPublicKeyFromBase64String(args[1].String())
		sharedKey := ourPrivateKey.SharedSecretFrom(theirPublickKey)
		return base64.StdEncoding.EncodeToString(sharedKey)
	})
	return sharedSecretFunc
}

func Encrypt() js.Func {
	encryptFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		data := []byte(args[0].String())
		theirPublickKey, _ := crypto.NewKeyAgreementPublicKeyFromBase64String(args[1].String())
		ourSigningPrivateKey, _ := base64.StdEncoding.DecodeString(args[2].String())
		ourSigningPublieKey, _ := base64.StdEncoding.DecodeString(args[3].String())
		keyPair := crypto.SigningKeyPair{
			PrivateKey: crypto.NewSigningPrivateKeyFrom(ourSigningPrivateKey),
			PublicKey:  crypto.NewSigningPublicKeyFrom(ourSigningPublieKey),
		}
		message, _ := crypto.Encrypt(data, theirPublickKey, &keyPair)
		return base64.StdEncoding.EncodeToString(message.Cipher) + ":" +
			base64.StdEncoding.EncodeToString(message.Signature) + ":" +
			message.EphemeralPublicKey.ToBase64String()
	})
	return encryptFunc
}

func Decrypt() js.Func {
	decryptFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		cipher, _ := base64.StdEncoding.DecodeString(args[0].String())
		signature, _ := base64.StdEncoding.DecodeString(args[1].String())
		ephemeralPublicKey, _ := base64.StdEncoding.DecodeString(args[2].String())
		key := crypto.NewKeyAgreementPublicKeyFrom(ephemeralPublicKey)
		message := crypto.SealedMessage{
			Cipher:             cipher,
			Signature:          signature,
			EphemeralPublicKey: key,
		}
		keyAgreementPrivateKeyBytes, _ := base64.StdEncoding.DecodeString(args[3].String())
		keyAgreementPrivateKey := crypto.NewKeyAgreementPrivateKeyFrom(keyAgreementPrivateKeyBytes)
		keyAgreementPublicKeyBytes, _ := base64.StdEncoding.DecodeString(args[4].String())
		keyAgreementPublicKey := crypto.NewKeyAgreementPublicKeyFrom(keyAgreementPublicKeyBytes)
		signingPublicKeyBytes, _ := base64.StdEncoding.DecodeString(args[5].String())
		theirSigningPublicKey := crypto.NewSigningPublicKeyFrom(signingPublicKeyBytes)
		data, _ := crypto.Decrypt(&message, &crypto.KeyAgreementKeyPair{
			PrivateKey: keyAgreementPrivateKey,
			PublicKey:  keyAgreementPublicKey,
		}, theirSigningPublicKey)
		// fmt.Println(data)
		// info := string(data)
		return string(data)
	})
	return decryptFunc
}
