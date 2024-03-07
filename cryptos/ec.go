package cryptos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

// Elliptic Curve Cryptography (ECC) is a key-based technique for encrypting data.
// ECC focuses on pairs of public and private keys for decryption and encryption of web traffic.
// ECC is frequently discussed in the context of the Rivest–Shamir–Adleman (RSA) cryptographic algorithm.
// EllipticCurve data struct
type ECC struct {
	// pubKeyCurve elliptic.Curve // http://golang.org/pkg/crypto/elliptic/#P256
	// privateKey  *ecdsa.PrivateKey
}

// GenerateKeys EllipticCurve public and private keys
func (ec ECC) GenerateKey(curve elliptic.Curve) (privKey *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (ec ECC) GenerateKeyPairPem(curve elliptic.Curve) (pubKeyPem string, privKeyPem string, err error) {
	privKey, err := ec.GenerateKey(curve)
	if err != nil {
		return "", "", err
	}
	privKeyPem, err = ec.EncodePrivate(privKey)
	if err != nil {
		return "", "", err
	}
	pubKeyPem, err = ec.EncodePublic(&privKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	return
}

// EncodePrivate private key
func (ec ECC) EncodePrivate(privKey *ecdsa.PrivateKey) (key string, err error) {
	encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	key = string(pemEncoded)
	return
}

// EncodePublic public key
func (ec ECC) EncodePublic(pubKey *ecdsa.PublicKey) (key string, err error) {
	encoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	key = string(pemEncodedPub)
	return
}

// DecodePrivate private key
func (ec ECC) DecodePrivate(pemEncodedPriv string) (privateKey *ecdsa.PrivateKey, err error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))
	x509EncodedPriv := blockPriv.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509EncodedPriv)

	return
}

// DecodePublic public key
func (ec ECC) DecodePublic(pemEncodedPub string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)
	return
}

// VerifySignature sign ecdsa style and verify signature
func (ec ECC) Sign(privKeyPem string, bs []byte) (signature []byte, err error) {
	privKey, err := ec.DecodePrivate(privKeyPem)
	if err != nil {
		return
	}
	signhash := sha256.New().Sum(bs)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, signhash)
	if err != nil {
		return nil, err
	}

	signature = r.Bytes()
	signature = append(signature, s.Bytes()...)
	// ok = ecdsa.Verify(pubKey, signhash, r, s)
	return
}

func (ec ECC) Verify(pubKeyPem string, bs []byte, signature []byte) (bool, error) {
	signhash := sha256.New().Sum(bs)
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])
	pubKey, err := ec.DecodePublic(pubKeyPem)
	if err != nil {
		return false, err
	}
	return ecdsa.Verify(pubKey, signhash, r, s), nil
}
