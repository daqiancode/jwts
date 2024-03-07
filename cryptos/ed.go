package cryptos

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

type EDdSA struct{}

func (EDdSA) GenerateKeyPairPem() (pubKeyPEM string, priKeyPem string, err error) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv) // Convert a generated ed25519 key into a PEM block so that the ssh library can ingest it, bit round about tbh
	if err != nil {
		return "", "", err
	}
	privatePEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		},
	)
	priKeyPem = string(privatePEM)

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}

	publicPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})
	pubKeyPEM = string(publicPEM)
	return
}

func (EDdSA) Sign(privKeyPem string, bs []byte) (signature []byte, err error) {
	block, _ := pem.Decode([]byte(privKeyPem))
	if block == nil {
		return nil, nil
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signature = ed25519.Sign(priv.(ed25519.PrivateKey), bs)
	return
}

func (EDdSA) Verify(pubKeyPem string, bs []byte, signature []byte) (bool, error) {
	block, _ := pem.Decode([]byte(pubKeyPem))
	if block == nil {
		return false, nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub.(ed25519.PublicKey), bs, signature), nil
}
