package jwts_test

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/daqiancode/jwts"
	"github.com/daqiancode/jwts/cryptos"
	"github.com/stretchr/testify/assert"
)

func TestEdDSA(t *testing.T) {
	pubKey, privKey, err := cryptos.EDdSA{}.GenerateKeyPairPem()
	assert.Nil(t, err)
	fmt.Println(pubKey)
	fmt.Println(privKey)
	refreskTokenId := "123456"
	ats := jwts.NewAccessTokens(jwts.EdDSA, privKey, 20)
	rt, err := ats.GenerateRefreshToken("123", "ADMIN", "email", refreskTokenId, 24*3600)
	assert.Nil(t, err)
	at, err := ats.GenerateAccessToken("123", "ADMIN", "email", refreskTokenId, 3600)
	assert.Nil(t, err)
	fmt.Println(rt)
	fmt.Println(at)
	var decodedAt jwts.AccessToken
	_, err = jwts.JwtSigner{}.Decode(rt, pubKey, &decodedAt)
	assert.Nil(t, err)
	assert.Equal(t, decodedAt.Subject, "123")
}

func TestES256(t *testing.T) {
	pubKey, privKey, err := cryptos.ECC{}.GenerateKeyPairPem(elliptic.P256())
	assert.Nil(t, err)
	fmt.Println(pubKey)
	fmt.Println(privKey)
	refreskTokenId := "123456"
	ats := jwts.NewAccessTokens(jwts.ES256, privKey, 20)
	rt, err := ats.GenerateRefreshToken("123", "ADMIN", "email", refreskTokenId, 24*3600)
	assert.Nil(t, err)
	at, err := ats.GenerateAccessToken("123", "ADMIN", "email", refreskTokenId, 3600)
	assert.Nil(t, err)
	fmt.Println(rt)
	fmt.Println(at)
	var decodedAt jwts.AccessToken
	_, err = jwts.JwtSigner{}.Decode(rt, pubKey, &decodedAt)
	assert.Nil(t, err)
	assert.Equal(t, decodedAt.Subject, "123")
}
