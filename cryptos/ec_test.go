package cryptos_test

import (
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/daqiancode/jwts/cryptos"
	"github.com/stretchr/testify/assert"
)

func TestEC(t *testing.T) {
	pubKey, privKey, err := cryptos.ECC{}.GenerateKeyPairPem(elliptic.P256())
	assert.Nil(t, err)
	fmt.Println(pubKey)
	fmt.Println(privKey)
	sign, err := cryptos.ECC{}.Sign(privKey, []byte("hello"))
	assert.Nil(t, err)
	base64Sign := base64.StdEncoding.EncodeToString(sign)
	fmt.Println(base64Sign)
	ok, err := cryptos.ECC{}.Verify(pubKey, []byte("hello"), sign)
	assert.Nil(t, err)
	assert.True(t, ok)

}

func TestEd(t *testing.T) {
	pubKey, privKey, err := cryptos.EDdSA{}.GenerateKeyPairPem()
	assert.Nil(t, err)
	fmt.Println(pubKey)
	fmt.Println(privKey)
	sign, err := cryptos.EDdSA{}.Sign(privKey, []byte("hello"))
	assert.Nil(t, err)
	base64Sign := base64.StdEncoding.EncodeToString(sign)
	fmt.Println(base64Sign)
	ok, err := cryptos.EDdSA{}.Verify(pubKey, []byte("hello"), sign)
	assert.Nil(t, err)
	assert.True(t, ok)
}
