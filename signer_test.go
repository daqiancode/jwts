package jwts_test

import (
	"fmt"
	"testing"

	"github.com/daqiancode/jwts"
	"github.com/kataras/iris/v12/middleware/jwt"
	"github.com/stretchr/testify/assert"
)

func TestHS256(t *testing.T) {
	pk := "123456"
	uid := "123"
	r, err := jwts.GenerateTokenPair(jwts.SignAlg("HS256"), pk, uid, "ADMIN", "email", "xxxxxxxx", 30*60, 24*3600)
	assert.Nil(t, err)
	assert.True(t, len(r.AccessToken) > 0)
	assert.True(t, len(r.RefreshToken) > 0)
	verifier := jwt.NewVerifier(jwt.HS256, pk)
	a, err := verifier.VerifyToken([]byte(r.AccessToken))
	assert.Nil(t, err)
	var token jwts.AccessToken
	a.Claims(&token)
	assert.Equal(t, token.Subject, uid)
}

func TestEdDSA(t *testing.T) {
	publicKey, privateKey, err := jwts.GenerateEdDSAKeyPair()
	assert.Nil(t, err)
	r, err := jwts.GenerateTokenPair(jwts.SignAlg("EdDSA"), privateKey, "123", "ADMIN", "email", "xxxxxxxx", 30*60, 24*3600)
	assert.Nil(t, err)
	fmt.Println(r)
	at, err := jwts.JwtVerify([]byte(r.AccessToken), publicKey)
	assert.Nil(t, err)
	assert.Equal(t, at.StandardClaims.Subject, "123")
}

func TestES256(t *testing.T) {
	privateKey := `MHcCAQEEIBwtVzV00P8z7Jtj5jBSbgopZbr/tdh1KCiJ7uvVvVgtoAo
	GCCqGSM49AwEHoUQDQgAECyM0x23QynOi9w9PtcUiLTfe0Nem9WnNFvjbYoEe8/ivD4/4oUNc/gS6bmtLGROjhm8qNQsepHuwBQDM+mVhIQ==`
	publicKey := `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyM0x23QynOi9w9PtcUiLTfe0Nem9WnNFvjbYoEe8/ivD4/4oUNc/gS6bmtLGROjhm8qNQsepHuwBQDM+mVhIQ==`
	r, err := jwts.GenerateTokenPair(jwts.SignAlg("ES256"), privateKey, "123", "ADMIN", "email", "xxxxxxxx", 30*60, 24*3600)
	assert.Nil(t, err)
	fmt.Println(r)
	at, err := jwts.JwtVerify([]byte(r.AccessToken), publicKey)
	assert.Nil(t, err)
	assert.Equal(t, at.StandardClaims.Subject, "123")
}

type testStruct struct {
	Email   string `validate:"email"`
	Mobile  string
	Captcha string `validate:"required,len=6"`
	Name    string `validate:"min=4,max=6"`
}
