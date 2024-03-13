package jwts

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/kataras/iris/v12/middleware/jwt"
	kjwt "github.com/kataras/jwt"
)

type JwtSigner struct{}

func (JwtSigner) Encode(alg SignAlg, privateKeyPem string, claim interface{}) (string, error) {
	a := alg.Alg()
	if a == nil {
		return "", errors.New("not support such signature algorithm: " + string(alg))
	}
	pk, err := alg.ParsePrivateKey(privateKeyPem)
	if err != nil {
		return "", err
	}
	bs, err := jwt.NewSigner(a, pk, 0).Sign(claim)
	return string(bs), err
}

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func (JwtSigner) Decode(token string, publicKeyPem string, claim any) (header JwtHeader, err error) {
	tokenBs := []byte(token)
	i := bytes.Index(tokenBs, []byte{'.'})
	bs, err := kjwt.Base64Decode(tokenBs[0:i])
	if err != nil {
		return header, err
	}
	err = json.Unmarshal(bs, &header)
	if err != nil {
		return header, err
	}
	signAlg := SignAlg(header.Alg)
	alg, ok := SignAlgs[signAlg]
	if !ok {
		return header, errors.New("Not support such alg:" + header.Alg)
	}
	pk, err := signAlg.ParsePublicKey(publicKeyPem)
	if err != nil {
		return header, err
	}
	verifier := jwt.NewVerifier(alg, pk)
	vt, err := verifier.VerifyToken([]byte(token))
	if err != nil {
		return header, err
	}
	err = vt.Claims(claim)
	return header, err
}

type TokenPair struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

var UUIDLen = 20

type AccessTokens struct {
	alg        SignAlg
	privateKey string
}

func NewAccessTokens(alg SignAlg, privateKey string) *AccessTokens {
	return &AccessTokens{alg: alg, privateKey: privateKey}
}

func (a *AccessTokens) GenerateAccessToken(tokenId, uid, roles, scope, refreshTokenID string, maxAgeSecs int64) (string, error) {
	accessToken := AccessToken{Claims: jwt.Claims{ID: tokenId, Subject: uid, Expiry: time.Now().Unix() + maxAgeSecs}, Roles: roles, Scope: scope, Rid: refreshTokenID}
	return JwtSigner{}.Encode(a.alg, a.privateKey, accessToken)
}

func (a *AccessTokens) GenerateRefreshToken(tokenId, uid, roles, scope, encryptedPassword string, maxAgeSecs int64) (string, error) {
	expiry := time.Now().Unix() + maxAgeSecs
	refreshToken := &RefreshToken{
		Claims: jwt.Claims{ID: tokenId, Subject: uid, Expiry: expiry},
		Scope:  scope,
		V:      CreateRefreshTokenVerfication(encryptedPassword, uid, roles, maxAgeSecs),
	}
	return JwtSigner{}.Encode(a.alg, a.privateKey, refreshToken)
}

func Md5Base64(s string) string {
	a := md5.Sum([]byte(s))
	return base64.StdEncoding.EncodeToString(a[:])
}

func CreateRefreshTokenVerfication(encryptedPassword, uid, roles string, maxAgeSecs int64) string {
	return Md5Base64(encryptedPassword + uid + roles + strconv.FormatInt(maxAgeSecs, 10))
}
