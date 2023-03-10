package jwts

import (
	"errors"
	"time"

	"github.com/kataras/iris/v12/middleware/jwt"
)

func Sign(alg SignAlg, claim interface{}, privateKey string) (string, error) {
	a := alg.Alg()
	if a == nil {
		return "", errors.New("not support such signature algorithm: " + string(alg))
	}
	pk, err := alg.ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	bs, err := jwt.NewSigner(a, pk, 0).Sign(claim)
	return string(bs), err
}

type TokenPair struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

var UUIDLen = 20

// GenerateTokenPair generate access_token & refresh_token, roles are seperate by space .eg, "ADMIN SYSTEM"
func GenerateTokenPair(alg SignAlg, privateKey, uid, roles, scope, encryptedPassword string, accessTokenMaxAge, refreshTokenMaxAge int64) (TokenPair, error) {
	refreshTokenID := UUID(UUIDLen)
	refreshToken, err := GenerateRefreshToken(alg, privateKey, uid, roles, scope, refreshTokenMaxAge, refreshTokenID, encryptedPassword)
	if err != nil {
		return TokenPair{}, err
	}
	accessToken, err := GenerateAccessToken(alg, privateKey, uid, roles, scope, accessTokenMaxAge, refreshTokenID)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func GenerateAccessToken(alg SignAlg, privateKey, uid, roles, scope string, maxAge int64, refreshTokenID string) (string, error) {
	accessToken := AccessToken{Claims: jwt.Claims{ID: UUID(UUIDLen), Subject: uid, Expiry: time.Now().Unix() + maxAge}, Roles: roles, Scope: scope, Rid: refreshTokenID}
	return Sign(alg, accessToken, privateKey)
}

func GenerateRefreshToken(alg SignAlg, privateKey, uid, roles, scope string, maxAge int64, refreshTokenID, encryptedPassword string) (string, error) {
	expiry := time.Now().Unix() + maxAge
	refreshToken := &RefreshToken{
		Claims: jwt.Claims{ID: refreshTokenID, Subject: uid, Expiry: expiry},
		Scope:  scope,
		V:      CreateRefreshTokenVerfication(encryptedPassword, uid, roles, expiry),
	}
	return Sign(alg, refreshToken, privateKey)
}
