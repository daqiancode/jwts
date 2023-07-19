package jwts

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/jwt"
	kjwt "github.com/kataras/jwt"
)

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func JwtVerify(token []byte, publicKey string) (*kjwt.VerifiedToken, error) {
	i := bytes.Index(token, []byte{'.'})
	bs, err := kjwt.Base64Decode(token[0:i])
	if err != nil {
		return nil, err
	}
	var header JwtHeader
	err = json.Unmarshal(bs, &header)
	if err != nil {
		return nil, err
	}
	signAlg := SignAlg(header.Alg)
	alg, ok := SignAlgs[signAlg]
	if !ok {
		return nil, errors.New("Not support such alg:" + header.Alg)
	}
	pk, err := signAlg.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	verifier := jwt.NewVerifier(alg, pk)
	return verifier.VerifyToken([]byte(token))
}

type AccessTokenSetterConfig struct {
	PublicKey    string
	DetectCookie bool
	CookieName   string
}

func GetAccessTokenFromBearer(ctx iris.Context) string {
	token := ctx.GetHeader("Authorization")
	if len(token) != 0 && token[:7] == "Bearer " {
		return token[7:]
	}
	return ""
}
func AccessTokenSetter(config AccessTokenSetterConfig) iris.Handler {

	return func(ctx iris.Context) {
		token := GetAccessTokenFromBearer(ctx)
		if token == "" && config.DetectCookie {
			if config.CookieName == "" {
				config.CookieName = "access_token"
			}
			if v := ctx.GetCookie(config.CookieName); len(v) > 0 {
				token = v
			}
		}
		if token == "" {
			ctx.Next()
			return
		}
		verifiedToken, err := JwtVerify([]byte(token), config.PublicKey)
		if err != nil {
			ctx.StopWithError(401, err)
			return
		}
		var accessToken AccessToken
		err = verifiedToken.Claims(&accessToken)
		if err != nil {
			ctx.StopWithError(401, err)
			return
		}
		ctx.SetUser(&accessToken)
		ctx.Next()
	}
}
func checkUserExists(ctx iris.Context) bool {
	user := ctx.User()
	if user == nil {
		ctx.StopWithText(401, "Access token is required")
		return false
	}
	return true
}
func Require() iris.Handler {
	return func(ctx iris.Context) {
		if checkUserExists(ctx) {
			ctx.Next()
		}
	}
}

func RBAC(roles []string) iris.Handler {
	return func(ctx iris.Context) {
		if !checkUserExists(ctx) {
			return
		}
		userRoles, err := ctx.User().GetRoles()
		if err != nil {
			ctx.StopWithError(iris.StatusUnauthorized, err)
			return
		}
		if !findRole(roles, userRoles) {
			ctx.StopWithText(iris.StatusForbidden, "Forbidden")
			return
		}
		ctx.Next()
	}
}
func intersection(a, b []string) []string {
	m := make(map[string]bool)
	for _, v := range a {
		m[v] = true
	}
	var r []string
	for _, v := range b {
		if m[v] {
			r = append(r, v)
		}
	}
	return r
}
func findRole(giveRoles, myRoles []string) bool {
	if len(giveRoles) == 0 {
		return true
	}
	return len(intersection(giveRoles, myRoles)) > 0
}
func indexStrs(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

func Scope(givenScope ...string) iris.Handler {
	return func(ctx iris.Context) {
		if !checkUserExists(ctx) {
			return
		}
		if len(givenScope) == 0 {
			ctx.Next()
			return
		}
		scope, err := ctx.User().GetField("scope")
		if err != nil {
			ctx.StopWithError(iris.StatusUnauthorized, err)
			return
		}
		if scopeStr, ok := scope.(string); ok {
			scopes := strings.Split(scopeStr, " ")
			if indexStrs(scopes, "*") != -1 {
				ctx.Next()
				return
			}
			if len(intersection(givenScope, scopes)) > 0 {
				ctx.Next()
				return
			}

		}
		ctx.StopWithText(iris.StatusForbidden, "Invalid scope")
	}
}
