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

// Role based access controll filter
func RBAC(roles []string) iris.Handler {
	return func(ctx iris.Context) {
		if CheckRBAC(roles, ctx) {
			ctx.Next()
		}
	}
}

// Scope based access controll filter
func Scope(scope ...string) iris.Handler {
	return func(ctx iris.Context) {
		if CheckSBAC(scope, ctx) {
			ctx.Next()
		}
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

func CheckRBAC(ctx iris.Context, roles ...string) bool {
	if !checkUserExists(ctx) {
		ctx.StopWithText(iris.StatusUnauthorized, "please signin")
		return false
	}
	if len(roles) == 0 {
		return true
	}
	tokenRoles, err := ctx.User().GetRoles()
	if err != nil {
		ctx.StopWithText(iris.StatusUnauthorized, "invalid roles")
		return false
	}
	if !findRole(roles, tokenRoles) {
		ctx.StopWithText(iris.StatusForbidden, "roles not matched")
		return false
	}
	return true
}

func CheckSBAC(ctx iris.Context, scopes ...string) bool {
	if !checkUserExists(ctx) {
		ctx.StopWithText(iris.StatusUnauthorized, "please signin")
		return false
	}
	if len(scopes) == 0 {
		return true
	}
	tokenScope, err := ctx.User().GetField("scope")
	if err != nil {
		ctx.StopWithText(iris.StatusUnauthorized, "invalid scopes")
		return false
	}
	if scopeStr, ok := tokenScope.(string); ok {
		tokenScopes := strings.Split(scopeStr, " ")
		if indexStrs(scopes, "*") != -1 {
			return true
		}
		if len(intersection(tokenScopes, scopes)) > 0 {
			return true
		}

	}
	ctx.StopWithText(iris.StatusUnauthorized, "roles not matched")
	return false
}

func IsTokenExists(ctx iris.Context) bool {
	user := ctx.User()
	return user != nil
}

func GetScopes(ctx iris.Context) ([]string, error) {
	scope, err := ctx.User().GetField("scope")
	if err != nil {
		return nil, err
	}
	if scopeStr, ok := scope.(string); ok {
		return strings.Split(scopeStr, " "), nil
	}
	return nil, nil
}
