package jwts

import (
	"bytes"
	"encoding/json"
	"errors"

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

func Require() iris.Handler {
	return func(ctx iris.Context) {
		user := ctx.User()
		if user == nil {
			ctx.StopWithText(401, "Access token is required")
			return
		}
		ctx.Next()
	}
}

func RBAC(roles []string) iris.Handler {
	return func(ctx iris.Context) {
		userRoles, err := ctx.User().GetRoles()
		if err != nil {
			ctx.StopWithError(iris.StatusUnauthorized, err)
			return
		}
		if !findRole(roles, userRoles) {
			ctx.StopWithJSON(iris.StatusForbidden, "Forbidden")
			return
		}
		ctx.Next()
	}
}

func findRole(giveRoles, myRoles []string) bool {
	if len(giveRoles) == 0 {
		return true
	}
	giveRolesMap := make(map[string]bool, len(giveRoles))
	for _, v := range giveRoles {
		giveRolesMap[v] = true
	}
	for _, v := range myRoles {
		if giveRolesMap[v] {
			return true
		}
	}
	return false
}
