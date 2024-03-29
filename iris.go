package jwts

import (
	"errors"
	"strings"

	"github.com/kataras/iris/v12"
)

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
		var accessToken AccessToken

		_, err := JwtSigner{}.Decode(token, config.PublicKey, &accessToken)
		if err != nil {
			ctx.StopWithError(401, err)
			return
		}
		ctx.SetUser(&accessToken)
		ctx.Next()
	}
}
func checkUserExists(ctx iris.Context) error {
	user := ctx.User()
	if user == nil {
		ctx.StopWithText(401, "access token is required")
		return errors.New("access token is required")
	}
	return nil
}
func Require() iris.Handler {
	return func(ctx iris.Context) {
		if nil == checkUserExists(ctx) {
			ctx.Next()
		}
	}
}

// Role based access controll filter
func RBAC(roles []string) iris.Handler {
	return func(ctx iris.Context) {
		if nil == CheckRBAC(ctx, roles...) {
			ctx.Next()
		}
	}
}

// Scope based access controll filter
func Scope(scope ...string) iris.Handler {
	return func(ctx iris.Context) {
		if nil == CheckSBAC(ctx, scope...) {
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

func CheckRBAC(ctx iris.Context, roles ...string) error {
	if err := checkUserExists(ctx); err != nil {
		return err
	}
	if len(roles) == 0 {
		return nil
	}
	tokenRoles, err := ctx.User().GetRoles()
	if err != nil {
		ctx.StopWithText(iris.StatusUnauthorized, "invalid roles")
		return errors.New("invalid roles")
	}
	if !findRole(roles, tokenRoles) {
		ctx.StopWithText(iris.StatusForbidden, "roles not matched")
		return errors.New("roles not matched")
	}
	return nil
}

func CheckSBAC(ctx iris.Context, scopes ...string) error {
	if err := checkUserExists(ctx); err != nil {
		return err
	}
	if len(scopes) == 0 {
		return nil
	}
	tokenScope, err := ctx.User().GetField("scope")
	if err != nil {
		ctx.StopWithText(iris.StatusUnauthorized, "invalid scopes")
		return err
	}
	if scopeStr, ok := tokenScope.(string); ok {
		tokenScopes := strings.Split(scopeStr, " ")
		if indexStrs(scopes, "*") != -1 {
			return nil
		}
		if len(intersection(tokenScopes, scopes)) > 0 {
			return nil
		}

	}
	ctx.StopWithText(iris.StatusUnauthorized, "roles not matched")
	return errors.New("roles not matched")
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
