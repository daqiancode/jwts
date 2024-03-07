package jwts

import (
	"errors"
	"strings"
	"time"

	"github.com/kataras/iris/v12/middleware/jwt"
)

/*
	{
		jti:"token id",
		sub : "user id",
		exp:123,
		roles:"FINANCE SALE ADMIN",
		rid:"refresh token id"
	}
*/
type AccessToken struct {
	jwt.Claims
	Roles string `json:"roles,omitempty"`
	Scope string `json:"scope,omitempty"`
	Rid   string `json:"rid,omitempty"`
}
type RefreshToken struct {
	jwt.Claims
	V     string `json:"v,omitempty"` // md5(crypted_password + uid + exp)
	Scope string `json:"scope,omitempty"`
}

func ParseAccessToken(accessToken string, publicKey string) (AccessToken, error) {
	var token AccessToken
	_, err := JwtSigner{}.Decode(accessToken, publicKey, &token)
	return token, err
}

func (s AccessToken) ValidateToken(token []byte, standardClaims jwt.Claims, err error) error {
	return nil
}

func (s *AccessToken) GetRaw() (interface{}, error) {
	return s, nil
}

// GetAuthorization should return the authorization method,
// e.g. Basic Authentication.
func (s AccessToken) GetAuthorization() (string, error) {
	return "", errors.New("no authorization")
}

// GetAuthorizedAt should return the exact time the
// client has been authorized for the "first" time.
func (s AccessToken) GetAuthorizedAt() (time.Time, error) {
	return time.Time{}, errors.New("no authorizedAt")
}

// GetID should return the ID of the User.
func (s AccessToken) GetID() (string, error) {
	return s.Subject, nil
}

// GetUsername should return the name of the User.
func (s AccessToken) GetUsername() (string, error) {
	return "", errors.New("no username")
}

// GetPassword should return the encoded or raw password
// (depends on the implementation) of the User.
func (s AccessToken) GetPassword() (string, error) {
	return "", errors.New("no password")
}

// GetEmail should return the e-mail of the User.
func (s AccessToken) GetEmail() (string, error) {
	return "", errors.New("no Email")
}

// GetRoles should optionally return the specific user's roles.
// Returns `ErrNotSupported` if this method is not
// implemented by the User implementation.
func (s AccessToken) GetRoles() ([]string, error) {
	return strings.Split(s.Roles, " "), nil
}

// GetToken should optionally return a token used
// to authorize this User.
func (s AccessToken) GetToken() ([]byte, error) {
	return nil, errors.New("no Token")
}

// GetField should optionally return a dynamic field
// based on its key. Useful for custom user fields.
// Keep in mind that these fields are encoded as a separate JSON key.
func (s AccessToken) GetField(key string) (interface{}, error) {
	switch strings.ToLower(key) {
	case "tokenid", "jti":
		return s.ID, nil
	case "roles":
		return s.Roles, nil
	case "rid":
		return s.Rid, nil
	case "scope":
		return s.Scope, nil
	}
	return nil, errors.New("No such key: " + key)
}

/*
	{
		jti:"token id",
		sub : "user id",
		exp:123,
		v:"password verification",
	}
*/

func ParseRefreshToken(refreshToken string, publicKey string) (RefreshToken, error) {
	var token RefreshToken
	// claim, err := JwtVerify([]byte(refreshToken), publicKey)
	// if err != nil {
	// 	return token, err
	// }

	// err = claim.Claims(&token)
	_, err := JwtSigner{}.Decode(refreshToken, publicKey, &token)
	return token, err
}

// func (s *RefreshToken) SetV(encryptedPassword, roles string) string {
// 	return CreateRefreshTokenVerfication(encryptedPassword, s.Subject, roles, s.Expiry)
// }

func (s RefreshToken) GetID() string {
	return s.Subject
}
