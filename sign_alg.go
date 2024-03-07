package jwts

import (
	"errors"
	"strings"

	"github.com/kataras/iris/v12/middleware/jwt"
)

var SignAlgs map[SignAlg]jwt.Alg = map[SignAlg]jwt.Alg{
	"EdDSA": jwt.EdDSA,
	"ES256": jwt.ES256,
	"ES384": jwt.ES384,
	"ES512": jwt.ES512,
	// "HS256": jwt.HS256,
	// "HS384": jwt.HS384,
	// "HS512": jwt.HS512,
	// "RS256": jwt.RS256,
	// "RS384": jwt.RS384,
	// "RS512": jwt.RS512,
	// "PS256": jwt.PS256,
	// "PS384": jwt.PS384,
	// "PS512": jwt.PS512,
}

type SignAlg string

const (
	EdDSA SignAlg = "EdDSA"
	ES256 SignAlg = "ES256"
)

func (s SignAlg) Alg() jwt.Alg {
	return SignAlgs[s]
}
func (s SignAlg) Ensure() SignAlg {
	if _, ok := SignAlgs[s]; !ok {
		panic(errors.New("Not support signature algorithm: " + string(s)))
	}
	return s
}
func (s SignAlg) ParsePrivateKey(privateKey string) (interface{}, error) {
	if strings.HasPrefix(string(s), "HS") {
		return []byte(privateKey), nil
	}
	if s == "EdDSA" {
		return jwt.ParsePrivateKeyEdDSA([]byte(addPrefixPrivateKey(privateKey)))
	}
	if strings.HasPrefix(string(s), "ES") {
		return jwt.ParsePrivateKeyECDSA([]byte(addPrefixPrivateKey(privateKey)))
	}
	if strings.HasPrefix(string(s), "RS") || strings.HasPrefix(string(s), "PS") {
		return jwt.ParsePrivateKeyRSA([]byte(privateKey))
	}
	return nil, errors.New("Not support for such signature algorithm:" + string(s))
}

func (s SignAlg) ParsePublicKey(publicKey string) (interface{}, error) {
	if strings.HasPrefix(string(s), "HS") {
		return []byte(publicKey), nil
	}
	if s == "EdDSA" {
		return jwt.ParsePublicKeyEdDSA([]byte(addPrefixPublicKey(publicKey)))
	}
	if strings.HasPrefix(string(s), "ES") {
		return jwt.ParsePublicKeyECDSA([]byte(addPrefixPublicKey(publicKey)))
	}
	if strings.HasPrefix(string(s), "RS") || strings.HasPrefix(string(s), "PS") {
		return jwt.ParsePublicKeyRSA([]byte(publicKey))
	}
	return nil, errors.New("Not support for such signature algorithm:" + string(s))
}

func addPrefixPrivateKey(key string) string {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "---") {
		return "-----BEGIN PRIVATE KEY-----\n" + key + "\n-----END PRIVATE KEY-----"
	}
	return key
}
func addPrefixPublicKey(key string) string {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "---") {
		return "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"
	}
	return key
}
