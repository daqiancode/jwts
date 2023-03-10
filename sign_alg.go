package jwts

import (
	"errors"
	"strings"

	"github.com/kataras/iris/v12/middleware/jwt"
	kjwt "github.com/kataras/jwt"
)

var SignAlgs map[SignAlg]jwt.Alg = map[SignAlg]jwt.Alg{
	"EdDSA": jwt.EdDSA,
	"HS256": jwt.HS256,
	"HS384": jwt.HS384,
	"HS512": jwt.HS512,
	"RS256": jwt.RS256,
	"RS384": jwt.RS384,
	"RS512": jwt.RS512,
	"ES256": jwt.ES256,
	"ES384": jwt.ES384,
	"ES512": jwt.ES512,
	"PS256": jwt.PS256,
	"PS384": jwt.PS384,
	"PS512": jwt.PS512,
}

type SignAlg string

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
		return jwt.ParsePrivateKeyEdDSA([]byte(processPrivateKey(privateKey)))
	}
	if strings.HasPrefix(string(s), "ES") {
		return jwt.ParsePrivateKeyECDSA([]byte(processPrivateKey(privateKey)))
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
		return jwt.ParsePublicKeyEdDSA([]byte(processPublicKey(publicKey)))
	}
	if strings.HasPrefix(string(s), "ES") {
		return jwt.ParsePublicKeyECDSA([]byte(processPublicKey(publicKey)))
	}
	if strings.HasPrefix(string(s), "RS") || strings.HasPrefix(string(s), "PS") {
		return jwt.ParsePublicKeyRSA([]byte(publicKey))
	}
	return nil, errors.New("Not support for such signature algorithm:" + string(s))
}

func processPrivateKey(privateKey string) string {
	privateKey = strings.TrimSpace(privateKey)
	if !strings.HasPrefix(privateKey, "---") {
		return "-----BEGIN PRIVATE KEY-----\n" + privateKey + "\n-----END PRIVATE KEY-----"
	}
	return privateKey
}
func processPublicKey(privateKey string) string {
	privateKey = strings.TrimSpace(privateKey)
	if !strings.HasPrefix(privateKey, "---") {
		return "-----BEGIN PUBLIC KEY-----\n" + privateKey + "\n-----END PUBLIC KEY-----"
	}
	return privateKey
}

func GenerateEdDSAKeyPair() (string, string, error) {
	pub, pri, err := kjwt.GenerateEdDSA()
	return string(pub), string(pri), err
}
