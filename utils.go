package jwts

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func UUID(length ...int) string {
	l := 32
	if len(length) > 0 {
		l = length[0]
	}
	b := make([]byte, l)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
func Md5(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func CreateRefreshTokenVerfication(encryptedPassword, uid, roles string, exp int64) string {
	return Md5(encryptedPassword + uid + roles + strconv.FormatInt(exp, 10))
}
