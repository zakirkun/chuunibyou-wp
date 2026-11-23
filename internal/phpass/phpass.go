// Package phpass is a faithful Go port of the WordPress PasswordHash class
// (portable "$P$" hashes), ported from wordpress-develop/src/wp-includes/class-phpass.php.
// Needed to forge valid user_pass values for privilege-escalation payloads.
package phpass

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"strings"
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Hash produces a portable phpass hash ($P$) for password, using WP's
// default iteration count (log2=8 -> 8192 rounds).
func Hash(password string) (string, error) {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	setting := "$P$" + string(itoa64[8+5]) + encode64(random, 6)
	out, err := CryptPrivate(password, setting)
	if err != nil {
		return "", err
	}
	if len(out) != 34 {
		return "", errors.New("phpass: unexpected hash length")
	}
	return out, nil
}

// CheckPassword verifies password against a stored $P$/$H$ hash.
func CheckPassword(password, stored string) bool {
	got, err := CryptPrivate(password, stored)
	if err != nil {
		return false
	}
	return got == stored
}

// CryptPrivate ports PasswordHash::crypt_private.
func CryptPrivate(password, setting string) (string, error) {
	if len(setting) < 12 {
		return "", errors.New("phpass: setting too short")
	}
	if setting[:2] == "*0" {
		return "*1", nil
	}
	if setting[:2] == "*1" {
		return "*0", nil
	}
	id := setting[:3]
	if id != "$P$" && id != "$H$" {
		return "", errors.New("phpass: unsupported hash id")
	}
	countLog2 := strings.IndexByte(itoa64, setting[3])
	if countLog2 < 7 || countLog2 > 30 {
		return "", errors.New("phpass: bad iteration char")
	}
	count := 1 << uint(countLog2)
	salt := setting[4:12]

	sum := md5.Sum([]byte(salt + password))
	hash := sum[:]
	for i := 0; i < count; i++ {
		buf := make([]byte, 0, len(hash)+len(password))
		buf = append(buf, hash...)
		buf = append(buf, password...)
		sum = md5.Sum(buf)
		hash = sum[:]
	}
	return setting[:12] + encode64(hash, 16), nil
}

// encode64 ports PasswordHash::encode64 exactly, including the post-compare
// increments inside the break conditions.
func encode64(input []byte, count int) string {
	var out strings.Builder
	out.Grow(24)
	i := 0
	for {
		value := int(input[i])
		i++
		out.WriteByte(itoa64[value&0x3f])
		if i < count {
			value |= int(input[i]) << 8
		}
		out.WriteByte(itoa64[(value>>6)&0x3f])
		gt := i >= count
		i++
		if gt {
			break
		}
		if i < count {
			value |= int(input[i]) << 16
		}
		out.WriteByte(itoa64[(value>>12)&0x3f])
		gt = i >= count
		i++
		if gt {
			break
		}
		out.WriteByte(itoa64[(value>>18)&0x3f])
		if i >= count {
			break
		}
	}
	return out.String()
}
