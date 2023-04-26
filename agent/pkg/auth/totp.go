package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

type TOTPAuth struct {
	username string
	secret   string
}

func (ta *TOTPAuth) Validate(data []byte) (bool, error) {
	code, err := GenerateCode(ta.secret)
	if err != nil {
		return false, err
	}

	if string(data) != code {
		return false, errors.New("wrong one time passwd")
	}

	return true, nil
}

func GenerateCode(secret string) (string, error) {
	// TOTP algorithm refer to https://datatracker.ietf.org/doc/html/rfc6238
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	// Get hash of current unix time with window 30
	counter := time.Now().Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	// XXX: Create a sha1 hash, use write to add data, and use sum to count hash
	hs := hmac.New(sha1.New, secretBytes)
	hs.Write(buf)
	sum := hs.Sum(nil)

	// Get the offset from the last 4 bits
	offset := int(sum[len(sum)-1] & 0x0f)

	// Get the dynamic data of totp
	code := (uint32(sum[offset]&0x7F) << 24) +
		(uint32(sum[offset+1]) << 16) +
		(uint32(sum[offset+2]) << 8) +
		(uint32(sum[offset+3]))

	// Use the last 6 numbers as the totp
	totp := int(int(code) % int(math.Pow10(6)))
	return fmt.Sprintf("%06d", totp), nil
}

func NewTOTPAuth(username, secret string) Auth {
	return &TOTPAuth{username: username, secret: secret}
}
