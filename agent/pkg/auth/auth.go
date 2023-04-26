package auth

import (
	"errors"

	"github.com/lucheng0127/gsec/agent/pkg/cipher"
)

type Auth interface {
	Validate([]byte) (bool, error)
}

type UserAuth struct {
	username string
	psk      string
}

func (ua *UserAuth) Validate(rawData []byte) (bool, error) {
	c, err := cipher.NewAESCipher(ua.psk)
	if err != nil {
		return false, err
	}

	data, err := c.Decrypt(rawData)
	if err != nil {
		return false, err
	}

	if string(data[:]) != ua.username {
		return false, errors.New("invalid auth data")
	}
	return true, nil
}

func NewUserAuth(username, psk string) Auth {
	return &UserAuth{username: username, psk: psk}
}
