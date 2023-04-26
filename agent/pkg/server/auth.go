package server

import (
	"fmt"

	"github.com/lucheng0127/gsec/agent/pkg/auth"
	"github.com/lucheng0127/gsec/agent/pkg/cipher"
)

func handle_auth(userbook map[string]string, username string, authData []byte) error {
	psk, ok := userbook[username]
	if !ok {
		return fmt.Errorf("user [%s] not exist", username)
	}

	ua := auth.NewUserAuth(username, psk)
	pass, err := ua.Validate(authData)
	if err != nil {
		return fmt.Errorf("user [%s] auth failed: %s", username, err.Error())
	}
	if !pass {
		return fmt.Errorf("user [%s] auth failed", username)
	}
	return nil
}

func generate_auth_payload(username, psk string) ([]byte, error) {
	c, err := cipher.NewAESCipher(psk)
	if err != nil {
		return make([]byte, 0), fmt.Errorf("generate user [%s] auth payload failed: %s", username, err.Error())
	}

	payload, err := c.Encrypt([]byte(username))
	if err != nil {
		return make([]byte, 0), fmt.Errorf("encrypt user [%s] info failed: %s", username, err.Error())
	}
	return payload, nil
}
