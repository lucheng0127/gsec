package cipher

import (
	"encoding/hex"
	"reflect"
	"strconv"
	"testing"
)

func TestAESCipher(t *testing.T) {
	hexData, _ := hex.DecodeString("0x130913f")
	ac := NewAESCipher("c05eba661498163be49d589a6d67e1c8")

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "test string",
			data:    []byte("lucheng test"),
			wantErr: false,
		},
		{
			name:    "test hex",
			data:    hexData,
			wantErr: false,
		},
		{
			name:    "test int",
			data:    []byte(strconv.Itoa(19960127)),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodeData, err := ac.Encrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("AESCipher.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			decodeData, err := ac.Decrypt(encodeData)
			if (err != nil) != tt.wantErr {
				t.Errorf("AESCipher.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(decodeData, tt.data) {
				t.Errorf("AESCipher decrypt encrypt data not match")
			}
		})
	}
}
