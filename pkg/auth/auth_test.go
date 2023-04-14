package auth

import (
	"errors"
	"reflect"
	"testing"

	"bou.ke/monkey"
	"github.com/golang/mock/gomock"
	"github.com/lucheng0127/gsec/mocks/mock_cipher"
	"github.com/lucheng0127/gsec/pkg/cipher"
)

func TestUserAuth_Validate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockCipher := mock_cipher.NewMockCipher(ctrl)

	type fields struct {
		username string
		psk      string
	}
	type args struct {
		rawData []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "ERR: new ciper err",
			fields:  fields{username: "lucheng", psk: "0123456789abcedf"},
			args:    args{rawData: []byte("lucheng")},
			want:    false,
			wantErr: true,
		},
		{
			name:    "ERR: decrypt err",
			fields:  fields{username: "lucheng", psk: "0123456789abcedf"},
			args:    args{rawData: []byte("lucheng")},
			want:    false,
			wantErr: true,
		},
		{
			name:    "ERR: not match",
			fields:  fields{username: "lucheng", psk: "0123456789abcedf"},
			args:    args{rawData: []byte("lucheng")},
			want:    false,
			wantErr: true,
		},
		{
			name:    "auth succeed",
			fields:  fields{username: "lucheng", psk: "0123456789abcedf"},
			args:    args{rawData: []byte("lucheng")},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "ERR: new ciper err" {
				monkey.Patch(cipher.NewAESCipher, func(key string) (cipher.Cipher, error) {
					return nil, errors.New("new aes cipher err")
				})
			} else {
				monkey.Patch(cipher.NewAESCipher, func(key string) (cipher.Cipher, error) {
					return mockCipher, nil
				})

				if tt.name == "ERR: decrypt err" {
					mockCipher.EXPECT().Decrypt(tt.args.rawData).Return(make([]byte, 0), errors.New("decrypt err"))
				}
				if tt.name == "ERR: not match" {
					mockCipher.EXPECT().Decrypt(tt.args.rawData).Return([]byte("shawnlu"), nil)
				}
				if tt.name == "auth succeed" {
					mockCipher.EXPECT().Decrypt(tt.args.rawData).Return([]byte("lucheng"), nil)
				}
			}

			ua := &UserAuth{
				username: tt.fields.username,
				psk:      tt.fields.psk,
			}
			got, err := ua.Validate(tt.args.rawData)
			if (err != nil) != tt.wantErr {
				t.Errorf("UserAuth.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("UserAuth.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewUserAuth(t *testing.T) {
	type args struct {
		username string
		psk      string
	}
	tests := []struct {
		name string
		args args
		want Auth
	}{
		{
			name: "ok",
			args: args{username: "lucheng", psk: "0123456789abcdef"},
			want: &UserAuth{username: "lucheng", psk: "0123456789abcdef"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewUserAuth(tt.args.username, tt.args.psk); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewUserAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}
