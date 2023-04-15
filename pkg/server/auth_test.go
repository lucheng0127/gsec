package server

import (
	"errors"
	"reflect"
	"testing"

	"bou.ke/monkey"
	"github.com/golang/mock/gomock"
	"github.com/lucheng0127/gsec/mocks"
	"github.com/lucheng0127/gsec/mocks/mock_cipher"
	"github.com/lucheng0127/gsec/pkg/auth"
	"github.com/lucheng0127/gsec/pkg/cipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AuthTestSuite struct {
	suite.Suite
	userbook map[string]string
	ctrl     *gomock.Controller
}

func (s *AuthTestSuite) SetupTest() {
	s.userbook = make(map[string]string)
	s.userbook["lucheng"] = "0123456789abcdef"
	ctrl := gomock.NewController(s.T())
	s.ctrl = ctrl
}

func (s *AuthTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *AuthTestSuite) TestHandle() {
	mock_auth := mocks.NewMockAuth(s.ctrl)
	monkey.Patch(auth.NewUserAuth, func(username, psk string) auth.Auth {
		return mock_auth
	})

	type args struct {
		username string
		autoData []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "user not exist",
			args: args{
				username: "not exist user",
				autoData: make([]byte, 0),
			},
			wantErr: true,
		},
		{
			name: "validate err",
			args: args{
				username: "lucheng",
				autoData: make([]byte, 0),
			},
			wantErr: true,
		},
		{
			name: "validate failed",
			args: args{
				username: "lucheng",
				autoData: make([]byte, 0),
			},
			wantErr: true,
		},
		{
			name: "ok",
			args: args{
				username: "lucheng",
				autoData: make([]byte, 0),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		if tt.name == "validate err" {
			mock_auth.EXPECT().Validate(tt.args.autoData).Return(false, errors.New("vaildate err"))
		}
		if tt.name == "validate failed" {
			mock_auth.EXPECT().Validate(tt.args.autoData).Return(false, nil)
		}
		if tt.name == "ok" {
			mock_auth.EXPECT().Validate(tt.args.autoData).Return(true, nil)
		}

		err := handle_auth(s.userbook, tt.args.username, tt.args.autoData)
		if tt.wantErr {
			assert.NotNil(s.T(), err)
		} else {
			assert.Nil(s.T(), err)
		}
	}
}

func TestAuthTestSuit(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}

func Test_generate_auth_payload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock_cipher := mock_cipher.NewMockCipher(ctrl)

	type args struct {
		username string
		psk      string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "cipher err",
			args: args{
				username: "lucheng",
				psk:      "0123456789abcdef",
			},
			want:    make([]byte, 0),
			wantErr: true,
		},
		{
			name: "encrypt err",
			args: args{
				username: "lucheng",
				psk:      "0123456789abcdef",
			},
			want:    make([]byte, 0),
			wantErr: true,
		},
		{
			name: "ok",
			args: args{
				username: "lucheng",
				psk:      "0123456789abcdef",
			},
			want:    []byte("ok"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "cipher err" {
				monkey.Patch(cipher.NewAESCipher, func(key string) (cipher.Cipher, error) {
					return nil, errors.New("cipher err")
				})
			} else {
				monkey.Patch(cipher.NewAESCipher, func(key string) (cipher.Cipher, error) {
					return mock_cipher, nil
				})
				if tt.name == "encrypt err" {
					mock_cipher.EXPECT().Encrypt([]byte(tt.args.username)).Return(make([]byte, 0), errors.New("encrypt err"))
				}
				if tt.name == "ok" {
					mock_cipher.EXPECT().Encrypt([]byte(tt.args.username)).Return([]byte("ok"), nil)
				}
			}

			got, err := generate_auth_payload(tt.args.username, tt.args.psk)
			if (err != nil) != tt.wantErr {
				t.Errorf("generate_auth_payload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generate_auth_payload() = %v, want %v", got, tt.want)
			}
		})
	}
}
