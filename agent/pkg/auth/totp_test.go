package auth

import (
	"testing"
	"time"

	"bou.ke/monkey"
)

func TestTOTPAuth_Validate(t *testing.T) {
	timeNow := time.Now()
	secret := "ONSWG4TFOQ======"
	monkey.Patch(time.Now, func() time.Time {
		return timeNow
	})
	totp, _ := GenerateCode(secret)
	totpBytes := []byte(totp)

	//  timeAfter29, _ := time.ParseDuration("29s")
	//  timeBefore29, _ := time.ParseDuration("-29s")
	//	timeAfter30, _ := time.ParseDuration("30s")
	//	timeBeforce30, _ := time.ParseDuration("-30s")

	type fields struct {
		username string
		secret   string
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "secret error",
			fields: fields{
				username: "lucheng",
				secret:   "d3JvbmcgZW5jb2Rl",
			},
			args: args{
				data: []byte("anything"),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ok 0",
			fields: fields{
				username: "lucheng",
				secret:   secret,
			},
			args: args{
				data: totpBytes,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "err not match",
			fields: fields{
				username: "anybody",
				secret:   secret,
			},
			args: args{
				data: []byte("wrong code"),
			},
			want:    false,
			wantErr: true,
		},
		//{
		//	name: "ok +29",
		//	fields: fields{
		//		username: "lucheng",
		//		secret:   secret,
		//	},
		//	args: args{
		//		data: totpBytes,
		//	},
		//	want:    true,
		//	wantErr: false,
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//if tt.name == "ok +29" {
			//	monkey.Patch(time.Now, func() time.Time {
			//		return timeNow.Add(timeBefore29)
			//	})
			//}

			ta := NewTOTPAuth(tt.fields.username, tt.fields.secret)
			got, err := ta.Validate(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("TOTPAuth.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TOTPAuth.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}
