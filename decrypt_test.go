package aspnetpass

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVerify(t *testing.T) {
	type args struct {
		pass string
		hash string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			args: args{
				pass: "Hello World",
				hash: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw==",
			},
			want: true,
		},
		{
			args: args{
				pass: "HelloWorld",
				hash: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw==",
			},
			want: false,
		},
		{
			args: args{
				pass: "",
				hash: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw==",
			},
			want: false,
		},
		{
			args: args{
				pass: "Hello World",
				hash: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw=",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.pass, tt.args.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("566298380357b9ae22ce8141a107bc88b46774efba50c3043cd8de37a801948f")
	salt, _ := hex.DecodeString("6da8173f0087b1d5e274fbf763123d69")
	type args struct {
		str string
	}
	tests := []struct {
		name     string
		args     args
		wantVer  string
		wantKey  []byte
		wantSalt []byte
		wantIter int
		wantAlg  string
		wantErr  bool
	}{
		{
			args: args{
				str: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw==",
			},
			wantVer:  "3",
			wantKey:  key,
			wantSalt: salt,
			wantIter: 10000,
			wantAlg:  algoSha256,
		},
		{
			args: args{
				str: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw=",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVer, gotKey, gotSalt, gotIter, gotAlg, err := Decrypt(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotVer != tt.wantVer {
				t.Errorf("Decrypt() gotVer = %v, want %v", gotVer, tt.wantVer)
			}
			if !bytes.Equal(gotKey, tt.wantKey) {
				t.Errorf("Decrypt() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
			if !bytes.Equal(gotSalt, tt.wantSalt) {
				t.Errorf("Decrypt() gotSalt = %v, want %v", gotSalt, tt.wantSalt)
			}
			if gotIter != tt.wantIter {
				t.Errorf("Decrypt() gotIter = %v, want %v", gotIter, tt.wantIter)
			}
			if gotAlg != tt.wantAlg {
				t.Errorf("Decrypt() gotAlg = %v, want %v", gotAlg, tt.wantAlg)
			}
		})
	}
}
