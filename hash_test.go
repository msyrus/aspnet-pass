package aspnetpass

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/msyrus/aspnet-pass/mock"
	matcher "github.com/msyrus/go/gomock-matcher"
)

func TestNewHasherV2(t *testing.T) {
	buf := &bytes.Buffer{}

	type args struct {
		sg SaltGenerator
	}
	tests := []struct {
		name    string
		args    args
		want    Hasher
		wantErr bool
	}{
		{
			args: args{sg: buf},
			want: &hasherV2{sg: buf},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHasherV2(tt.args.sg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHasherV2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHasherV2() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasherV2_Hash(t *testing.T) {
	s16, _ := hex.DecodeString("6da8173f0087b1d5e274fbf763123d69")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mocksg := mock.NewMockSaltGenerator(ctrl)

	gomock.InOrder(
		mocksg.EXPECT().Read(matcher.And(gomock.AssignableToTypeOf([]byte{}), matcher.Len(16))).SetArg(0, s16).Return(16, nil),
	)

	h, _ := NewHasherV2(mocksg)

	type args struct {
		pass string
	}
	tests := []struct {
		name    string
		h       Hasher
		args    args
		want    string
		wantErr bool
	}{
		{
			h:    h,
			args: args{pass: "Hello World"},
			want: "AG2oFz8Ah7HV4nT792MSPWkwEctaCy65/AG9AryfW+GcDDhfkG3j73oEMy4VwYJ/Kw==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Hash(tt.args.pass)
			if (err != nil) != tt.wantErr {
				t.Errorf("HasherV2.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HasherV2.Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewHasherV3(t *testing.T) {
	type args struct {
		iter    int
		saltLen int
		keyLen  int
		algo    string
		sg      SaltGenerator
	}
	tests := []struct {
		name    string
		args    args
		want    *hasherV3
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHasherV3(tt.args.iter, tt.args.saltLen, tt.args.keyLen, tt.args.algo, tt.args.sg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHasherV3() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHasherV3() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasherV3_Hash(t *testing.T) {
	s16, _ := hex.DecodeString("6da8173f0087b1d5e274fbf763123d69")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mocksg := mock.NewMockSaltGenerator(ctrl)

	gomock.InOrder(
		mocksg.EXPECT().Read(matcher.And(gomock.AssignableToTypeOf([]byte{}), matcher.Len(16))).SetArg(0, s16).Return(16, nil),
	)

	h, _ := NewHasherV3(10000, 16, 32, AlgoSha256, mocksg)

	type args struct {
		pass string
	}
	tests := []struct {
		name    string
		h       Hasher
		args    args
		want    string
		wantErr bool
	}{
		{
			h:    h,
			args: args{pass: "Hello World"},
			want: "AQAAAAEAACcQAAAAEG2oFz8Ah7HV4nT792MSPWlWYpg4A1e5riLOgUGhB7yItGd077pQwwQ82N43qAGUjw==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Hash(tt.args.pass)
			if (err != nil) != tt.wantErr {
				t.Errorf("HasherV3.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HasherV3.Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHash(t *testing.T) {
	strs := []string{}
	for n := 0; n < 10; n++ {
		b := make([]byte, rand.Intn(30))
		rand.Read(b)
		strs = append(strs, string(b))
	}

	type args struct {
		pass string
	}
	type scheme struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}
	tests := []scheme{}

	for _, str := range strs {
		tests = append(tests, scheme{
			args: args{
				pass: str,
			},
			wantLen: 84,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hash(tt.args.pass)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("Hash() = %v, wantlen %v, gotLen %v", got, tt.wantLen, len(got))
			}
		})
	}
}

func BenchmarkHash(b *testing.B) {
	pass := "password"
	for n := 0; n < b.N; n++ {
		Hash(pass)
	}
}
