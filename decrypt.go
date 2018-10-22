package aspnetpass

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"

	"golang.org/x/crypto/pbkdf2"
)

// List of supported algorithms
const (
	AlgoSha1   = "sha1"
	AlgoSha256 = "sha256"
	AlgoSha512 = "sha512"
)

// Verify verifies if a password matches to a .Net password hash string
func Verify(pass, hash string) (bool, error) {
	_, key, salt, iter, alg, err := Decrypt(hash)
	if err != nil {
		return false, err
	}

	h := sha1.New
	switch alg {
	case AlgoSha256:
		h = sha256.New
	case AlgoSha512:
		h = sha512.New
	}

	k := pbkdf2.Key([]byte(pass), salt, iter, len(key), h)

	return bytes.Equal(key, k), nil
}

// Decrypt decrypts .Net password hash string
func Decrypt(hstr string) (ver string, key, salt []byte, iter int, alg string, err error) {
	var klen, slen int

	byts, err := base64.StdEncoding.DecodeString(hstr)
	if err != nil {
		return
	}

	switch byts[0] {
	case 0x00:
		ver = "2"
	case 0x01:
		ver = "3"
	default:
		err = ErrBadVersion
		return
	}

	if ver == "2" {
		klen = 256 / 8
		slen = 128 / 8
		if len(byts) != (1 + klen + slen) {
			err = ErrBadSize
			return
		}
		alg = AlgoSha1
		iter = 1000
		salt = byts[1 : 1+slen]
		key = byts[1+slen:]
		return
	}

	switch binary.BigEndian.Uint32(byts[1:5]) {
	case 0:
		alg = AlgoSha1
	case 1:
		alg = AlgoSha256
	case 2:
		alg = AlgoSha512
	default:
		err = ErrBadAlgorithm
		return
	}

	iter = int(binary.BigEndian.Uint32(byts[5:9]))
	if iter < 1 {
		err = ErrBadIteration
		return
	}

	slen = int(binary.BigEndian.Uint32(byts[9:13]))
	if slen < 128/8 {
		err = ErrBadSaltLen
		return
	}

	klen = len(byts) - (13 + slen)
	if klen < 128/8 {
		err = ErrBadKeyLen
	}

	salt = byts[13 : 13+slen]

	key = byts[13+slen:]

	return
}
