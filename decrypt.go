package aspnetpass

import (
	"encoding/base64"
	"encoding/binary"
)

// Decrypt decrypts .Net password hash string
func Decrypt(str string) (ver string, key, salt []byte, iter int, alg string, err error) {
	var klen, slen int

	byts, err := base64.StdEncoding.DecodeString(str)
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
		alg = "sha1"
		iter = 1000
		salt = byts[1 : 1+slen]
		key = byts[1+slen:]
		return
	}

	switch binary.BigEndian.Uint32(byts[1:5]) {
	case 0:
		alg = "sha1"
	case 1:
		alg = "sha256"
	case 2:
		alg = "sha512"
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
