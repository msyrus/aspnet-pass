package aspnetpass

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"math/rand"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Hasher is the interface that wraps the basic Hash method
type Hasher interface {
	Hash(string) (string, error)
}

// SaltGenerator is the interface that generates salt
//
// Read generates len(p) bytes
// it should return the len(p) and a nil error
// otherwise 0, error
type SaltGenerator interface {
	Read(p []byte) (int, error)
}

// hasherV2 implements Hasher interface
// it is the implementation of .Net PasswordHasher V2
type hasherV2 struct {
	sg SaltGenerator
}

// NewHasherV2 returns a new HasherV2 instance
func NewHasherV2(sg SaltGenerator) (Hasher, error) {
	return &hasherV2{
		sg: sg,
	}, nil
}

// Hash hashes a password into .Net PaswordHasher V2 string
func (h *hasherV2) Hash(pass string) (string, error) {
	salt := make([]byte, 128/8)
	if _, err := h.sg.Read(salt); err != nil {
		return "", err
	}
	return genhash(pass, []byte{0x00}, salt, 1000, 256/8, sha1.New), nil
}

// hasherV3 implements Hasher interface
// it is the implementation of .Net PasswordHasher V3
type hasherV3 struct {
	sg               SaltGenerator
	iter, klen, slen int
	algo             string
}

// NewHasherV3 returns a new HasherV3 instance with
// salt length of saltLen bytes, minimum 16 byte
// key length of keyLen bytes, minimum 32 byte
// algo should be one of the sha1, sha256 or sha512
func NewHasherV3(iter, saltLen, keyLen int, algo string, sg SaltGenerator) (Hasher, error) {
	if iter < 1 {
		return nil, ErrBadIteration
	}
	if saltLen*8 < 128 {
		return nil, ErrBadSaltLen
	}
	if keyLen*8 < 256 {
		return nil, ErrBadKeyLen
	}
	if algo != AlgoSha1 &&
		algo != AlgoSha256 &&
		algo != AlgoSha512 {
		return nil, ErrBadAlgorithm
	}
	return &hasherV3{
		sg:   sg,
		iter: iter,
		klen: keyLen,
		slen: saltLen,
		algo: algo,
	}, nil
}

// Hash hashes a password into .Net PaswordHasher V3 string
func (h *hasherV3) Hash(pass string) (string, error) {
	salt := make([]byte, h.slen)
	if _, err := h.sg.Read(salt); err != nil {
		return "", err
	}

	cfg := make([]byte, 13)
	cfg[0] = 0x01

	alg := sha1.New
	switch h.algo {
	case AlgoSha256:
		alg = sha256.New
		binary.BigEndian.PutUint32(cfg[1:5], 1)
	case AlgoSha512:
		alg = sha512.New
		binary.BigEndian.PutUint32(cfg[1:5], 2)
	}
	binary.BigEndian.PutUint32(cfg[5:9], uint32(h.iter))
	binary.BigEndian.PutUint32(cfg[9:13], uint32(h.slen))

	return genhash(pass, cfg, salt, h.iter, h.klen, alg), nil
}

func genhash(pass string, pre []byte, salt []byte, iter, klen int, h func() hash.Hash) string {
	byts := append(pre, salt...)

	key := pbkdf2.Key([]byte(pass), salt, iter, klen, h)
	byts = append(byts, key...)

	return base64.StdEncoding.EncodeToString(byts)
}

// DefaultHasher is the .Net password hasher v3 with default configuration
var DefaultHasher Hasher = &hasherV3{
	sg:   rand.New(rand.NewSource(time.Now().UnixNano())),
	iter: 10000,
	slen: 16,
	klen: 32,
	algo: AlgoSha256,
}

// Hash hashes the given pass using the DefaultHasher
func Hash(pass string) (string, error) {
	return DefaultHasher.Hash(pass)
}
