package aspnetpass

import "errors"

// List of errors
var (
	ErrBadSize      = errors.New("bad size")
	ErrBadSaltLen   = errors.New("bad salt length")
	ErrBadKeyLen    = errors.New("bad key length")
	ErrBadVersion   = errors.New("bad version")
	ErrBadAlgorithm = errors.New("bad algorithm")
	ErrBadIteration = errors.New("bad iteration")
)
