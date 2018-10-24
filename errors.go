package aspnetpass

import "errors"

// List of errors
var (
	ErrBadSize      = errors.New("aspnetpass: bad size")
	ErrBadSaltLen   = errors.New("aspnetpass: bad salt length")
	ErrBadKeyLen    = errors.New("aspnetpass: bad key length")
	ErrBadVersion   = errors.New("aspnetpass: bad version")
	ErrBadAlgorithm = errors.New("aspnetpass: bad algorithm")
	ErrBadIteration = errors.New("aspnetpass: bad iteration")
)
