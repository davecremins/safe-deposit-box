package keymgt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// DerivedKeySize is the size in bytes of keys produced by DeriveKey (256 bits).
	DerivedKeySize = 32
	// SaltSize is the size in bytes of the random salt used for key derivation.
	SaltSize = 16

	// Upper bounds accepted when deriving a key from untrusted parameters
	// (e.g. read from a file header). They stop a crafted file from making
	// the tool allocate unbounded memory or spin forever.
	maxTime    = 64
	maxMemory  = 4 * 1024 * 1024 // KiB, i.e. 4 GiB
	minMemory  = 8 * 1024        // KiB, i.e. 8 MiB
	maxThreads = 64
)

// KDFParams are the Argon2id cost parameters.
type KDFParams struct {
	Time    uint32 // number of passes over memory
	Memory  uint32 // memory in KiB
	Threads uint8  // degree of parallelism
}

// DefaultKDFParams follow the second recommended option of RFC 9106
// (t=3, m=64 MiB, p=4), which suits interactive use on commodity hardware.
var DefaultKDFParams = KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// ErrEmptyPassphrase is returned when an empty passphrase is supplied.
var ErrEmptyPassphrase = errors.New("passphrase must not be empty")

// Validate checks the parameters are within sane bounds.
func (p KDFParams) Validate() error {
	switch {
	case p.Time < 1 || p.Time > maxTime:
		return fmt.Errorf("argon2id time cost %d out of range [1, %d]", p.Time, maxTime)
	case p.Memory < minMemory || p.Memory > maxMemory:
		return fmt.Errorf("argon2id memory %d KiB out of range [%d, %d]", p.Memory, minMemory, maxMemory)
	case p.Threads < 1 || p.Threads > maxThreads:
		return fmt.Errorf("argon2id threads %d out of range [1, %d]", p.Threads, maxThreads)
	}
	return nil
}

// NewSalt returns SaltSize bytes from the system CSPRNG.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey stretches a passphrase into a 256-bit key using Argon2id.
func DeriveKey(passphrase, salt []byte, p KDFParams) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes, got %d", SaltSize, len(salt))
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, DerivedKeySize), nil
}

// Wipe overwrites b with zeros. It is a best-effort measure to shorten the
// lifetime of key material in memory.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
