// Package safe implements the Safe Deposit Box encrypted file format.
//
// Data is protected with envelope encryption: every file gets a fresh random
// 256-bit data key that encrypts the payload with ChaCha20-Poly1305 in
// fixed-size authenticated chunks. The data key itself is wrapped with
// XChaCha20-Poly1305 under a key-encryption key derived from the user's
// passphrase with Argon2id. Only the wrapped key is stored; neither the
// passphrase nor any usable key ever touches the disk.
package safe

import (
	"errors"
	"io"

	km "gitlab.com/davecremins/safe-deposit-box/key-mgt"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrNotSDB means the input does not start with the SDB magic bytes.
	ErrNotSDB = errors.New("input is not a safe deposit box file")
	// ErrUnsupportedVersion means the file uses an unknown format or KDF.
	ErrUnsupportedVersion = errors.New("unsupported safe deposit box format")
	// ErrWrongPassphrase means the data key could not be unwrapped: either
	// the passphrase is wrong or the header has been modified.
	ErrWrongPassphrase = errors.New("incorrect passphrase or tampered header")
	// ErrTruncated means the input ended unexpectedly.
	ErrTruncated = errors.New("encrypted data is truncated")
	// ErrCorrupt means authentication of the encrypted data failed.
	ErrCorrupt = errors.New("encrypted data is corrupt or has been tampered with")
)

// Options tune encryption. The zero value uses secure defaults.
type Options struct {
	// KDF overrides the Argon2id cost parameters when non-zero.
	KDF km.KDFParams
}

// Encrypt reads plaintext from src and writes an SDB file to dst.
func Encrypt(dst io.Writer, src io.Reader, passphrase []byte, opts Options) error {
	params := opts.KDF
	if params == (km.KDFParams{}) {
		params = km.DefaultKDFParams
	}
	h, dataKey, err := newHeader(passphrase, params)
	if err != nil {
		return err
	}
	defer km.Wipe(dataKey)

	aead, err := chacha20poly1305.New(dataKey)
	if err != nil {
		return err
	}
	if _, err := dst.Write(h.marshal()); err != nil {
		return err
	}
	return encryptStream(dst, src, aead)
}

// Decrypt reads an SDB file from src and writes the plaintext to dst.
//
// Plaintext is written chunk by chunk as each one is authenticated. If an
// error is returned, data already written to dst must be discarded because
// the remainder of the stream could not be verified.
func Decrypt(dst io.Writer, src io.Reader, passphrase []byte) error {
	h, err := readHeader(src)
	if err != nil {
		return err
	}
	dataKey, err := h.unwrap(passphrase)
	if err != nil {
		return err
	}
	defer km.Wipe(dataKey)

	aead, err := chacha20poly1305.New(dataKey)
	if err != nil {
		return err
	}
	return decryptStream(dst, src, aead)
}
