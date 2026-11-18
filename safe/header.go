package safe

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	km "gitlab.com/davecremins/safe-deposit-box/key-mgt"
	"golang.org/x/crypto/chacha20poly1305"
)

// File header layout (big-endian, 102 bytes):
//
//	offset size  field
//	0      3     magic "SDB"
//	3      1     format version (1)
//	4      1     KDF identifier (1 = Argon2id)
//	5      4     Argon2id time cost
//	9      4     Argon2id memory (KiB)
//	13     1     Argon2id threads
//	14     16    Argon2id salt
//	30     24    XChaCha20-Poly1305 nonce used to wrap the data key
//	54     48    wrapped data key (32-byte key + 16-byte tag)
//
// Bytes [0, 54) are the additional authenticated data of the key wrap, so
// any modification of the header makes unwrapping fail.
const (
	magic          = "SDB"
	formatVersion  = 1
	kdfArgon2id    = 1
	dataKeySize    = chacha20poly1305.KeySize
	wrapNonceSize  = chacha20poly1305.NonceSizeX
	wrappedKeySize = dataKeySize + chacha20poly1305.Overhead
	aadSize        = 3 + 1 + 1 + 4 + 4 + 1 + km.SaltSize + wrapNonceSize
	headerSize     = aadSize + wrappedKeySize
)

type header struct {
	kdf        km.KDFParams
	salt       []byte
	wrapNonce  []byte
	wrappedKey []byte
}

// newHeader generates a fresh data key and wraps it under a key derived
// from passphrase. The caller owns (and should wipe) the returned data key.
func newHeader(passphrase []byte, params km.KDFParams) (*header, []byte, error) {
	salt, err := km.NewSalt()
	if err != nil {
		return nil, nil, err
	}
	h := &header{kdf: params, salt: salt, wrapNonce: make([]byte, wrapNonceSize)}
	if _, err := io.ReadFull(rand.Reader, h.wrapNonce); err != nil {
		return nil, nil, err
	}
	dataKey := make([]byte, dataKeySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, nil, err
	}

	kek, err := km.DeriveKey(passphrase, salt, params)
	if err != nil {
		return nil, nil, err
	}
	defer km.Wipe(kek)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, nil, err
	}
	h.wrappedKey = aead.Seal(nil, h.wrapNonce, dataKey, h.aad())
	return h, dataKey, nil
}

// aad serialises the authenticated (non-secret) part of the header.
func (h *header) aad() []byte {
	var b bytes.Buffer
	b.Grow(aadSize)
	b.WriteString(magic)
	b.WriteByte(formatVersion)
	b.WriteByte(kdfArgon2id)
	_ = binary.Write(&b, binary.BigEndian, h.kdf.Time)
	_ = binary.Write(&b, binary.BigEndian, h.kdf.Memory)
	b.WriteByte(h.kdf.Threads)
	b.Write(h.salt)
	b.Write(h.wrapNonce)
	return b.Bytes()
}

func (h *header) marshal() []byte {
	return append(h.aad(), h.wrappedKey...)
}

func readHeader(r io.Reader) (*header, error) {
	buf := make([]byte, headerSize)
	n, err := io.ReadFull(r, buf)
	if n < len(magic) || string(buf[:len(magic)]) != magic {
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return nil, ErrNotSDB
	}
	if err == io.ErrUnexpectedEOF {
		return nil, ErrTruncated
	} else if err != nil {
		return nil, err
	}
	if buf[3] != formatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, buf[3])
	}
	if buf[4] != kdfArgon2id {
		return nil, fmt.Errorf("%w: unknown KDF %d", ErrUnsupportedVersion, buf[4])
	}
	h := &header{
		kdf: km.KDFParams{
			Time:    binary.BigEndian.Uint32(buf[5:9]),
			Memory:  binary.BigEndian.Uint32(buf[9:13]),
			Threads: buf[13],
		},
	}
	off := 14
	h.salt = buf[off : off+km.SaltSize]
	off += km.SaltSize
	h.wrapNonce = buf[off : off+wrapNonceSize]
	off += wrapNonceSize
	h.wrappedKey = buf[off:]
	if err := h.kdf.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return h, nil
}

// unwrap derives the key-encryption key and recovers the data key.
func (h *header) unwrap(passphrase []byte) ([]byte, error) {
	kek, err := km.DeriveKey(passphrase, h.salt, h.kdf)
	if err != nil {
		return nil, err
	}
	defer km.Wipe(kek)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	dataKey, err := aead.Open(nil, h.wrapNonce, h.wrappedKey, h.aad())
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return dataKey, nil
}
