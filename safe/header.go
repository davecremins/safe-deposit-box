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
	magic          = "SDB"                                               // identifies SDB files
	formatVersion  = 1                                                   // bumped on incompatible changes
	kdfArgon2id    = 1                                                   // KDF identifier for Argon2id
	dataKeySize    = chacha20poly1305.KeySize                            // 32-byte per-file data key
	wrapNonceSize  = chacha20poly1305.NonceSizeX                         // 24-byte XChaCha20 nonce
	wrappedKeySize = dataKeySize + chacha20poly1305.Overhead             // encrypted key + 16-byte tag
	aadSize        = 3 + 1 + 1 + 4 + 4 + 1 + km.SaltSize + wrapNonceSize // authenticated prefix
	headerSize     = aadSize + wrappedKeySize                            // 102 bytes in total
)

// header is the in-memory form of the file header. It holds everything
// needed to recover the data key from a passphrase; none of it is secret
// without the passphrase.
type header struct {
	kdf        km.KDFParams // Argon2id cost parameters used for this file
	salt       []byte       // random Argon2id salt, unique per file
	wrapNonce  []byte       // random nonce used to wrap the data key
	wrappedKey []byte       // data key encrypted under the passphrase key
}

// newHeader creates the header for a new file:
//
//  1. pick a random salt, wrap nonce and 256-bit data key;
//  2. derive the key-encryption key (KEK) from the passphrase with Argon2id;
//  3. encrypt ("wrap") the data key with the KEK using XChaCha20-Poly1305,
//     authenticating the rest of the header as associated data.
//
// It returns the header and the plaintext data key, which the caller uses
// to encrypt the payload and should wipe afterwards. The KEK is wiped here.
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

// aad serialises the header fields that precede the wrapped key, i.e. the
// first 54 bytes of the file. They are used as associated data when the data
// key is wrapped, so changing any of them makes unwrapping fail.
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

// marshal returns the complete 102-byte on-disk header.
func (h *header) marshal() []byte {
	return append(h.aad(), h.wrappedKey...)
}

// readHeader reads and parses the 102-byte header from r. It checks the
// magic bytes, format version and KDF identifier, and rejects out-of-range
// Argon2id parameters before any expensive key derivation is attempted, so a
// crafted file cannot make the tool allocate huge amounts of memory. It does
// not need the passphrase; authenticity is checked later by unwrap.
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

// unwrap re-derives the key-encryption key from passphrase using the salt
// and parameters stored in the header, then decrypts the data key. A wrong
// passphrase and a modified header are indistinguishable by design: both
// fail authentication and return ErrWrongPassphrase.
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
