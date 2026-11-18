package safe

import (
	"bufio"
	"crypto/cipher"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// The payload is split into chunks of chunkSize plaintext bytes, each sealed
// independently with ChaCha20-Poly1305 under the per-file data key (the
// STREAM construction, Hoang et al. 2015). The 96-bit nonce is an 88-bit
// big-endian chunk counter followed by a flag byte that is 1 only for the
// final chunk. This authenticates chunk order and detects truncation.
//
// Every chunk but the last carries exactly chunkSize bytes; the last carries
// 0..chunkSize and is empty only when the whole plaintext is empty.
const (
	chunkSize   = 64 * 1024                      // plaintext bytes per chunk
	tagSize     = chacha20poly1305.Overhead      // Poly1305 tag appended to each chunk
	sealedChunk = chunkSize + tagSize            // on-disk size of a full chunk
	counterSize = chacha20poly1305.NonceSize - 1 // nonce bytes used by the counter
)

// errCounterOverflow is returned if more than 2^88 chunks are processed.
var errCounterOverflow = errors.New("stream chunk counter overflow")

// nonce is the 12-byte per-chunk nonce: 11 counter bytes then 1 flag byte.
// Because every file has its own random data key, a simple counter is enough
// to guarantee a nonce is never reused with the same key.
type nonce [chacha20poly1305.NonceSize]byte

// next increments the big-endian chunk counter by one, carrying between
// bytes. It returns an error once 2^88 chunks have been processed, which can
// never happen in practice but is checked anyway.
func (n *nonce) next() error {
	for i := counterSize - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			return nil // no carry needed
		}
	}
	return errCounterOverflow
}

// setFinal marks the nonce as belonging to the last chunk of the stream. A
// chunk sealed with this flag cannot be passed off as a middle chunk and vice
// versa, which is what makes truncation and extension detectable.
func (n *nonce) setFinal() { n[counterSize] = 1 }

// readBlock fills buf from r as far as possible and reports whether the
// stream ends after this block. It peeks one byte ahead after a full read so
// the last chunk is identified without needing to know the input length.
func readBlock(r *bufio.Reader, buf []byte) (int, bool, error) {
	n, err := io.ReadFull(r, buf)
	switch err {
	case nil:
		// Buffer full: it is the last block only if nothing follows.
		if _, perr := r.Peek(1); perr == io.EOF {
			return n, true, nil
		} else if perr != nil {
			return n, false, perr
		}
		return n, false, nil
	case io.EOF, io.ErrUnexpectedEOF:
		// Short (or empty) read: the input ended inside this block.
		return n, true, nil
	default:
		return n, false, err
	}
}

// encryptStream reads plaintext from src in chunkSize pieces, seals each one
// with aead and writes the sealed chunks to dst. One buffer is reused for
// every chunk and sealing happens in place, so memory use is constant (about
// 128 KiB) regardless of input size.
func encryptStream(dst io.Writer, src io.Reader, aead cipher.AEAD) error {
	r := bufio.NewReaderSize(src, sealedChunk)
	buf := make([]byte, sealedChunk) // room for plaintext plus tag
	var nc nonce
	for {
		n, last, err := readBlock(r, buf[:chunkSize])
		if err != nil {
			return err
		}
		if last {
			nc.setFinal()
		}
		// Seal in place: ciphertext||tag overwrites the plaintext in buf.
		out := aead.Seal(buf[:0], nc[:], buf[:n], nil)
		if _, err := dst.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
		if err := nc.next(); err != nil {
			return err
		}
	}
}

// decryptStream is the inverse of encryptStream. It reads sealed chunks from
// src, authenticates and decrypts each one, and writes the plaintext to dst.
// Any modification, reordering, truncation or appended data makes a chunk
// fail authentication, and decryption stops with ErrCorrupt or ErrTruncated.
func decryptStream(dst io.Writer, src io.Reader, aead cipher.AEAD) error {
	r := bufio.NewReaderSize(src, sealedChunk)
	buf := make([]byte, sealedChunk)
	var nc nonce
	for first := true; ; first = false {
		n, last, err := readBlock(r, buf)
		if err != nil {
			return err
		}
		if n < tagSize {
			// Not even room for a tag: the file was cut short.
			return ErrTruncated
		}
		if last {
			nc.setFinal()
			if n == tagSize && !first {
				// An empty final chunk is only valid for empty plaintext.
				return ErrCorrupt
			}
		}
		// Open in place: plaintext overwrites the ciphertext in buf.
		out, err := aead.Open(buf[:0], nc[:], buf[:n], nil)
		if err != nil {
			// Covers tampering, reordering and truncation at a chunk
			// boundary (the last remaining chunk was not sealed as final).
			return ErrCorrupt
		}
		if _, err := dst.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
		if err := nc.next(); err != nil {
			return err
		}
	}
}
