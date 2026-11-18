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
	chunkSize   = 64 * 1024
	tagSize     = chacha20poly1305.Overhead
	sealedChunk = chunkSize + tagSize
	counterSize = chacha20poly1305.NonceSize - 1
)

var errCounterOverflow = errors.New("stream chunk counter overflow")

type nonce [chacha20poly1305.NonceSize]byte

// next advances the counter. It returns an error once 2^88 chunks have been
// processed, which can never happen in practice but is checked anyway.
func (n *nonce) next() error {
	for i := counterSize - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			return nil
		}
	}
	return errCounterOverflow
}

func (n *nonce) setFinal() { n[counterSize] = 1 }

// readBlock fills buf from r and reports whether the stream ends after it.
func readBlock(r *bufio.Reader, buf []byte) (int, bool, error) {
	n, err := io.ReadFull(r, buf)
	switch err {
	case nil:
		if _, perr := r.Peek(1); perr == io.EOF {
			return n, true, nil
		} else if perr != nil {
			return n, false, perr
		}
		return n, false, nil
	case io.EOF, io.ErrUnexpectedEOF:
		return n, true, nil
	default:
		return n, false, err
	}
}

func encryptStream(dst io.Writer, src io.Reader, aead cipher.AEAD) error {
	r := bufio.NewReaderSize(src, sealedChunk)
	buf := make([]byte, sealedChunk)
	var nc nonce
	for {
		n, last, err := readBlock(r, buf[:chunkSize])
		if err != nil {
			return err
		}
		if last {
			nc.setFinal()
		}
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
			return ErrTruncated
		}
		if last {
			nc.setFinal()
			if n == tagSize && !first {
				// An empty final chunk is only valid for empty plaintext.
				return ErrCorrupt
			}
		}
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
