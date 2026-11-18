package safe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	km "gitlab.com/davecremins/safe-deposit-box/key-mgt"
	"golang.org/x/crypto/chacha20poly1305"
)

// Shared test fixtures: a passphrase and deliberately cheap KDF settings.
var (
	testPass = []byte("a very long and secret passphrase")
	testOpts = Options{KDF: km.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}}
)

// randBytes returns n cryptographically random bytes, failing the test on error.
func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// encrypt is a test helper that encrypts plaintext with the test passphrase
// and fast KDF settings, returning the complete SDB file bytes.
func encrypt(t testing.TB, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(plaintext), testPass, testOpts); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// decrypt is a test helper that decrypts an SDB file held in memory.
func decrypt(ciphertext, pass []byte) ([]byte, error) {
	var out bytes.Buffer
	err := Decrypt(&out, bytes.NewReader(ciphertext), pass)
	return out.Bytes(), err
}

// TestRoundTripSizes encrypts and decrypts inputs around the chunk boundaries
// and checks both the recovered plaintext and the exact ciphertext length.
func TestRoundTripSizes(t *testing.T) {
	sizes := []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize, 3*chunkSize + 17}
	for _, size := range sizes {
		plaintext := randBytes(t, size)
		ct := encrypt(t, plaintext)
		chunks := size/chunkSize + 1
		if size > 0 && size%chunkSize == 0 {
			chunks--
		}
		if want := headerSize + size + chunks*tagSize; len(ct) != want {
			t.Errorf("size %d: ciphertext length %d, want %d", size, len(ct), want)
		}
		got, err := decrypt(ct, testPass)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("size %d: plaintext mismatch", size)
		}
	}
}

// TestDefaultOptionsRoundTrip checks that zero Options select the default
// Argon2id parameters and still round-trip correctly.
func TestDefaultOptionsRoundTrip(t *testing.T) {
	var ct, pt bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader([]byte("hi")), testPass, Options{}); err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(bytes.NewReader(ct.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if h.kdf != km.DefaultKDFParams {
		t.Errorf("expected default KDF params, got %+v", h.kdf)
	}
	if err := Decrypt(&pt, &ct, testPass); err != nil || pt.String() != "hi" {
		t.Fatalf("round trip failed: %v", err)
	}
}

// TestEncryptionIsRandomised checks that encrypting the same data twice gives
// different ciphertexts (fresh salt, nonce and data key each time).
func TestEncryptionIsRandomised(t *testing.T) {
	msg := []byte("same message")
	if bytes.Equal(encrypt(t, msg), encrypt(t, msg)) {
		t.Error("two encryptions of the same plaintext are identical")
	}
}

// TestWrongPassphrase checks that a wrong passphrase is reported as such.
func TestWrongPassphrase(t *testing.T) {
	ct := encrypt(t, []byte("secret"))
	if _, err := decrypt(ct, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("expected ErrWrongPassphrase, got %v", err)
	}
}

// TestEmptyPassphraseRejected checks that empty passphrases are refused for
// both encryption and decryption.
func TestEmptyPassphraseRejected(t *testing.T) {
	err := Encrypt(io.Discard, bytes.NewReader(nil), nil, testOpts)
	if !errors.Is(err, km.ErrEmptyPassphrase) {
		t.Errorf("encrypt: expected ErrEmptyPassphrase, got %v", err)
	}
	ct := encrypt(t, []byte("x"))
	if _, err := decrypt(ct, nil); !errors.Is(err, km.ErrEmptyPassphrase) {
		t.Errorf("decrypt: expected ErrEmptyPassphrase, got %v", err)
	}
}

// TestHeaderTamperingDetected flips bits throughout the header and checks that
// every modification is caught when the data key is unwrapped.
func TestHeaderTamperingDetected(t *testing.T) {
	ct := encrypt(t, []byte("secret"))
	// Skip magic/version/kdf id (checked explicitly) and KDF params, which
	// are range checked before use; flip one byte everywhere else.
	for i := 14; i < headerSize; i++ {
		tampered := bytes.Clone(ct)
		tampered[i] ^= 0x01
		if _, err := decrypt(tampered, testPass); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("byte %d: expected ErrWrongPassphrase, got %v", i, err)
		}
	}
	// A KDF parameter change that stays in range must also be detected.
	tampered := bytes.Clone(ct)
	tampered[8]++ // low byte of time cost
	if _, err := decrypt(tampered, testPass); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("kdf time: expected ErrWrongPassphrase, got %v", err)
	}
}

// TestPayloadTamperingDetected flips bits in the first, a middle and the last
// chunk and checks that authentication fails.
func TestPayloadTamperingDetected(t *testing.T) {
	ct := encrypt(t, randBytes(t, 2*chunkSize+5))
	for _, i := range []int{headerSize, headerSize + chunkSize, len(ct) - 1} {
		tampered := bytes.Clone(ct)
		tampered[i] ^= 0x80
		if _, err := decrypt(tampered, testPass); !errors.Is(err, ErrCorrupt) {
			t.Errorf("byte %d: expected ErrCorrupt, got %v", i, err)
		}
	}
}

// TestTruncationDetected cuts the file at various points (inside the header,
// at a chunk boundary, mid-chunk) and checks the truncation is detected.
func TestTruncationDetected(t *testing.T) {
	ct := encrypt(t, randBytes(t, 2*chunkSize+5))
	cases := map[string]int{
		"at chunk boundary": headerSize + sealedChunk,
		"mid chunk":         headerSize + 100,
		"inside tag":        headerSize + 5,
		"no payload":        headerSize,
	}
	for name, n := range cases {
		_, err := decrypt(ct[:n], testPass)
		if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: expected truncation to be detected, got %v", name, err)
		}
	}
	if _, err := decrypt(ct[:headerSize-1], testPass); !errors.Is(err, ErrTruncated) {
		t.Errorf("short header: expected ErrTruncated, got %v", err)
	}
}

// TestAppendedDataDetected checks that bytes added after the final chunk are
// rejected rather than silently ignored.
func TestAppendedDataDetected(t *testing.T) {
	ct := encrypt(t, []byte("short"))
	if _, err := decrypt(append(ct, 0), testPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt, got %v", err)
	}
}

// TestChunkReorderingDetected swaps two chunks and checks that decryption fails,
// proving chunk order is authenticated by the nonce counter.
func TestChunkReorderingDetected(t *testing.T) {
	ct := encrypt(t, randBytes(t, 3*chunkSize))
	a := headerSize
	b := a + sealedChunk
	swapped := bytes.Clone(ct)
	copy(swapped[a:b], ct[b:b+sealedChunk])
	copy(swapped[b:b+sealedChunk], ct[a:b])
	if _, err := decrypt(swapped, testPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt, got %v", err)
	}
}

// TestEmptyFinalChunkAfterDataRejected checks that a non-canonical stream (a
// full chunk followed by an empty final chunk) is refused.
func TestEmptyFinalChunkAfterDataRejected(t *testing.T) {
	// Hand-craft a stream with a full non-final chunk followed by an empty
	// final chunk; valid encryptors never produce this.
	h, dataKey, err := newHeader(testPass, testOpts.KDF)
	if err != nil {
		t.Fatal(err)
	}
	aead, _ := chacha20poly1305.New(dataKey)
	var nc nonce
	out := h.marshal()
	out = aead.Seal(out, nc[:], make([]byte, chunkSize), nil)
	_ = nc.next()
	nc.setFinal()
	out = aead.Seal(out, nc[:], nil, nil)
	if _, err := decrypt(out, testPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt, got %v", err)
	}
}

// TestNotSDB checks that empty and non-SDB inputs are identified as such.
func TestNotSDB(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("S"), []byte("hello world, not encrypted")} {
		if _, err := decrypt(in, testPass); !errors.Is(err, ErrNotSDB) {
			t.Errorf("%q: expected ErrNotSDB, got %v", in, err)
		}
	}
}

// TestUnsupportedVersionAndKDF checks that unknown format versions and KDF
// identifiers are refused.
func TestUnsupportedVersionAndKDF(t *testing.T) {
	ct := encrypt(t, []byte("x"))
	v := bytes.Clone(ct)
	v[3] = 99
	if _, err := decrypt(v, testPass); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("version: expected ErrUnsupportedVersion, got %v", err)
	}
	k := bytes.Clone(ct)
	k[4] = 99
	if _, err := decrypt(k, testPass); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("kdf: expected ErrUnsupportedVersion, got %v", err)
	}
}

// TestHostileKDFParamsRejected checks that a header demanding an excessive
// amount of Argon2id memory is refused before any key derivation runs.
func TestHostileKDFParamsRejected(t *testing.T) {
	ct := encrypt(t, []byte("x"))
	ct[9] = 0xff // memory cost far above the cap
	if _, err := decrypt(ct, testPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt, got %v", err)
	}
}

// TestNonceCounter checks counter increment, carry propagation, overflow
// detection and the final-chunk flag.
func TestNonceCounter(t *testing.T) {
	var n nonce
	if err := n.next(); err != nil || n[counterSize-1] != 1 {
		t.Fatalf("unexpected counter state %v (%v)", n, err)
	}
	n[counterSize-1] = 0xff
	_ = n.next()
	if n[counterSize-2] != 1 || n[counterSize-1] != 0 {
		t.Errorf("carry not propagated: %v", n)
	}
	for i := 0; i < counterSize; i++ {
		n[i] = 0xff
	}
	if err := n.next(); !errors.Is(err, errCounterOverflow) {
		t.Errorf("expected overflow, got %v", err)
	}
	n.setFinal()
	if n[counterSize] != 1 {
		t.Error("final flag not set")
	}
}

// failWriter is an io.Writer that succeeds `after` times and then fails.
type failWriter struct{ after int }

// Write counts down successful writes and fails once the budget is spent.
func (w *failWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("write failed")
	}
	w.after--
	return len(p), nil
}

// failReader is an io.Reader whose every Read fails.
type failReader struct{}

// Read always returns an error.
func (failReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestIOErrorsPropagate checks that read and write errors at every stage of
// encryption and decryption are returned to the caller.
func TestIOErrorsPropagate(t *testing.T) {
	if err := Encrypt(&failWriter{0}, bytes.NewReader(nil), testPass, testOpts); err == nil {
		t.Error("expected header write error")
	}
	if err := Encrypt(&failWriter{1}, bytes.NewReader([]byte("x")), testPass, testOpts); err == nil {
		t.Error("expected chunk write error")
	}
	if err := Encrypt(io.Discard, failReader{}, testPass, testOpts); err == nil {
		t.Error("expected read error on encrypt")
	}
	if err := Decrypt(io.Discard, failReader{}, testPass); err == nil {
		t.Error("expected read error on decrypt header")
	}
	ct := encrypt(t, []byte("x"))
	if err := Decrypt(&failWriter{0}, bytes.NewReader(ct), testPass); err == nil {
		t.Error("expected write error on decrypt")
	}
	body := io.MultiReader(bytes.NewReader(ct[:headerSize]), failReader{})
	if err := Decrypt(io.Discard, body, testPass); err == nil {
		t.Error("expected read error on decrypt body")
	}
}

// TestReadErrorAfterFullChunk checks that a read error discovered while
// peeking past a full chunk is returned rather than treated as end of input.
func TestReadErrorAfterFullChunk(t *testing.T) {
	src := io.MultiReader(bytes.NewReader(make([]byte, chunkSize)), failReader{})
	if err := Encrypt(io.Discard, src, testPass, testOpts); err == nil {
		t.Error("expected read error")
	}
}

// BenchmarkEncryptStream measures payload encryption throughput on 16 MiB of
// data (key derivation excluded). Run with "make bench".
func BenchmarkEncryptStream(b *testing.B) {
	data := randBytes(b, 16*1024*1024)
	aead, _ := chacha20poly1305.New(randBytes(b, dataKeySize))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := encryptStream(io.Discard, bytes.NewReader(data), aead); err != nil {
			b.Fatal(err)
		}
	}
}
