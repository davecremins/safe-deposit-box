package apps

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	km "gitlab.com/davecremins/safe-deposit-box/key-mgt"
)

// pass is the passphrase used throughout the CLI tests.
const pass = "correct horse battery staple"

// harness bundles a CLI wired to in-memory streams with its captured output.
type harness struct {
	cli    *CLI
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

// newHarness returns a CLI reading stdin from the given string, whose
// password prompt answers with responses in order and then fails.
func newHarness(stdin string, responses ...string) *harness {
	h := &harness{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	h.cli = &CLI{
		Stdin:  strings.NewReader(stdin),
		Stdout: h.stdout,
		Stderr: h.stderr,
		ReadPassword: func(string) ([]byte, error) {
			if len(responses) == 0 {
				return nil, errors.New("no more input")
			}
			r := responses[0]
			responses = responses[1:]
			return []byte(r), nil
		},
		StdoutIsTerminal: func() bool { return false },
		KDF:              km.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1},
	}
	return h
}

// run executes the CLI with args and fails the test unless it exits with want.
func (h *harness) run(t *testing.T, want int, args ...string) {
	t.Helper()
	if got := h.cli.Run(args); got != want {
		t.Fatalf("Run(%q) = %d, want %d; stderr: %s", args, got, want, h.stderr)
	}
}

// writeFile creates a file with the given content, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readFile returns the content of a file, failing the test on error.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestFileRoundTrip encrypts a file to FILE.sdb and decrypts it back, checking
// permissions, that the ciphertext hides the plaintext and that the original
// is left untouched.
func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "top secret")

	newHarness("", pass, pass).run(t, exitOK, "encrypt", plain)
	enc := plain + ".sdb"
	info, err := os.Stat(enc)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("encrypted file permissions %o, want 600", perm)
	}
	if strings.Contains(readFile(t, enc), "top secret") {
		t.Error("ciphertext contains plaintext")
	}
	if readFile(t, plain) != "top secret" {
		t.Error("original file should be left untouched")
	}

	os.Remove(plain)
	newHarness("", pass).run(t, exitOK, "decrypt", enc)
	if readFile(t, plain) != "top secret" {
		t.Error("decrypted content mismatch")
	}
}

// TestStdinStdoutRoundTrip pipes data through encrypt and decrypt via stdin and
// stdout.
func TestStdinStdoutRoundTrip(t *testing.T) {
	enc := newHarness("piped data", pass, pass)
	enc.run(t, exitOK, "encrypt")
	dec := newHarness(enc.stdout.String(), pass)
	dec.run(t, exitOK, "decrypt", "-")
	if dec.stdout.String() != "piped data" {
		t.Errorf("got %q", dec.stdout.String())
	}
}

// TestExplicitOutputAndForce checks -o selects the output path and that an
// existing file is only overwritten with -f.
func TestExplicitOutputAndForce(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "a")
	enc := filepath.Join(dir, "custom.bin")
	writeFile(t, plain, "x")
	writeFile(t, enc, "existing")

	h := newHarness("", pass, pass)
	h.run(t, exitFailure, "encrypt", "-o", enc, plain)
	if !strings.Contains(h.stderr.String(), "already exists") {
		t.Errorf("unexpected stderr: %s", h.stderr)
	}
	newHarness("", pass, pass).run(t, exitOK, "encrypt", "-f", "-o", enc, plain)

	out := filepath.Join(dir, "out")
	newHarness("", pass).run(t, exitOK, "decrypt", "-o", out, enc)
	if readFile(t, out) != "x" {
		t.Error("decrypted content mismatch")
	}
}

// TestDecryptWrongPassphraseLeavesNoOutput checks a failed decryption reports
// the wrong passphrase and leaves no output or temporary files behind.
func TestDecryptWrongPassphraseLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "f")
	writeFile(t, plain, "data")
	newHarness("", pass, pass).run(t, exitOK, "encrypt", plain)
	os.Remove(plain)

	h := newHarness("", "wrong passphrase")
	h.run(t, exitFailure, "decrypt", plain+".sdb")
	if !strings.Contains(h.stderr.String(), "incorrect passphrase") {
		t.Errorf("unexpected stderr: %s", h.stderr)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only the encrypted file to remain, found %d entries", len(entries))
	}
}

// TestPassphraseFile checks -passphrase-file uses only the first line (CRLF
// tolerated) and rejects empty or missing files.
func TestPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "pass")
	writeFile(t, pf, pass+"\r\nignored second line\n")

	enc := newHarness("hello")
	enc.run(t, exitOK, "encrypt", "-passphrase-file", pf)
	dec := newHarness(enc.stdout.String(), pass) // same passphrase via prompt
	dec.run(t, exitOK, "decrypt")
	if dec.stdout.String() != "hello" {
		t.Errorf("got %q", dec.stdout.String())
	}

	empty := filepath.Join(dir, "empty")
	writeFile(t, empty, "\n")
	newHarness("x").run(t, exitFailure, "encrypt", "-passphrase-file", empty)
	newHarness("x").run(t, exitFailure, "encrypt", "-passphrase-file", filepath.Join(dir, "missing"))
}

// TestPassphrasePromptErrors covers mismatched confirmation, empty input and
// prompt failures.
func TestPassphrasePromptErrors(t *testing.T) {
	newHarness("x", pass, "different").run(t, exitFailure, "encrypt")
	newHarness("x", "").run(t, exitFailure, "encrypt")
	newHarness("x").run(t, exitFailure, "encrypt")
	newHarness("x", pass).run(t, exitFailure, "encrypt") // confirmation fails
	newHarness("x").run(t, exitFailure, "decrypt")
}

// TestShortPassphraseWarning checks a warning is printed for short passphrases.
func TestShortPassphraseWarning(t *testing.T) {
	h := newHarness("x", "short", "short")
	h.run(t, exitOK, "encrypt")
	if !strings.Contains(h.stderr.String(), "warning") {
		t.Error("expected a weak passphrase warning")
	}
}

// TestRefusesCiphertextToTerminal checks ciphertext is never dumped to an
// interactive terminal.
func TestRefusesCiphertextToTerminal(t *testing.T) {
	h := newHarness("x", pass, pass)
	h.cli.StdoutIsTerminal = func() bool { return true }
	h.run(t, exitFailure, "encrypt")
	if h.stdout.Len() != 0 {
		t.Error("nothing should be written to the terminal")
	}
}

// TestDecryptNeedsOutputWithoutExtension checks decrypting a file without the
// .sdb extension requires an explicit -o.
func TestDecryptNeedsOutputWithoutExtension(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "noext")
	writeFile(t, f, "x")
	newHarness("", pass).run(t, exitFailure, "decrypt", f)
}

// TestSameInputAndOutputRejected checks a file cannot be encrypted onto itself.
func TestSameInputAndOutputRejected(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	writeFile(t, f, "x")
	newHarness("", pass, pass).run(t, exitFailure, "encrypt", "-f", "-o", f, f)
	if readFile(t, f) != "x" {
		t.Error("input file was modified")
	}
}

// TestMissingInputAndBadOutputDir checks errors for a missing input file and
// an output directory that does not exist.
func TestMissingInputAndBadOutputDir(t *testing.T) {
	dir := t.TempDir()
	newHarness("", pass, pass).run(t, exitFailure, "encrypt", filepath.Join(dir, "missing"))
	newHarness("x", pass, pass).run(t, exitFailure, "encrypt", "-o", filepath.Join(dir, "no", "such", "dir"))
}

// TestUsage covers help output and the usage errors for bad commands, flags
// and arguments.
func TestUsage(t *testing.T) {
	newHarness("").run(t, exitUsage)
	newHarness("").run(t, exitUsage, "bogus")
	newHarness("").run(t, exitUsage, "encrypt", "a", "b")
	newHarness("").run(t, exitUsage, "encrypt", "-nope")
	newHarness("").run(t, exitOK, "encrypt", "-h")
	h := newHarness("")
	h.run(t, exitOK, "help")
	if !strings.Contains(h.stdout.String(), "Usage") {
		t.Error("help should print usage")
	}
}

// TestNewCLI checks NewCLI wires the CLI to the real process environment.
func TestNewCLI(t *testing.T) {
	c := NewCLI()
	if c.Stdin != os.Stdin || c.ReadPassword == nil || c.StdoutIsTerminal == nil {
		t.Error("NewCLI not wired to the process environment")
	}
	_ = c.StdoutIsTerminal()
}
