// Package apps contains the user-facing front end of Safe Deposit Box: the
// command line interface that parses arguments, obtains the passphrase,
// opens input/output files and delegates the cryptography to package safe.
package apps

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	km "gitlab.com/davecremins/safe-deposit-box/key-mgt"
	"gitlab.com/davecremins/safe-deposit-box/safe"
)

const (
	// extension is appended to encrypted files and stripped on decryption.
	extension = ".sdb"
	// stdio is the conventional file name meaning "standard input/output".
	stdio = "-"
	// shortPassphrase is the length below which a weak-passphrase warning
	// is printed when encrypting.
	shortPassphrase = 12

	// Process exit codes returned by Run.
	exitOK      = 0 // success
	exitFailure = 1 // the operation failed (I/O error, wrong passphrase...)
	exitUsage   = 2 // the command line was invalid

	// usageText is printed for "sdb help" and on invalid usage.
	usageText = `Usage:
  sdb encrypt [flags] [FILE]   encrypt FILE (or stdin) into FILE.sdb (or stdout)
  sdb decrypt [flags] [FILE]   decrypt FILE.sdb (or stdin) into FILE (or stdout)

Use "-" as FILE to read stdin. Run "sdb <command> -h" for command flags.
The passphrase is read from the terminal unless -passphrase-file is given.
`
)

// CLI is the command line interface. Every interaction with the outside
// world goes through one of its fields, which lets tests substitute buffers
// and fake prompts; NewCLI wires them to the real process.
type CLI struct {
	Stdin  io.Reader // source of data when no input file is given
	Stdout io.Writer // destination of data when no output file is given
	Stderr io.Writer // destination of errors, warnings and flag usage
	// ReadPassword prompts for and returns a secret without echoing it.
	ReadPassword func(prompt string) ([]byte, error)
	// StdoutIsTerminal reports whether Stdout is an interactive terminal.
	StdoutIsTerminal func() bool
	// KDF overrides the Argon2id parameters (zero value means defaults).
	// Tests use it to make key derivation fast.
	KDF km.KDFParams
}

// NewCLI returns a CLI bound to the process's standard streams, with the
// passphrase read from the controlling terminal.
func NewCLI() *CLI {
	return &CLI{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		ReadPassword:     readPasswordFromTTY,
		StdoutIsTerminal: func() bool { return isTerminal(os.Stdout) },
	}
}

// options holds the parsed flags and arguments of an encrypt/decrypt command.
type options struct {
	input    string // input path, or "-" for stdin
	output   string // output path, "-" for stdout, or "" to pick a default
	passFile string // optional file holding the passphrase
	force    bool   // overwrite an existing output file
}

// Run executes the command line in args (excluding the program name) and
// returns the process exit code. It never calls os.Exit itself, so it can be
// exercised directly from tests.
func (c *CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, usageText)
		return exitUsage
	}

	// The first argument selects the sub-command; short aliases are accepted.
	cmd, rest := args[0], args[1:]
	var encrypting bool
	switch cmd {
	case "encrypt", "enc", "e":
		encrypting = true
	case "decrypt", "dec", "d":
		encrypting = false
	case "help", "-h", "-help", "--help":
		fmt.Fprint(c.Stdout, usageText)
		return exitOK
	default:
		fmt.Fprintf(c.Stderr, "sdb: unknown command %q\n\n%s", cmd, usageText)
		return exitUsage
	}

	// Parse the sub-command's flags. "-h" prints flag help and is a success.
	opts, err := c.parseFlags(cmd, rest)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil {
		fmt.Fprintf(c.Stderr, "sdb %s: %v\n", cmd, err)
		return exitUsage
	}

	// Perform the operation and translate any error into an exit code.
	if encrypting {
		err = c.encrypt(opts)
	} else {
		err = c.decrypt(opts)
	}
	if err != nil {
		fmt.Fprintf(c.Stderr, "sdb %s: %v\n", cmd, err)
		return exitFailure
	}
	return exitOK
}

// parseFlags parses the flags and positional arguments shared by the encrypt
// and decrypt sub-commands. With no positional argument the input is stdin;
// more than one input file is an error.
func (c *CLI) parseFlags(cmd string, args []string) (*options, error) {
	fs := flag.NewFlagSet("sdb "+cmd, flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	opts := &options{}
	fs.StringVar(&opts.output, "o", "", `output path ("-" for stdout)`)
	fs.StringVar(&opts.passFile, "passphrase-file", "", "read the passphrase from the first line of this file")
	fs.BoolVar(&opts.force, "f", false, "overwrite the output file if it exists")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	switch fs.NArg() {
	case 0:
		opts.input = stdio
	case 1:
		opts.input = fs.Arg(0)
	default:
		return nil, errors.New("expected at most one input file")
	}
	return opts, nil
}

// encrypt implements "sdb encrypt". The default output is FILE.sdb for a
// file input and stdout for stdin input. Binary ciphertext is never written
// to an interactive terminal. The passphrase is entered twice to catch typos,
// because a mistyped passphrase would make the data unrecoverable.
func (c *CLI) encrypt(o *options) error {
	// Choose the output destination.
	out := o.output
	if out == "" {
		out = stdio
		if o.input != stdio {
			out = o.input + extension
		}
	}
	if out == stdio && c.StdoutIsTerminal() {
		return errors.New("refusing to write encrypted data to a terminal; use -o or redirect stdout")
	}

	// Obtain (and confirm) the passphrase; wipe it from memory when done.
	pass, err := c.passphrase(o.passFile, true)
	if err != nil {
		return err
	}
	defer km.Wipe(pass)

	// Stream the input through safe.Encrypt into the output.
	return c.transform(o.input, out, o.force, func(w io.Writer, r io.Reader) error {
		return safe.Encrypt(w, r, pass, safe.Options{KDF: c.KDF})
	})
}

// decrypt implements "sdb decrypt". The default output is the input path with
// its ".sdb" extension removed, or stdout for stdin input. If the input has
// no ".sdb" extension the user must name the output explicitly with -o.
func (c *CLI) decrypt(o *options) error {
	// Choose the output destination.
	out := o.output
	if out == "" {
		switch {
		case o.input == stdio:
			out = stdio
		case strings.HasSuffix(o.input, extension) && len(o.input) > len(extension):
			out = strings.TrimSuffix(o.input, extension)
		default:
			return fmt.Errorf("input does not end in %s; specify the output with -o", extension)
		}
	}

	// Obtain the passphrase (no confirmation needed: a wrong one just fails).
	pass, err := c.passphrase(o.passFile, false)
	if err != nil {
		return err
	}
	defer km.Wipe(pass)

	// Stream the input through safe.Decrypt into the output.
	return c.transform(o.input, out, o.force, func(w io.Writer, r io.Reader) error {
		return safe.Decrypt(w, r, pass)
	})
}

// passphrase obtains the passphrase either from the first line of file (for
// scripted, non-interactive use) or by prompting on the terminal. When
// confirm is true (encryption) the user must type it twice, and a warning is
// printed for short passphrases. Empty passphrases are always rejected.
// The caller owns the returned slice and should wipe it after use.
func (c *CLI) passphrase(file string, confirm bool) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		defer km.Wipe(data) // the file may contain more than the first line
		// Use only the first line and tolerate Windows (CRLF) line endings.
		line, _, _ := bytes.Cut(data, []byte("\n"))
		pass := bytes.Clone(bytes.TrimSuffix(line, []byte("\r")))
		if len(pass) == 0 {
			return nil, km.ErrEmptyPassphrase
		}
		return pass, nil
	}

	pass, err := c.ReadPassword("Passphrase: ")
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, km.ErrEmptyPassphrase
	}
	if !confirm {
		return pass, nil
	}

	// Encryption: ask again and require an exact match.
	again, err := c.ReadPassword("Confirm passphrase: ")
	if err != nil {
		km.Wipe(pass)
		return nil, err
	}
	defer km.Wipe(again)
	if !bytes.Equal(pass, again) {
		km.Wipe(pass)
		return nil, errors.New("passphrases do not match")
	}
	if len(pass) < shortPassphrase {
		fmt.Fprintf(c.Stderr, "warning: passphrases shorter than %d characters are easier to guess\n", shortPassphrase)
	}
	return pass, nil
}

// transform opens input (or uses stdin), then streams it through fn into
// output (or stdout).
//
// File outputs are written atomically: data goes to a private (0600)
// temporary file in the destination directory, which is flushed to disk and
// renamed over the final path only if fn succeeds. A failure, such as a wrong
// passphrase or tampered ciphertext, therefore never leaves partial or
// unverified data behind. Existing files are only replaced when force is set,
// and the input file can never be used as its own output.
func (c *CLI) transform(input, output string, force bool, fn func(io.Writer, io.Reader) error) error {
	// Open the source.
	var src io.Reader = c.Stdin
	if input != stdio {
		f, err := os.Open(input)
		if err != nil {
			return err
		}
		defer f.Close()
		src = f
	}

	// Streaming to stdout needs no temporary file.
	if output == stdio {
		return fn(c.Stdout, src)
	}

	// Safety checks before touching the destination.
	if input != stdio && sameFile(input, output) {
		return errors.New("input and output must be different files")
	}
	if !force {
		if _, err := os.Lstat(output); err == nil {
			return fmt.Errorf("%s already exists; use -f to overwrite", output)
		}
	}

	// Create the temporary file next to the destination so that the final
	// rename stays on one filesystem and is atomic. os.CreateTemp uses 0600.
	tmp, err := os.CreateTemp(filepath.Dir(output), "."+filepath.Base(output)+".*.tmp")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		// On any failure path, discard the temporary file.
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	// Run the transformation, flush it to stable storage, then publish it.
	if err := fn(tmp, src); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), output); err != nil {
		return err
	}
	committed = true
	return nil
}

// sameFile reports whether paths a and b refer to the same existing file,
// following symlinks and hard links. It returns false if either is missing.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}
