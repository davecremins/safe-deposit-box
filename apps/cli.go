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
	extension       = ".sdb"
	stdio           = "-"
	shortPassphrase = 12
	exitOK          = 0
	exitFailure     = 1
	exitUsage       = 2
	usageText       = `Usage:
  sdb encrypt [flags] [FILE]   encrypt FILE (or stdin) into FILE.sdb (or stdout)
  sdb decrypt [flags] [FILE]   decrypt FILE.sdb (or stdin) into FILE (or stdout)

Use "-" as FILE to read stdin. Run "sdb <command> -h" for command flags.
The passphrase is read from the terminal unless -passphrase-file is given.
`
)

// CLI is the command line interface. Its fields allow the environment to be
// substituted in tests; NewCLI wires it to the real process.
type CLI struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// ReadPassword prompts for and returns a secret without echoing it.
	ReadPassword func(prompt string) ([]byte, error)
	// StdoutIsTerminal reports whether Stdout is an interactive terminal.
	StdoutIsTerminal func() bool
	// KDF overrides the Argon2id parameters (zero value means defaults).
	KDF km.KDFParams
}

// NewCLI returns a CLI bound to the process's standard streams and terminal.
func NewCLI() *CLI {
	return &CLI{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		ReadPassword:     readPasswordFromTTY,
		StdoutIsTerminal: func() bool { return isTerminal(os.Stdout) },
	}
}

type options struct {
	input, output, passFile string
	force                   bool
}

// Run executes the command line in args (excluding the program name) and
// returns the process exit code.
func (c *CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, usageText)
		return exitUsage
	}
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

	opts, err := c.parseFlags(cmd, rest)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil {
		fmt.Fprintf(c.Stderr, "sdb %s: %v\n", cmd, err)
		return exitUsage
	}

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

func (c *CLI) encrypt(o *options) error {
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
	pass, err := c.passphrase(o.passFile, true)
	if err != nil {
		return err
	}
	defer km.Wipe(pass)
	return c.transform(o.input, out, o.force, func(w io.Writer, r io.Reader) error {
		return safe.Encrypt(w, r, pass, safe.Options{KDF: c.KDF})
	})
}

func (c *CLI) decrypt(o *options) error {
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
	pass, err := c.passphrase(o.passFile, false)
	if err != nil {
		return err
	}
	defer km.Wipe(pass)
	return c.transform(o.input, out, o.force, func(w io.Writer, r io.Reader) error {
		return safe.Decrypt(w, r, pass)
	})
}

// passphrase obtains the passphrase from a file or the terminal, asking for
// confirmation when a new one is being set.
func (c *CLI) passphrase(file string, confirm bool) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		defer km.Wipe(data)
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

// transform streams input through fn into output. File outputs are written
// to a private temporary file in the destination directory and renamed into
// place only on success, so failures never leave partial or unverified data.
func (c *CLI) transform(input, output string, force bool, fn func(io.Writer, io.Reader) error) error {
	var src io.Reader = c.Stdin
	if input != stdio {
		f, err := os.Open(input)
		if err != nil {
			return err
		}
		defer f.Close()
		src = f
	}

	if output == stdio {
		return fn(c.Stdout, src)
	}

	if input != stdio && sameFile(input, output) {
		return errors.New("input and output must be different files")
	}
	if !force {
		if _, err := os.Lstat(output); err == nil {
			return fmt.Errorf("%s already exists; use -f to overwrite", output)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(output), "."+filepath.Base(output)+".*.tmp")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

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
