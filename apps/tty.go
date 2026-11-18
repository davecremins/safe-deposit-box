package apps

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// readPasswordFromTTY prints prompt and reads one line from the user with
// terminal echo disabled, so the passphrase is not shown on screen.
//
// It talks to the controlling terminal (/dev/tty) rather than stdin, which
// keeps stdin free for the data being encrypted (e.g. "cat f | sdb encrypt").
// If there is no controlling terminal it falls back to stdin, provided stdin
// is itself a terminal; otherwise it asks the user to use -passphrase-file.
func readPasswordFromTTY(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !isTerminal(os.Stdin) {
			return nil, errors.New("no terminal available to read the passphrase; use -passphrase-file")
		}
		fmt.Fprint(os.Stderr, prompt)
		defer fmt.Fprintln(os.Stderr) // move past the prompt line afterwards
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	defer fmt.Fprintln(tty) // the user's Enter key is not echoed, so add it
	return term.ReadPassword(int(tty.Fd()))
}

// isTerminal reports whether f is connected to an interactive terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
