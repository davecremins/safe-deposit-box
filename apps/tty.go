package apps

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// readPasswordFromTTY prompts on the controlling terminal and reads a line
// with echo disabled. Using the terminal directly (rather than stdin) keeps
// stdin free for the data being encrypted.
func readPasswordFromTTY(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !isTerminal(os.Stdin) {
			return nil, errors.New("no terminal available to read the passphrase; use -passphrase-file")
		}
		fmt.Fprint(os.Stderr, prompt)
		defer fmt.Fprintln(os.Stderr)
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	defer fmt.Fprintln(tty)
	return term.ReadPassword(int(tty.Fd()))
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
