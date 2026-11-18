// Command sdb (Safe Deposit Box) encrypts and decrypts files or streams with
// a passphrase. See the README and the docs directory for usage and design.
package main

import (
	"os"

	"gitlab.com/davecremins/safe-deposit-box/apps"
)

// main is the program entry point. It hands the command line arguments
// (minus the program name) to the CLI and exits with the status code the CLI
// returns, so shell scripts can detect success (0), failure (1) or misuse (2).
func main() {
	os.Exit(apps.NewCLI().Run(os.Args[1:]))
}
