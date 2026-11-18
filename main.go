package main

import (
	"os"

	"gitlab.com/davecremins/safe-deposit-box/apps"
)

func main() {
	os.Exit(apps.NewCLI().Run(os.Args[1:]))
}
