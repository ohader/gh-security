package main

import (
	"os"

	"github.com/ohader/gh-security/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
