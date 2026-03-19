package main

import (
	"os"

	"github.com/srl-labs/raven/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
