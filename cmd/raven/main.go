package main

import (
	"os"

	"github.com/nokia/bgp-routing-security-monitor/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
