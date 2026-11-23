// Command sftp is Gameplane's optional SFTP endpoint (spec 040). It accepts
// SFTP clients on one address per cluster and sends every login and file
// operation to the Gameplane API as the signed-in user; it never reads a
// game server's volume itself. This first version is a scaffold: only the
// version subcommand exists. See specs.md.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

// errUsage is returned for an unknown or missing subcommand.
var errUsage = errors.New("usage: sftp version")

func main() {
	os.Exit(exitCode(os.Args[1:], os.Stdout, os.Stderr))
}

// exitCode runs one subcommand and returns the process exit code: 0 on
// success, 2 after printing the error to errOut.
func exitCode(args []string, out, errOut io.Writer) int {
	if err := run(args, out); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	return 0
}

// run dispatches one subcommand and writes its output to out.
func run(args []string, out io.Writer) error {
	if len(args) != 1 || args[0] != "version" {
		return errUsage
	}
	if _, err := fmt.Fprintln(out, Version); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}
