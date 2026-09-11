package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage())
	}
	switch args[0] {
	case "connect":
		return runConnect(args[1:], input, output)
	case "version", "--version", "-version":
		_, err := fmt.Fprintf(output, "null %s\n", version)
		return err
	case "help", "--help", "-h":
		_, err := fmt.Fprintln(output, usage())
		return err
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage())
	}
}

func usage() string {
	return "usage: null <connect|version>\n\nRun 'null connect --help' for onboarding options."
}
