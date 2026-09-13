package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, input io.Reader, output io.Writer) error {
	return runContext(context.Background(), args, input, output)
}

func runContext(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage())
	}
	switch args[0] {
	case "connect":
		return runConnectContext(ctx, args[1:], input, output)
	case "status":
		return runStatusContext(ctx, args[1:], output)
	case "doctor":
		return runDoctorContext(ctx, args[1:], output)
	case "github":
		return runGitHubContext(ctx, args[1:], output)
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
	return "usage: null <connect|status|doctor|github|version>\n\nRun 'null connect --help' for onboarding, 'null status' to inspect persisted authority, or 'null doctor' to diagnose the local runtime."
}
