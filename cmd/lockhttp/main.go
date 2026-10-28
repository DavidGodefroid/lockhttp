// Command lockhttp is the proxy every outbound HTTP request of an AI agent
// goes through: reads of trusted hosts pass, anything that sends data,
// triggers an action or reaches an unknown host waits for a human in a
// console the agent cannot reach.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// version is set at build time (-X main.version=...).
var version = "dev"

// Exit codes: 0 ok, 1 refused/denied/failed, 2 no console, 3 usage or
// configuration error.
const (
	exitOK        = 0
	exitFail      = 1
	exitNoConsole = 2
	exitUsage     = 3
)

// env is what a command reads and writes; tests replace it.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	cwd            string
	// tty reports whether stdin is a terminal.
	tty bool
}

const usageText = `usage: lockhttp <command> [arguments]

Human commands (host)
  install    separate the console from the agent: console account, clients group,
             /etc/lockhttp (sudo)
  console    run the approval console
  doctor     check the setup

Gate commands (proxy container)
  gate       run the HTTP(S) proxy

Other
  version, help

Exit codes  0 ok · 1 refused/denied/failed · 2 no console · 3 usage/config error
`

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lockhttp:", err)
		os.Exit(exitFail)
	}
	os.Exit(run(env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, cwd: cwd}, os.Args[1:]))
}

func run(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usageText)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "version", "--version":
		fmt.Fprintln(e.stdout, "lockhttp "+version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(e.stdout, usageText)
		return exitOK
	default:
		fmt.Fprintf(e.stderr, "lockhttp: unknown command %q\n\n%s", cmd, usageText)
		return exitUsage
	}
}

// usageFail prints a usage error.
func usageFail(e env, cmd, usage, msg string) int {
	fmt.Fprintf(e.stderr, "lockhttp %s: %s\nusage: %s\n", cmd, msg, strings.TrimSpace(usage))
	return exitUsage
}
