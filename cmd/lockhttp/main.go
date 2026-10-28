// Command lockhttp is the proxy every outbound HTTP request of an AI agent
// goes through: reads of trusted hosts pass, anything that sends data,
// triggers an action or reaches an unknown host waits for a human in a
// console the agent cannot reach.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
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
	// root runs install's script as root; nil is sudo sh -c.
	root func(script string) error
	// executable and goos replace the running binary and system (tests).
	executable, goos string
	// euid is the effective uid; nil is os.Geteuid.
	euid func() int
	// subuid is /etc/subuid's content; nil reads the file.
	subuid func() (string, error)
	// userConfig is the console's config file; "" is the real one.
	userConfig string
}

const usageText = `usage: lockhttp <command> [arguments]

Human commands (host)
  install  [--client USER] [--gate-uid N [--rootless]] [--print] [--trust-binary] [--yes]
                                   separate the console from the agent: console account,
                                   clients group, /etc/lockhttp, the gate's uid (sudo)
  init     [--profile P] [--trusted "a.com .corp.example"] [--force]
                                   write the policy file (as the console account)
  console  [--profile P] [--config FILE] [--auto]
                                   run the approval console (as the console account)
  doctor   [--config FILE] [--ca-cert FILE] [--gate ADDR]
                                   check the setup
  ca init  --dir DIR [--name NAME] [--force]
                                   create (or rotate) the local CA for decryption

Proxy container
  gate     --listen ADDR [--upstream URL] [--profile P] [--sources FILE]
           [--credentials FILE] [--audit-dir DIR] [--status-file FILE]
           [--ca-cert FILE --signer SOCKET] [--check]
                                   run the HTTP(S) proxy
  signer   --ca-cert FILE --ca-key FILE --listen SOCKET [--allow-uid N ...]
                                   issue leaf certificates to the gate (holds the CA key)

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
	os.Exit(run(env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, cwd: cwd,
		tty: term.IsTerminal(int(os.Stdin.Fd()))}, os.Args[1:]))
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
	case "install":
		return runInstall(e, args[1:])
	case "init":
		return runInit(e, args[1:])
	case "console":
		return runConsole(e, args[1:])
	case "doctor":
		return runDoctor(e, args[1:])
	case "ca":
		return runCA(e, args[1:])
	case "gate":
		return runGate(e, args[1:])
	case "signer":
		return runSigner(e, args[1:])
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

// parse parses flags and refuses positional arguments.
func parse(e env, fs *flag.FlagSet, cmd, usage string, args []string) bool {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		usageFail(e, cmd, usage, err.Error())
		return false
	}
	if fs.NArg() > 0 {
		usageFail(e, cmd, usage, "unexpected argument "+fs.Arg(0))
		return false
	}
	return true
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func (e env) geteuid() int {
	if e.euid != nil {
		return e.euid()
	}
	return os.Geteuid()
}

// intList is a repeatable integer flag.
type intList []int

func (l *intList) String() string { return fmt.Sprint(*l) }

func (l *intList) Set(s string) error {
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil || n < 0 {
		return fmt.Errorf("invalid uid %q", s)
	}
	*l = append(*l, n)
	return nil
}
