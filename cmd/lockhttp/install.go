package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockhttp/internal/product"
	"github.com/DavidGodefroid/lockhttp/internal/separate"
)

// runInstall is `lockhttp install`: the one-time setup that separates
// the console from the agent and lets the gate's uid reach it.
func runInstall(e env, args []string) int {
	const usage = "lockhttp install [--client USER] [--gate-uid N [--rootless]] [--user lockhttp] [--group lockhttp-clients] [--print] [--trust-binary] [--yes]"
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var o separate.Options
	fs.StringVar(&o.Client, "client", "", "the account the agents (lea) run as (default: you)")
	fs.StringVar(&o.Service, "user", product.P.Account, "the console account to create")
	fs.StringVar(&o.Group, "group", product.P.ClientsGroup, "the group allowed to reach the console")
	gateUID := fs.Int("gate-uid", -1, "the gate's uid inside lea's proxy container (10003)")
	rootless := fs.Bool("rootless", false, "the proxy container runs under rootless Podman: map --gate-uid through /etc/subuid")
	printOnly := fs.Bool("print", false, "print the commands, do not run them")
	trust := fs.Bool("trust-binary", false, "copy this binary even when another account than root can change it")
	yes := fs.Bool("yes", false, "run the commands without asking")
	if !parse(e, fs, "install", usage, args) {
		return exitUsage
	}
	separate.Fill(product.P, &o)
	if err := separate.Check(o); err != nil {
		return usageFail(e, "install", usage, err.Error())
	}
	if *gateUID == 0 {
		return usageFail(e, "install", usage, "--gate-uid 0 is refused: the gate never runs as root (in a rootless container uid 0 is the host user)")
	}
	if *rootless && *gateUID < 0 {
		return usageFail(e, "install", usage, "--rootless needs --gate-uid")
	}
	if *gateUID > 0 {
		uid := *gateUID
		if *rootless {
			u, err := user.Lookup(o.Client)
			if err != nil {
				return usageFail(e, "install", usage, err.Error())
			}
			cuid, _ := strconv.Atoi(u.Uid)
			read := e.subuid
			if read == nil {
				read = func() (string, error) { b, err := os.ReadFile("/etc/subuid"); return string(b), err }
			}
			text, err := read()
			if err != nil {
				fmt.Fprintln(e.stderr, "lockhttp install:", err)
				return exitFail
			}
			if uid, err = separate.SubUID(text, o.Client, cuid, *gateUID); err != nil {
				fmt.Fprintln(e.stderr, "lockhttp install:", err)
				return exitFail
			}
		}
		o.AllowedUIDs = []int{uid}
	}
	bin := e.executable
	if bin == "" {
		var err error
		if bin, err = os.Executable(); err == nil {
			bin, err = filepath.EvalSymlinks(bin)
		}
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp install:", err)
			return exitFail
		}
	}
	pin := ""
	if *trust {
		var err error
		if pin, err = separate.FileSum(bin); err != nil {
			fmt.Fprintln(e.stderr, "lockhttp install:", err)
			return exitFail
		}
		fmt.Fprintf(e.stdout, "--trust-binary: copying %s (sha256 %s, checked again before it is installed)\n\n", bin, pin)
	} else if msg, err := separate.SourceRefusal(product.P, bin); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp install:", err)
		return exitFail
	} else if msg != "" {
		fmt.Fprint(e.stderr, msg)
		return exitFail
	}
	goos := e.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	script := separate.Script(product.P, goos, bin, o, pin)
	gateLine := "  - no gate uid given: only members of the clients group reach the console."
	if len(o.AllowedUIDs) > 0 {
		gateLine = fmt.Sprintf("  - the gate's uid as the host sees it (%d) may reach the console socket\n    (allowed_uids); bind-mount /run/lockhttp in the proxy container only.", o.AllowedUIDs[0])
	}
	fmt.Fprintf(e.stdout, `lockhttp install separates the console from the agent:
  - the console runs as %[1]q, in its own login session, and alone shows
    the approvals and keeps the policy;
  - the agent's account %[2]q joins group %[3]q;
%[5]s
  - lockhttp is copied to /usr/local/bin, owned by root.

These commands run as root:

    %[4]s
`, o.Service, o.Client, o.Group, strings.ReplaceAll(strings.TrimRight(script, "\n"), "\n", "\n    "), gateLine)
	if *printOnly || goos != "linux" {
		if goos != "linux" {
			fmt.Fprintln(e.stdout, "\nRun them in a terminal as an administrator.")
		}
		return exitOK
	}
	if !*yes {
		if !e.tty {
			fmt.Fprintln(e.stderr, "lockhttp install: confirm in a terminal, or run with --print or --yes")
			return exitUsage
		}
		fmt.Fprint(e.stdout, "Run them now with sudo? [y/N] ")
		ans, _ := bufio.NewReader(e.stdin).ReadString('\n')
		if !strings.EqualFold(strings.TrimSpace(ans), "y") {
			fmt.Fprintln(e.stdout, "nothing done")
			return exitOK
		}
	}
	if err := e.asRoot(script); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp install:", err)
		return exitFail
	}
	fmt.Fprintf(e.stdout, `
Done. Next:
  1. sudo passwd %[1]s            (a password for the console account)
  2. log in as %[1]s in its own session (switch user, Wayland), then:
       lockhttp init               (the policy, ~/.config/lockhttp/config.toml)
       lockhttp console            (keep it open: it asks you)
  3. start the gate (lea does it with LEA_LOCKHTTP=1), then: lockhttp doctor
`, o.Service)
	return exitOK
}

// asRoot runs a shell script as root: e.root when set (tests), else sudo
// sh -c, or sh -c when this already is root.
func (e env) asRoot(script string) error {
	if e.root != nil {
		return e.root(script)
	}
	cmd := exec.Command("sudo", "sh", "-c", script)
	if e.geteuid() == 0 {
		cmd = exec.Command("sh", "-c", script)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, e.stdout, e.stderr
	return cmd.Run()
}
