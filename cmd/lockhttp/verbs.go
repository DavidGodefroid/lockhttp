package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockkit/agentwire"
	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// The launcher verbs `lox add` calls on every lock (lockkit GUIDE.md §14):
//
//	lockhttp init <agent>
//	lockhttp profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production] [--trusted "..."]
//	lockhttp doctor [--fix [--yes]] [--json] [--profile P] [--ca-cert FILE] [--gate ADDR]
//
// They run as the invoking user on the project: the launcher mounts the
// project at its own path.

const (
	initUsage    = "lockhttp init <agent>    (agent: claude, codex, cursor or gemini)"
	profileUsage = `lockhttp profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production] [--trusted "a.com .corp.example"]`
)

// flagTrusted is profile add's target flag, named after the config key it
// fills: hosts to trust for reads.
const flagTrusted = "trusted"

// noPolicyHint says where the console's policy file comes from.
const noPolicyHint = "lockhttp profile add writes it in the project, lox run copies it here"

// verbOut prints the outcome of a verb: one verbs.Error line on stdout
// with --json, human text on stderr.
type verbOut struct {
	e     env
	json  bool
	cmd   string
	usage string
}

// fail reports a failure with its verbs code and returns the exit status.
func (o verbOut) fail(code, msg string) int {
	if o.json {
		_ = verbs.WriteJSON(o.e.stdout, verbs.Error{Lock: product.P.Name, Code: code, Error: msg})
	}
	fmt.Fprintf(o.e.stderr, "lockhttp %s: %s\n", o.cmd, msg)
	switch code {
	case verbs.CodeUsage, verbs.CodeSecret:
		if o.usage != "" {
			fmt.Fprintf(o.e.stderr, "usage: %s\n", o.usage)
		}
		return exitUsage
	}
	return exitFail
}

// runInit is `lockhttp init <agent>`. lockhttp writes no agent file: lea
// routes the agent's HTTP through the gate, so there is nothing to wire.
// It checks the agent, says so and exits 0 (idempotent, never asks).
func runInit(e env, args []string) int {
	o := verbOut{e: e, cmd: "init", usage: initUsage}
	switch {
	case len(args) == 0:
		return o.fail(verbs.CodeUsage, "name the agent")
	case slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "-") }):
		return o.fail(verbs.CodeUsage, "init takes an agent and no flag (the policy: lockhttp profile add)")
	case len(args) > 1:
		return o.fail(verbs.CodeUsage, "init takes one agent")
	case !slices.Contains(agentwire.Agents(), args[0]):
		return o.fail(verbs.CodeUsage, "unknown agent: want "+strings.Join(agentwire.Agents(), ", "))
	}
	fmt.Fprintf(e.stdout, "lockhttp: nothing to write for %s: lockhttp has no agent files (lea routes the agent's HTTP through the gate, docs/lea.md)\n", args[0])
	return exitOK
}

// runProfile is `lockhttp profile add`.
func runProfile(e env, args []string) int {
	o := verbOut{e: e, json: verbs.WantsJSON(args), cmd: "profile", usage: profileUsage}
	if len(args) == 0 || args[0] != "add" {
		return o.fail(verbs.CodeUsage, "the subcommand is add")
	}
	o.cmd = "profile add"
	return runProfileAdd(e, o, args[1:])
}

// runProfileAdd adds one profile, with the default policy, to the
// project's .lockhttp/config.toml. A profile already there is never
// rewritten (code exists). It never takes, asks for or writes a secret:
// lockhttp's target needs none, so it takes no --credentials.
func runProfileAdd(e env, o verbOut, args []string) int {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	nonInteractive := fs.Bool(verbs.FlagNonInteractive, false, "never ask; a missing value is a usage error")
	fs.Bool(verbs.FlagJSON, false, "print one line of JSON on stdout")
	projectFlag := fs.String(verbs.FlagProject, "", "the project (default: the project of the current directory)")
	profileFlag := fs.String(verbs.FlagProfile, "", "the profile name (default: default)")
	production := fs.Bool(verbs.FlagProduction, false, "a production profile")
	trusted := fs.String(flagTrusted, "", "hosts to trust for reads, space or comma separated (lea's LEA_EGRESS_ALLOW)")
	if err := verbs.Parse(product.P, fs, args); err != nil {
		return o.fail(verbs.ErrorCode(err, verbs.CodeUsage), err.Error())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	interactive := !*nonInteractive
	if interactive && !e.tty {
		return o.fail(verbs.CodeUsage, "no terminal to ask on: pass --"+verbs.FlagNonInteractive+" and the flags")
	}
	root, err := projectRoot(e, *projectFlag)
	if err != nil {
		return o.fail(verbs.CodeUsage, err.Error())
	}
	path := kconfig.ProjectConfigPath(product.P, root)
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return o.fail(verbs.CodeFailed, err.Error())
	}
	var names []string
	if existing != nil {
		if names, err = policy.Profiles(existing, path); err != nil {
			return o.fail(verbs.CodeFailed, "the project's config does not parse (fix it first): "+err.Error())
		}
	}
	in := bufio.NewReader(e.stdin)
	ask := func(q string) (string, error) { return askLine(in, e.stderr, q) }

	name := *profileFlag
	if !set[verbs.FlagProfile] && interactive {
		ans, err := ask("Profile name [default]: ")
		if err != nil {
			return o.fail(verbs.CodeUsage, err.Error())
		}
		name = ans
	}
	if name == "" {
		name = "default"
	}
	if err := kconfig.CheckProfileName(name, false); err != nil {
		return o.fail(verbs.CodeUsage, "--"+verbs.FlagProfile+": "+err.Error())
	}
	if slices.Contains(names, name) {
		return o.fail(verbs.CodeExists, fmt.Sprintf("profile %s is already in %s: nothing written", name, path))
	}
	prod := *production
	if !set[verbs.FlagProduction] && interactive {
		ans, err := ask("Production profile (its name is typed for every approval)? [y/N] ")
		if err != nil {
			return o.fail(verbs.CodeUsage, err.Error())
		}
		prod = strings.EqualFold(ans, "y") || strings.EqualFold(ans, "yes")
	}
	if err := kconfig.CheckProfileName(name, prod); err != nil {
		return o.fail(verbs.CodeUsage, "--"+verbs.FlagProfile+": "+err.Error())
	}
	hosts := *trusted
	if !set[flagTrusted] && interactive {
		if hosts, err = ask("Hosts to trust for reads, space or comma separated (lea's LEA_EGRESS_ALLOW), empty for none: "); err != nil {
			return o.fail(verbs.CodeUsage, err.Error())
		}
	}
	extra, err := policy.ImportHosts(strings.FieldsFunc(hosts, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }))
	if err != nil {
		return o.fail(verbs.CodeUsage, "--"+flagTrusted+": "+err.Error())
	}

	text := policy.DefaultConfig(name, prod, extra)
	if existing != nil {
		s := string(existing)
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		text = s + "\n" + policy.DefaultProfile(name, prod, extra)
	}
	if after, err := policy.Profiles([]byte(text), path); err != nil || len(after) != len(names)+1 {
		return o.fail(verbs.CodeFailed, "the new profile does not fit in the project's config: nothing written")
	}
	if _, err := policy.Parse([]byte(text), path, name); err != nil {
		return o.fail(verbs.CodeFailed, "the new profile does not parse: nothing written")
	}
	if err := writeConfig(path, []byte(text)); err != nil {
		return o.fail(verbs.CodeFailed, err.Error())
	}
	if o.json {
		_ = verbs.WriteJSON(e.stdout, verbs.Profile{Lock: product.P.Name, Profile: name, Config: path, Production: prod})
	} else {
		fmt.Fprintf(e.stdout, "added profile %s to %s\nnext: lox run reviews it and copies it into the lockhttp console\n", name, path)
	}
	return exitOK
}

// projectRoot is --project (relative to the current directory), else the
// project of the current directory (agentwire.ProjectRoot: the nearest
// directory holding .lockhttp/config.toml, else .git, else the current
// directory).
func projectRoot(e env, flagVal string) (string, error) {
	if flagVal == "" {
		return agentwire.ProjectRoot(product.P, e.cwd), nil
	}
	dir := flagVal
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(e.cwd, dir)
	}
	dir = filepath.Clean(dir)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		// The value is not quoted: it may be anything pasted in the
		// wrong place.
		return "", errors.New("--" + verbs.FlagProject + ": not a directory")
	}
	return dir, nil
}

// writeConfig replaces path with data, through a file renamed in place:
// mode 0600 for a new file, the old mode otherwise; the .lockhttp
// directory is created 0700.
func writeConfig(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	f, err := os.CreateTemp(dir, ".config.toml.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// askLine asks q on w and reads one line of r, trimmed. The end of the
// input before an answer is an error.
func askLine(r *bufio.Reader, w io.Writer, q string) (string, error) {
	fmt.Fprint(w, q)
	line, err := r.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", errors.New("no answer: the input ended")
	}
	return strings.TrimSpace(line), nil
}
