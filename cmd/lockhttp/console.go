package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"

	"github.com/DavidGodefroid/lockhttp/internal/httpconsole"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// configPath is the console's policy file: --config, else the user
// config (~/.config/lockhttp/config.toml of the console account).
func (e env) configPath(flagVal string) (string, error) {
	if flagVal != "" {
		return filepath.Abs(flagVal)
	}
	if e.userConfig != "" {
		return e.userConfig, nil
	}
	return kconfig.UserConfigPath(product.P)
}

// runConsole is `lockhttp console`: the approval console, in the console
// account's own session.
func runConsole(e env, args []string) int {
	const usage = "lockhttp console [--profile P] [--config FILE] [--auto]"
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	profile := fs.String("profile", "default", "profile to serve")
	cfgFlag := fs.String("config", "", "policy file (default: ~/.config/lockhttp/config.toml)")
	auto := fs.Bool("auto", false, "start in auto mode (only rules with verdict \"auto\" are ever auto-approved)")
	if !parse(e, fs, "console", usage, args) {
		return exitUsage
	}
	if !e.tty {
		fmt.Fprintln(e.stderr, "lockhttp console: must run in a terminal: it asks the human for approvals")
		return exitUsage
	}
	path, err := e.configPath(*cfgFlag)
	if err != nil {
		return usageFail(e, "console", usage, err.Error())
	}
	term := console.NewTerminal(os.Stdin, e.stdout)
	if err := term.Interactive(); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp console: warning:", err, "(the mode keys and the status line are off)")
	}
	defer term.Restore()
	ctx, stop := signalContext()
	defer stop()
	p := product.P
	p.Version = strings.TrimPrefix(version, "v")
	be := httpconsole.New(httpconsole.Options{Profile: *profile, Config: path})
	err = console.Run(ctx, p, be, console.Options{
		Profile: *profile, IO: term, TTY: os.Stdin, Auto: *auto,
		Sanitizer: httpconsole.Sanitizer(),
	})
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp console:", err)
		if errors.Is(err, console.ErrConfig) {
			return exitUsage
		}
		return exitFail
	}
	return exitOK
}

// runPolicy is `lockhttp policy show|edit|path`: the console account's
// policy file, which lives in its home volume.
func runPolicy(e env, args []string) int {
	const usage = "lockhttp policy show | edit | path [--config FILE]"
	if len(args) == 0 {
		return usageFail(e, "policy", usage, "show, edit or path")
	}
	sub := args[0]
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "policy file (default: ~/.config/lockhttp/config.toml)")
	if !parse(e, fs, "policy", usage, args[1:]) {
		return exitUsage
	}
	path, err := e.configPath(*cfgFlag)
	if err != nil {
		return usageFail(e, "policy", usage, err.Error())
	}
	switch sub {
	case "path":
		fmt.Fprintln(e.stdout, path)
	case "show":
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp policy:", err, "(create it with: lockhttp init)")
			return exitFail
		}
		_, _ = e.stdout.Write(b)
	case "edit":
		if _, err := os.Stat(path); err != nil {
			fmt.Fprintln(e.stderr, "lockhttp policy:", err, "(create it with: lockhttp init)")
			return exitFail
		}
		edit := e.editor
		if edit == nil {
			edit = func(p string) error {
				ed := os.Getenv("EDITOR")
				if ed == "" {
					ed = "vi"
				}
				cmd := exec.Command(ed, p)
				cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				return cmd.Run()
			}
		}
		if err := edit(path); err != nil {
			fmt.Fprintln(e.stderr, "lockhttp policy:", err)
			return exitFail
		}
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp policy:", err)
			return exitFail
		}
		names, err := policy.Profiles(b, path)
		if err == nil {
			for _, n := range names {
				if _, err = policy.Parse(b, path, n); err != nil {
					break
				}
			}
		}
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp policy: the file does not parse:", err, "(the console keeps the approved policy until it does)")
			return exitUsage
		}
		fmt.Fprintln(e.stdout, "saved: the console shows any loosening for approval (:review)")
	default:
		return usageFail(e, "policy", usage, "unknown subcommand (show, edit or path)")
	}
	return exitOK
}

// runInit is `lockhttp init`: the policy file, in the console account.
func runInit(e env, args []string) int {
	const usage = `lockhttp init [--profile P] [--config FILE] [--trusted "a.com .corp.example"] [--force]`
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	profile := fs.String("profile", "default", "profile name")
	cfgFlag := fs.String("config", "", "policy file (default: ~/.config/lockhttp/config.toml)")
	trusted := fs.String("trusted", "", "hosts to trust for reads, space or comma separated (lea's LEA_EGRESS_ALLOW)")
	force := fs.Bool("force", false, "overwrite an existing file")
	if !parse(e, fs, "init", usage, args) {
		return exitUsage
	}
	path, err := e.configPath(*cfgFlag)
	if err != nil {
		return usageFail(e, "init", usage, err.Error())
	}
	if _, err := os.Stat(path); err == nil && !*force {
		fmt.Fprintf(e.stderr, "lockhttp init: %s exists (edit it, or --force)\n", path)
		return exitFail
	}
	imports := strings.FieldsFunc(*trusted, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' })
	// Checked here so an error names the --trusted entry, not its place in
	// the generated file (and never the value).
	for i, h := range imports {
		if _, err := policy.CheckHostPattern(fmt.Sprintf("--trusted entry %d", i+1), strings.TrimPrefix(h, "."), false); err != nil {
			return usageFail(e, "init", usage, err.Error())
		}
	}
	text := policy.DefaultConfig(imports)
	if *profile != "default" {
		text = strings.ReplaceAll(text, "profiles.default", "profiles."+*profile)
	}
	if _, err := policy.Parse([]byte(text), path, *profile); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp init:", err)
		return exitUsage
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp init:", err)
		return exitFail
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp init:", err)
		return exitFail
	}
	fmt.Fprintf(e.stdout, "wrote %s (profile %s)\nnext: lockhttp console --profile %s\n", path, *profile, *profile)
	return exitOK
}
