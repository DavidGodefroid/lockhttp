package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/lockhttp/internal/httpconsole"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

const managedUsage = "lockhttp managed show | check [--profile P] [--config FILE]"

// noManaged is what managed show, managed check and doctor print when the
// machine has no managed file.
const noManaged = "no managed configuration"

// loadManaged reads the machine's managed file and lockhttp's section of
// it: nil, nil and no error when there is none.
func loadManaged() (*managed.File, *policy.Managed, error) {
	m, err := managed.Load(context.Background())
	if err != nil || m == nil {
		return nil, nil, err
	}
	mg, err := policy.LoadManaged(m)
	if err != nil {
		return nil, nil, err
	}
	return m, mg, nil
}

// runManaged is `lockhttp managed show|check`: the company's managed
// configuration, as the console applies it. Its output and exit codes are
// a contract (lox runs managed check before it starts the lock): 0 within
// it or no managed file, 3 a refused file or a policy beyond it, one
// "blocked by company policy: …" line per violation.
func runManaged(e env, args []string) int {
	if len(args) == 0 {
		return usageFail(e, "managed", managedUsage, "show or check")
	}
	sub := args[0]
	fs := flag.NewFlagSet("managed", flag.ContinueOnError)
	profile := fs.String("profile", "", "with check: the profile to check (default: every profile)")
	cfgFlag := fs.String("config", "", "with check: policy file (default: ~/.config/lockhttp/config.toml)")
	if !parse(e, fs, "managed", managedUsage, args[1:]) {
		return exitUsage
	}
	switch sub {
	case "show":
		if *profile != "" || *cfgFlag != "" {
			return usageFail(e, "managed", managedUsage, "show takes no flag")
		}
		return managedShow(e)
	case "check":
		path, err := e.configPath(*cfgFlag)
		if err != nil {
			return usageFail(e, "managed", managedUsage, err.Error())
		}
		return managedCheck(e, path, *profile)
	}
	return usageFail(e, "managed", managedUsage, "unknown subcommand (show or check)")
}

func managedShow(e env) int {
	m, mg, err := loadManaged()
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp managed:", safe(err.Error()))
		return exitUsage
	}
	if m == nil {
		fmt.Fprintln(e.stdout, noManaged)
		return exitOK
	}
	out := e.stdout
	signed := "no"
	if m.Signed {
		signed = "yes"
	}
	org := m.Organisation
	if org == "" {
		org = "(none)"
	}
	fmt.Fprintln(out, "path: "+m.Path)
	fmt.Fprintln(out, "organisation: "+safe(org))
	fmt.Fprintln(out, "fingerprint: sha256:"+m.Fingerprint)
	fmt.Fprintln(out, "signed: "+signed)
	if !m.Has(product.P.Name) {
		fmt.Fprintln(out, "[lockhttp]: none (the file does not bound lockhttp)")
		return exitOK
	}
	for _, s := range []struct {
		title string
		lines []string
	}{
		{"bounds", mg.DescribeBounds()},
		{"defaults", mg.DescribeDefaults()},
		{"profiles", mg.ProfileNames()},
	} {
		if len(s.lines) == 0 {
			fmt.Fprintln(out, s.title+": (none)")
			continue
		}
		fmt.Fprintln(out, s.title+":")
		for _, l := range s.lines {
			fmt.Fprintln(out, "  "+safe(l))
		}
	}
	return exitOK
}

// managedCheck checks the policy file at path, as the console loads it,
// against the managed bounds and rules: profile, or every profile. It
// opens no connection.
func managedCheck(e env, path, profile string) int {
	m, mg, err := loadManaged()
	if err != nil {
		fmt.Fprintln(e.stdout, "blocked by company policy: "+safe(err.Error()))
		return exitUsage
	}
	if m == nil {
		fmt.Fprintln(e.stdout, noManaged)
		return exitOK
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp managed:", err, "("+noPolicyHint+")")
		return exitFail
	}
	names := []string{profile}
	if profile == "" {
		if names, err = policy.ProfilesManaged(data, path, mg); err != nil {
			fmt.Fprintln(e.stderr, "lockhttp managed:", safe(err.Error()))
			return exitUsage
		}
	}
	code := exitOK
	be := httpconsole.New(httpconsole.Options{Config: path})
	for _, n := range names {
		lines, err := checkProfile(be, data, path, n, m, mg)
		if err != nil {
			fmt.Fprintln(e.stdout, "blocked by company policy: "+safe(err.Error()))
			code = exitUsage
			continue
		}
		if len(lines) == 0 {
			fmt.Fprintf(e.stdout, "profile %s: within the company's managed configuration\n", n)
			continue
		}
		for _, l := range lines {
			fmt.Fprintln(e.stdout, safe(l))
		}
		code = exitUsage
	}
	return code
}

// checkProfile loads profile n as the console does and lists what of it
// goes beyond the managed file m: one line per violation. An error is a
// profile that does not load (a redefined managed profile, an invalid
// key).
func checkProfile(be *httpconsole.Backend, data []byte, path, n string, m *managed.File, mg *policy.Managed) ([]string, error) {
	p, err := policy.ParseManaged(data, path, n, mg)
	if err != nil {
		return nil, err
	}
	b, err := be.ManagedBounds(p, m)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, v := range managed.Check(p, b) {
		lines = append(lines, v.String())
	}
	return lines, nil
}

// safe escapes a value read from a file for the terminal.
func safe(s string) string { return strings.TrimSpace(sanitize.Terminal(s, false)) }
