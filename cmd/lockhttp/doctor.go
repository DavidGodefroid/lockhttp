package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/lockkit/ui"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/lockhttp/internal/ca"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

const doctorUsage = "lockhttp doctor [--fix [--yes]] [--json] [--profile P] [--ca-cert FILE] [--gate ADDR]"

// repair is one thing doctor --fix can do.
type repair struct {
	what string
	do   func() error
}

// doctorOpts are what the checks look at.
type doctorOpts struct {
	cwd, profile, caCert, gate string
}

// runDoctor is `lockhttp doctor`: the setup, the project's policy and its
// permissions, the CA and the gate. It checks the project of the current
// directory, as the invoking user (`lox add` runs `doctor --fix --yes
// --json`). --fix repairs the permissions of the project's policy and
// checks again.
func runDoctor(e env, args []string) int {
	o := verbOut{e: e, json: verbs.WantsJSON(args), cmd: "doctor", usage: doctorUsage}
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fix := fs.Bool(verbs.FlagFix, false, "repair what can be, then check again")
	yes := fs.Bool(verbs.FlagYes, false, "with --fix: repair without asking")
	fs.Bool(verbs.FlagJSON, false, "print one line of JSON on stdout")
	profile := fs.String("profile", "", "the profile to check (default: every profile)")
	caCert := fs.String("ca-cert", "", "CA certificate to check")
	gateAddr := fs.String("gate", "", "gate address to check (127.0.0.1:3130)")
	if err := verbs.Parse(product.P, fs, args); err != nil {
		return o.fail(verbs.ErrorCode(err, verbs.CodeUsage), err.Error())
	}
	if *yes && !*fix {
		return o.fail(verbs.CodeUsage, "--yes goes with --fix")
	}
	if *fix && !*yes && !e.tty {
		return o.fail(verbs.CodeUsage, "--fix asks before each repair and there is no terminal: add --yes")
	}
	opts := doctorOpts{cwd: e.cwd, profile: *profile, caCert: *caCert, gate: *gateAddr}
	checks, repairs := doctorChecks(opts)
	var fixed []string
	if *fix && len(repairs) > 0 {
		in := bufio.NewReader(e.stdin)
		for _, r := range repairs {
			if !*yes {
				ans, err := askLine(in, e.stderr, r.what+"? [y/N] ")
				if err != nil || !strings.EqualFold(ans, "y") && !strings.EqualFold(ans, "yes") {
					continue
				}
			}
			if err := r.do(); err != nil {
				fmt.Fprintf(e.stderr, "lockhttp doctor: %s: %v\n", r.what, err)
				continue
			}
			fixed = append(fixed, r.what)
		}
		if len(fixed) > 0 {
			checks, _ = doctorChecks(opts)
		}
	}
	d := verbs.NewDoctor(product.P, checks, fixed)
	if o.json {
		_ = verbs.WriteJSON(e.stdout, d)
	} else {
		fmt.Fprintln(e.stdout, "lockhttp "+version)
		for _, f := range d.Fixed {
			fmt.Fprintln(e.stdout, "fixed: "+f)
		}
		for _, c := range d.Checks {
			mark := ui.MarkOK
			switch c.Status {
			case verbs.StatusWarn:
				mark = ui.MarkWarn
			case verbs.StatusFail:
				mark = ui.MarkFail
			}
			line := mark + " " + c.Check + ": " + c.Detail
			if c.Fix != "" && c.Status != verbs.StatusOK {
				line += " (" + c.Fix + ")"
			}
			fmt.Fprintln(e.stdout, line)
		}
	}
	if !d.OK {
		return exitFail
	}
	return exitOK
}

// doctorChecks runs every check, and lists the repairs --fix can make.
func doctorChecks(o doctorOpts) ([]verbs.Check, []repair) {
	var checks []verbs.Check
	var repairs []repair
	add := func(name, status, detail, fix string) {
		checks = append(checks, verbs.Check{Check: name, Status: status, Detail: detail, Fix: fix})
	}

	sys, err := sysconf.Load(product.P)
	switch {
	case err != nil:
		add("setup", verbs.StatusFail, fmt.Sprintf("%s: %v", sysconf.File(product.P), err), "")
	case sys == nil:
		add("setup", verbs.StatusFail, fmt.Sprintf("no separated setup (%s)", sysconf.File(product.P)), "run lockhttp through the launcher, in its image (docs/docker.md)")
	default:
		detail := fmt.Sprintf("separated setup: console account %s, clients group %s, sockets in %s", sys.ServiceUser, sys.ClientGroup, sys.SocketDir)
		if len(sys.AllowedUIDs) > 0 {
			detail += fmt.Sprintf("; allowed_uids %v may reach the console besides the group", sys.AllowedUIDs)
		}
		add("setup", verbs.StatusOK, detail, "")
	}

	add("agent", verbs.StatusOK, "nothing to wire: lea routes the agent's HTTP through the gate", "")

	root, found := kconfig.FindProjectRoot(product.P, o.cwd)
	if !found {
		add("policy", verbs.StatusFail, "no .lockhttp/config.toml in this directory or above", "lockhttp profile add")
	} else {
		path := kconfig.ProjectConfigPath(product.P, root)
		checks = append(checks, policyChecks(path, o.profile)...)
		c, r := permissionCheck(path)
		checks = append(checks, c...)
		repairs = append(repairs, r...)
	}

	if o.caCert != "" {
		pem, err := os.ReadFile(o.caCert)
		if err != nil {
			add("ca", verbs.StatusFail, err.Error(), "")
		} else if cert, err := ca.ParseCert(pem); err != nil {
			add("ca", verbs.StatusFail, err.Error(), "")
		} else if left := time.Until(cert.NotAfter); left < 7*24*time.Hour {
			add("ca", verbs.StatusFail, "expires in "+left.Round(time.Hour).String(), "rotate it: lockhttp ca init --force")
		} else {
			add("ca", verbs.StatusOK, "valid until "+cert.NotAfter.Format(time.DateOnly), "")
		}
	} else {
		add("ca", verbs.StatusWarn, "no --ca-cert: decryption off, CONNECTs are decided at the domain (reads AND writes; Claude API content not checked)", "")
	}
	if o.gate != "" {
		c, err := net.DialTimeout("tcp", o.gate, 3*time.Second)
		if err != nil {
			add("gate", verbs.StatusFail, err.Error(), "")
		} else {
			_ = c.Close()
			add("gate", verbs.StatusOK, "answers on "+o.gate, "")
		}
	}
	return checks, repairs
}

// policyChecks parses the project's policy: profile, or every profile.
func policyChecks(path, profile string) []verbs.Check {
	data, err := os.ReadFile(path)
	if err != nil {
		return []verbs.Check{{Check: "policy", Status: verbs.StatusFail, Detail: err.Error()}}
	}
	names := []string{profile}
	if profile == "" {
		if names, err = policy.Profiles(data, path); err != nil {
			return []verbs.Check{{Check: "policy", Status: verbs.StatusFail, Detail: err.Error()}}
		}
		if len(names) == 0 {
			return []verbs.Check{{Check: "policy", Status: verbs.StatusFail, Detail: path + " has no profile", Fix: "lockhttp profile add"}}
		}
	}
	var out []verbs.Check
	for _, n := range names {
		p, err := policy.Parse(data, path, n)
		switch {
		case err != nil:
			out = append(out, verbs.Check{Check: "policy", Status: verbs.StatusFail, Detail: err.Error()})
		case p.Mode == policy.ModeShadow:
			out = append(out, verbs.Check{Check: "policy", Status: verbs.StatusWarn,
				Detail: fmt.Sprintf("%s, profile %s: shadow mode: what would ask or be denied passes (logged)", path, n)})
		default:
			out = append(out, verbs.Check{Check: "policy", Status: verbs.StatusOK,
				Detail: fmt.Sprintf("%s, profile %s: mode %s, heuristics %s, %d trusted hosts, %d rules", path, n, p.Mode, p.Heuristics, len(p.Trusted), len(p.Rules))})
		}
	}
	return out
}

// permissionCheck refuses a policy, or its .lockhttp directory, that
// others than its owner may write: lox run copies it into the console. The
// repair removes their write permission.
func permissionCheck(path string) ([]verbs.Check, []repair) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	var bad []string
	var repairs []repair
	for _, p := range []string{filepath.Dir(path), path} {
		st, err := os.Lstat(p)
		if err != nil {
			return []verbs.Check{{Check: "permissions", Status: verbs.StatusFail, Detail: err.Error()}}, nil
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return []verbs.Check{{Check: "permissions", Status: verbs.StatusFail, Detail: p + " is a symbolic link", Fix: "replace it with the file itself"}}, nil
		}
		if perm := st.Mode().Perm(); perm&0o022 != 0 {
			bad = append(bad, p)
			repairs = append(repairs, repair{what: "chmod go-w " + p, do: func() error { return os.Chmod(p, perm&^0o022) }})
		}
	}
	if len(bad) > 0 {
		return []verbs.Check{{Check: "permissions", Status: verbs.StatusFail,
			Detail: strings.Join(bad, ", ") + ": writable by others than the owner", Fix: "lockhttp doctor --fix (chmod go-w)"}}, repairs
	}
	return []verbs.Check{{Check: "permissions", Status: verbs.StatusOK, Detail: "the project's policy is writable by its owner only"}}, nil
}
