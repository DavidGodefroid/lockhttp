package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/lockkit/ui"

	"github.com/DavidGodefroid/lockhttp/internal/ca"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// runDoctor is `lockhttp doctor`: the setup, the policy, the CA, the gate.
func runDoctor(e env, args []string) int {
	const usage = "lockhttp doctor [--profile P] [--config FILE] [--ca-cert FILE] [--gate ADDR]"
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	profile := fs.String("profile", "default", "profile")
	cfgFlag := fs.String("config", "", "policy file (default: ~/.config/lockhttp/config.toml)")
	caCert := fs.String("ca-cert", "", "CA certificate to check")
	gateAddr := fs.String("gate", "", "gate address to check (127.0.0.1:3130)")
	if !parse(e, fs, "doctor", usage, args) {
		return exitUsage
	}
	bad := 0
	okf := func(f string, a ...any) { fmt.Fprintln(e.stdout, ui.MarkOK+" "+fmt.Sprintf(f, a...)) }
	warn := func(f string, a ...any) { fmt.Fprintln(e.stdout, ui.MarkWarn+" "+fmt.Sprintf(f, a...)) }
	fail := func(f string, a ...any) { bad++; fmt.Fprintln(e.stdout, ui.MarkFail+" "+fmt.Sprintf(f, a...)) }

	fmt.Fprintln(e.stdout, "lockhttp "+version)
	sys, err := sysconf.Load(product.P)
	switch {
	case err != nil:
		fail("%s: %v", sysconf.File(product.P), err)
	case sys == nil:
		fail("no separated setup (%s): run lockhttp through the launcher, in its image (docs/docker.md)", sysconf.File(product.P))
	default:
		okf("separated setup: console account %s, clients group %s, sockets in %s", sys.ServiceUser, sys.ClientGroup, sys.SocketDir)
		if len(sys.AllowedUIDs) > 0 {
			okf("allowed_uids %v may reach the console besides the group", sys.AllowedUIDs)
		}
	}
	path, err := e.configPath(*cfgFlag)
	if err == nil {
		data, rerr := os.ReadFile(path)
		switch {
		case os.IsNotExist(rerr):
			warn("no policy at %s (as the console account: lockhttp init)", path)
		case rerr != nil:
			warn("policy %s: %v (run the doctor as the console account to check it)", path, rerr)
		default:
			if p, perr := policy.Parse(data, path, *profile); perr != nil {
				fail("policy: %v", perr)
			} else {
				okf("policy %s, profile %s: mode %s, heuristics %s, %d trusted hosts, %d rules", path, *profile, p.Mode, p.Heuristics, len(p.Trusted), len(p.Rules))
				if p.Mode == policy.ModeShadow {
					warn("shadow mode: what would ask or be denied passes (logged)")
				}
			}
		}
	}
	if *caCert != "" {
		pem, err := os.ReadFile(*caCert)
		if err != nil {
			fail("CA: %v", err)
		} else if c, err := ca.ParseCert(pem); err != nil {
			fail("CA: %v", err)
		} else if left := time.Until(c.NotAfter); left < 7*24*time.Hour {
			fail("CA expires in %s: rotate it (lockhttp ca init --force)", left.Round(time.Hour))
		} else {
			okf("CA valid until %s", c.NotAfter.Format(time.DateOnly))
		}
	} else {
		warn("no --ca-cert: decryption off, CONNECTs are decided at the domain (reads AND writes; Claude API content not checked)")
	}
	if *gateAddr != "" {
		c, err := net.DialTimeout("tcp", *gateAddr, 3*time.Second)
		if err != nil {
			fail("--gate: no gate answers (%s)", netErrKind(err))
		} else {
			c.Close()
			okf("gate answers on %s", *gateAddr)
		}
	}
	if bad > 0 {
		return exitFail
	}
	return exitOK
}
