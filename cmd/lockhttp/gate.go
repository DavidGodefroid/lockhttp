package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/ca"
	"github.com/DavidGodefroid/lockhttp/internal/gate"
	"github.com/DavidGodefroid/lockhttp/internal/signer"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
)

// runGate is `lockhttp gate`: the proxy, in lea's proxy container (or
// beside the agent on a host, as another account than the console's).
func runGate(e env, args []string) int {
	const usage = "lockhttp gate --listen ADDR [--upstream URL] [--profile P] [--sources FILE] [--credentials FILE] [--audit-dir DIR] [--status-file FILE] [--ca-cert FILE --signer SOCKET] [--hub URL --hub-key-file FILE --instance NAME [--home DIR] [--hub-net CIDR ...]] [--check]"
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	listen := fs.String("listen", envOr("LOCKHTTP_LISTEN", "127.0.0.1:3130"), "address to listen on")
	upstream := fs.String("upstream", os.Getenv("LOCKHTTP_UPSTREAM"), "proxy to send through (squid: http://127.0.0.1:3128); empty dials directly")
	profile := fs.String("profile", envOr("LOCKHTTP_PROFILE", "default"), "console profile")
	sources := fs.String("sources", os.Getenv("LOCKHTTP_SOURCES"), "sources.json written by lea (empty: standalone, one container \"local\")")
	creds := fs.String("credentials", os.Getenv("LOCKHTTP_CREDENTIALS"), "credentials.json written by lea (Claude API keys per container)")
	auditDir := fs.String("audit-dir", os.Getenv("LOCKHTTP_AUDIT_DIR"), "directory of the daily JSONL audit (empty: stderr)")
	status := fs.String("status-file", os.Getenv("LOCKHTTP_STATUS_FILE"), "status file for lea (pending asks, console state)")
	caCert := fs.String("ca-cert", os.Getenv("LOCKHTTP_CA_CERT"), "CA certificate (enables decryption, with --signer)")
	signerSock := fs.String("signer", os.Getenv("LOCKHTTP_SIGNER"), "signer socket")
	check := fs.Bool("check", false, "exit 0 if a gate answers on --listen")
	hubURL := fs.String("hub", os.Getenv("LOCKHTTP_HUB"), "ask lockhub at this URL instead of the console (with --hub-key-file and --instance)")
	hubKeyFile := fs.String("hub-key-file", os.Getenv("LOCKHTTP_HUB_KEY_FILE"), "the pinned public key of the hub (base64, one line)")
	instance := fs.String("instance", os.Getenv("LOCKHTTP_INSTANCE"), "the lock instance name the hub knows this gate by")
	home := fs.String("home", os.Getenv("LOCKHTTP_HOME"), "the gate's own volume: instance key, plans and hub state (default: the home directory)")
	var hubNets prefixList
	fs.Var(&hubNets, "hub-net", "a network of the hub, refused as a target (repeatable)")
	if !parse(e, fs, "gate", usage, args) {
		return exitUsage
	}
	if *check {
		c, err := net.DialTimeout("tcp", *listen, 3*time.Second)
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp gate: no gate on", *listen+":", err)
			return exitFail
		}
		c.Close()
		fmt.Fprintln(e.stdout, "gate answers on", *listen)
		return exitOK
	}
	if e.geteuid() == 0 {
		fmt.Fprintln(e.stderr, "lockhttp gate: refused as root: in a rootless container uid 0 is the host user, which the console refuses; run as a dedicated uid (10003)")
		return exitUsage
	}
	cfg := gate.Config{
		Profile: *profile,
		Sources: gate.NewSources(*sources),
		Creds:   gate.NewCredentials(*creds),
		Console: &gate.LockkitConsole{Profile: *profile},
		Log:     e.stderr,
	}
	if err := cfg.Sources.Err(); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp gate:", err)
		return exitUsage
	}
	if *hubURL != "" || *hubKeyFile != "" || *instance != "" || len(hubNets) > 0 {
		h, err := openHub(*hubURL, *hubKeyFile, *instance, *home, hubNets)
		if err != nil {
			return usageFail(e, "gate", usage, err.Error())
		}
		cfg.Hub = h
	}
	if *upstream != "" {
		u, err := url.Parse(*upstream)
		if err != nil || u.Scheme != "http" || u.Host == "" {
			return usageFail(e, "gate", usage, "--upstream must be http://host:port")
		}
		cfg.Upstream = u
	}
	if (*caCert == "") != (*signerSock == "") {
		return usageFail(e, "gate", usage, "--ca-cert and --signer go together")
	}
	if *caCert != "" {
		pem, err := os.ReadFile(*caCert)
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp gate:", err)
			return exitUsage
		}
		cert, err := ca.ParseCert(pem)
		if err != nil {
			fmt.Fprintln(e.stderr, "lockhttp gate:", err)
			return exitUsage
		}
		cfg.Certs = &signer.Client{Path: *signerSock, CACert: cert}
	}
	log, err := gate.NewAuditLog(*auditDir, e.stderr, time.Now)
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp gate:", err)
		return exitFail
	}
	defer log.Close()
	cfg.Audit = log
	cfg.StatusFile = *status
	cfg.UpstreamTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp gate:", err)
		return exitFail
	}
	ctx, stop := signalContext()
	defer stop()
	g := gate.New(cfg)
	go g.Run(ctx)
	go func() { <-ctx.Done(); ln.Close() }()
	mode := "domain (CONNECT + SNI)"
	if cfg.Certs != nil {
		mode = "decrypting (signer " + *signerSock + ")"
	}
	if cfg.Hub != nil {
		mode += ", asks on hub " + *hubURL + " as " + *instance
	}
	fmt.Fprintf(e.stderr, "lockhttp gate %s: listening on %s, profile %s, %s\n", version, ln.Addr(), *profile, mode)
	if err := g.Serve(ctx, ln); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp gate:", err)
		return exitFail
	}
	return exitOK
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// runSigner is `lockhttp signer`: the only process that reads the CA key.
func runSigner(e env, args []string) int {
	const usage = "lockhttp signer --ca-cert FILE --ca-key FILE --listen SOCKET [--allow-uid N ...]"
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	certPath := fs.String("ca-cert", "", "CA certificate")
	keyPath := fs.String("ca-key", "", "CA key (readable by the signer's uid only)")
	listen := fs.String("listen", "", "Unix socket path")
	var allow intList
	fs.Var(&allow, "allow-uid", "uid allowed to ask for leaves (repeatable; default: this uid)")
	if !parse(e, fs, "signer", usage, args) {
		return exitUsage
	}
	if *certPath == "" || *keyPath == "" || *listen == "" {
		return usageFail(e, "signer", usage, "--ca-cert, --ca-key and --listen are required")
	}
	if fi, err := os.Stat(*keyPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(e.stderr, "lockhttp signer: %s is readable by others (mode %o): chmod 0600\n", *keyPath, fi.Mode().Perm())
		return exitUsage
	}
	authority, err := ca.Load(*certPath, *keyPath)
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp signer:", err)
		return exitUsage
	}
	if left := time.Until(authority.Cert.NotAfter); left < 7*24*time.Hour {
		fmt.Fprintf(e.stderr, "lockhttp signer: warning: the CA expires in %s: rotate it (lockhttp ca init --force)\n", left.Round(time.Hour))
	}
	ln, err := signer.Listen(*listen)
	if err != nil {
		fmt.Fprintln(e.stderr, "lockhttp signer:", err)
		return exitFail
	}
	ctx, stop := signalContext()
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()
	fmt.Fprintf(e.stderr, "lockhttp signer %s: listening on %s\n", version, *listen)
	s := &signer.Server{CA: authority, AllowUIDs: allow, Log: e.stderr}
	if err := s.Serve(ln); err != nil && ctx.Err() == nil {
		fmt.Fprintln(e.stderr, "lockhttp signer:", err)
		return exitFail
	}
	return exitOK
}

// runCA is `lockhttp ca init`.
func runCA(e env, args []string) int {
	const usage = "lockhttp ca init --dir DIR [--name NAME] [--force]"
	if len(args) == 0 || args[0] != "init" {
		return usageFail(e, "ca", usage, "unknown subcommand")
	}
	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory for ca.pem and ca-key.pem")
	name := fs.String("name", "", "installation name (default: the host name)")
	force := fs.Bool("force", false, "replace an existing CA (rotation)")
	if !parse(e, fs, "ca init", usage, args[1:]) {
		return exitUsage
	}
	if *dir == "" {
		return usageFail(e, "ca init", usage, "--dir is required")
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	if err := ca.Init(*dir, *name, *force, time.Now()); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp ca init:", err)
		return exitFail
	}
	fmt.Fprintf(e.stdout, "CA written to %s: %s (trust it in the agents' containers), %s (0600, the signer's only)\n", *dir, ca.CertFile, ca.KeyFile)
	return exitOK
}

// openHub opens the gate's hub mode: the pinned hub key, the instance key
// in the gate's own volume (made by `lockhttp hub-key`), the plans and the
// hub state beside it. The hub's host name and nets are refused as
// targets.
func openHub(rawURL, keyFile, instance, home string, nets []netip.Prefix) (*gate.Hub, error) {
	switch {
	case rawURL == "" || keyFile == "" || instance == "":
		return nil, errors.New("--hub, --hub-key-file and --instance go together")
	case !hubclient.ValidInstance(instance):
		return nil, fmt.Errorf("invalid instance name %q", instance)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("--hub must be a URL: %q", rawURL)
	}
	hubKey, err := hubclient.ReadHubKey(keyFile)
	if err != nil {
		return nil, err
	}
	if home == "" {
		if home, err = os.UserHomeDir(); err != nil {
			return nil, err
		}
	}
	key, err := hubclient.InstanceKey(home, instance)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(hubclient.KeyDir(home), instance)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := plans.Open(filepath.Join(dir, "plans"))
	if err != nil {
		return nil, err
	}
	c, err := hubclient.New(hubclient.Config{URL: rawURL, Instance: instance, Key: key, HubKey: hubKey, StateFile: filepath.Join(dir, "state.json")})
	if err != nil {
		return nil, err
	}
	return &gate.Hub{Client: c, Plans: st, Hosts: []string{u.Hostname()}, Nets: append(nets, hubAddrs(u.Hostname())...)}, nil
}

// hubAddrs are the hub's own addresses, refused as targets beside
// --hub-net: its URL's IP, or what its name resolves to now.
func hubAddrs(host string) []netip.Prefix {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Prefix{netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	var out []netip.Prefix
	for _, ip := range ips {
		out = append(out, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
	}
	return out
}

// prefixList is a repeatable network flag.
type prefixList []netip.Prefix

func (l *prefixList) String() string { return fmt.Sprint(*l) }

func (l *prefixList) Set(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Errorf("invalid network %q", s)
	}
	*l = append(*l, p.Masked())
	return nil
}

// runHubKey is `lockhttp hub-key --instance NAME [--home DIR]`: it prints
// the instance's public key (made on the first call) for `lock up` to pin
// at the hub.
func runHubKey(e env, args []string) int {
	home := os.Getenv("LOCKHTTP_HOME")
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--home" && i+1 < len(args):
			home = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--home="):
			home = strings.TrimPrefix(args[i], "--home=")
		default:
			rest = append(rest, args[i])
		}
	}
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			fmt.Fprintln(e.stderr, "lockhttp hub-key:", err)
			return exitFail
		}
	}
	if err := hubclient.HubKeyCommand(e.stdout, home, rest); err != nil {
		fmt.Fprintln(e.stderr, "lockhttp hub-key:", err)
		return exitUsage
	}
	return exitOK
}
