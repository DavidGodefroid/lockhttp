//go:build unix

package separate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/kit"
)

var p = kit.Product{Name: "lockhttp", Account: "lockhttp", ClientsGroup: "lockhttp-clients", KeychainService: "lockhttp", EnvPrefix: "LOCKHTTP_"}

func TestCheck(t *testing.T) {
	for _, bad := range []Options{
		{Client: "agent", Service: "agent", Group: "g"},
		{Client: "Agent!", Service: "lockhttp", Group: "g"},
		{Client: "agent", Service: "lockhttp", Group: "a b"},
		{Client: "agent; rm", Service: "lockhttp", Group: "g"},
	} {
		if Check(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	o := Options{Client: "agent"}
	Fill(p, &o)
	if Check(o) != nil || o.Service != "lockhttp" || o.Group != "lockhttp-clients" {
		t.Errorf("defaults %+v", o)
	}
}

// The scripts name the product's account, group, system file, socket
// directory and binary, and nothing of another product.
func TestScripts(t *testing.T) {
	o := Options{Client: "agent", Service: "lockhttp", Group: "lockhttp-clients"}
	linux := Script(p, "linux", "/opt/lockhttp", o, "")
	for _, want := range []string{"useradd --create-home --shell /bin/bash --comment \"lockhttp console\" lockhttp",
		"usermod -aG lockhttp-clients agent", "cat > /etc/lockhttp/system.toml", `service_user = "lockhttp"`,
		`socket_dir   = "/run/lockhttp"`, "d /run/lockhttp 2710 lockhttp lockhttp-clients -", "/etc/tmpfiles.d/lockhttp.conf",
		"install -m 0755 -o root -g root '/opt/lockhttp' /usr/local/bin/lockhttp"} {
		if !strings.Contains(linux, want) {
			t.Errorf("linux script lacks %q:\n%s", want, linux)
		}
	}
	darwin := Script(p, "darwin", "/opt/lockhttp", o, "")
	if !strings.Contains(darwin, "dseditgroup -o edit -a agent -t user lockhttp-clients") || !strings.Contains(darwin, `socket_dir   = "/usr/local/var/run/lockhttp"`) {
		t.Errorf("darwin script:\n%s", darwin)
	}
	for _, s := range []string{linux, darwin} {
		if strings.Contains(s, "locksql") {
			t.Errorf("another product named:\n%s", s)
		}
	}
	// A release already at /usr/local/bin is not copied onto itself.
	if s := Script(p, "linux", InstalledBinary(p), o, ""); strings.Contains(s, "install -m 0755") {
		t.Errorf("copy onto itself:\n%s", s)
	}
	if s := Script(p, "linux", InstalledBinary(p), o, strings.Repeat("a", 64)); !strings.Contains(s, `install -m 0755 -o root -g root "$tmp" /usr/local/bin/lockhttp`) {
		t.Errorf("pinned copy:\n%s", s)
	}
}

// The script is valid sh.
func TestScriptParses(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	o := Options{Client: "agent", Service: "lockhttp", Group: "lockhttp-clients"}
	for _, goos := range []string{"linux", "darwin"} {
		if out, err := exec.Command(sh, "-n", "-c", Script(p, goos, "/opt/it's lockhttp", o, strings.Repeat("b", 64))).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", goos, err, out)
		}
	}
}

// With a pin, the root script copies the binary, checks the copy and stops
// before any change when it differs.
func TestPinnedSourceChecksTheCopy(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed")
	}
	bin := filepath.Join(t.TempDir(), "lock mq")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSum(bin)
	if err != nil {
		t.Fatal(err)
	}
	prefix, src := PinnedSource(p, bin, sum, "sha256sum -c -")
	run := func() string {
		out, _ := exec.Command("sh", "-c", "set -eu\n"+prefix+"cat "+src+"; echo; echo DONE").CombinedOutput()
		return string(out)
	}
	if out := run(); !strings.Contains(out, "binary\nDONE") {
		t.Fatalf("unchanged binary:\n%s", out)
	}
	if err := os.WriteFile(bin, []byte("replaced"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out := run(); strings.Contains(out, "DONE") || !strings.Contains(out, "lockhttp install: the binary changed") {
		t.Fatalf("replaced binary:\n%s", out)
	}
}

func TestSourceRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the file is root-owned")
	}
	path := filepath.Join(t.TempDir(), "lockhttp")
	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	msg, err := SourceRefusal(p, path)
	if err != nil || !strings.Contains(msg, "could have been replaced by the agent") || !strings.Contains(msg, "--trust-binary") {
		t.Errorf("%q %v", msg, err)
	}
	if _, err := SourceRefusal(p, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing binary accepted")
	}
}

func TestAllowedUIDsAndSubUID(t *testing.T) {
	o := Options{Client: "agent", Service: "lockhttp", Group: "lockhttp-clients", AllowedUIDs: []int{110002}}
	s := Script(p, "linux", "/opt/lockhttp", o, "")
	if !strings.Contains(s, "allowed_uids = [110002]") {
		t.Fatalf("allowed_uids missing:\n%s", s)
	}
	sub := "other:200000:65536\nagent:100000:65536\n"
	if n, err := SubUID(sub, "agent", 1000, 10003); err != nil || n != 110002 {
		t.Fatalf("subuid: %d %v", n, err)
	}
	if n, _ := SubUID(sub, "agent", 1000, 0); n != 1000 {
		t.Fatalf("uid 0 is the user: %d", n)
	}
	if _, err := SubUID(sub, "agent", 1000, 70000); err == nil {
		t.Fatal("out of range accepted")
	}
	if _, err := SubUID(sub, "nobody", 1001, 5); err == nil {
		t.Fatal("no range accepted")
	}
}
