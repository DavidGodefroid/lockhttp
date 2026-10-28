//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// launcherFixture runs scripts/lockhttp, the host launcher, with a fake
// docker that records each call, one argument per line, a call ending with
// "--". PATH holds only the tools the launcher needs.
type launcherFixture struct {
	root, bin, project, calls, script string
	env                               []string
}

func newLauncherFixture(t *testing.T) *launcherFixture {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	f := &launcherFixture{
		root:    root,
		bin:     filepath.Join(root, "bin"),
		project: filepath.Join(root, "project"),
		calls:   filepath.Join(root, "calls"),
	}
	for _, d := range []string{f.bin, filepath.Join(f.project, ".lockhttp"), filepath.Join(f.project, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"sh", "dirname", "mkdir", "id", "cat", "printf", "awk", "sha256sum", "shasum", "tar", "gzip", "install", "mktemp", "rm", "uname", "sed", "tr", "tail", "grep"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// docker inspect prints DOCKER_INSPECT; docker run ... version prints
	// the image's version.
	f.fakeDocker(t)
	launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "lockhttp"))
	if err != nil {
		t.Fatal(err)
	}
	f.script = filepath.Join(root, "lockhttp")
	writeExec(t, f.script, string(launcher))
	f.env = []string{"PATH=" + f.bin, "HOME=" + filepath.Join(root, "home")}
	return f
}

func (f *launcherFixture) fakeDocker(t *testing.T) {
	writeExec(t, filepath.Join(f.bin, "docker"), `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done >> '`+f.calls+`'
echo -- >> '`+f.calls+`'
case "$1" in
inspect) printf '%s\n' "${DOCKER_INSPECT:-}" ;;
run) for a in "$@"; do [ "$a" = version ] && echo "lockhttp 9.9.9"; done ;;
esac
exit 0
`)
}

// setVersion makes the launcher one a release installed, without digests
// (installed with LOCKHTTP_SKIP_COSIGN=1).
func (f *launcherFixture) setVersion(t *testing.T, v string) {
	t.Helper()
	f.setVersionDigests(t, v, "")
}

// setVersionDigests makes the launcher one a release installed, with the
// digests of its verified images.
func (f *launcherFixture) setVersionDigests(t *testing.T, v, digest string) {
	t.Helper()
	b, err := os.ReadFile(f.script)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(b), "\nlauncher_version=dev\n", "\nlauncher_version="+v+"\n", 1)
	s = strings.Replace(s, "\nimage_digest=\n", "\nimage_digest="+digest+"\n", 1)
	writeExec(t, f.script, s)
}

// run runs the launcher with args from dir, and returns its output and the
// docker calls, each a list of arguments.
func (f *launcherFixture) run(t *testing.T, dir string, env []string, args ...string) (string, [][]string, error) {
	t.Helper()
	_ = os.Remove(f.calls)
	cmd := exec.Command(filepath.Join(f.bin, "sh"), append([]string{f.script}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, f.env...), env...)
	out, err := cmd.CombinedOutput()
	var calls [][]string
	b, _ := os.ReadFile(f.calls)
	var cur []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "--" {
			calls = append(calls, cur)
			cur = nil
		} else if l != "" {
			cur = append(cur, l)
		}
	}
	return string(out), calls, err
}

// lastRun is the last `docker run` call.
func lastRun(t *testing.T, calls [][]string) []string {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if len(calls[i]) > 0 && calls[i][0] == "run" {
			return calls[i]
		}
	}
	t.Fatalf("no docker run in %q", calls)
	return nil
}

// hasSeq reports whether args hold seq, in order and adjacent.
func hasSeq(args []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		ok := true
		for j, s := range seq {
			if args[i+j] != s {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// imageArgs are the arguments from the image on: the image and its command
// (the account lockhttp of --user is not the image lockhttp).
func imageArgs(args []string, image string) []string {
	for i, a := range args {
		if a == image && (i == 0 || args[i-1] != "--user") {
			return args[i:]
		}
	}
	return nil
}

// The console runs as the console account, in its named container, with
// the socket and home volumes, without a log driver.
func TestLauncherConsole(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, f.project, nil, "console", "--profile", "uat")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	run := lastRun(t, calls)
	for _, seq := range [][]string{
		{"run", "--rm"}, {"--name", "lockhttp-console"}, {"--log-driver", "none"}, {"--user", "lockhttp"},
		{"-v", "lockhttp-run:/run/lockhttp"}, {"-v", "lockhttp-home:/home/lockhttp"},
	} {
		if !hasSeq(run, seq...) {
			t.Errorf("console run lacks %q:\n%q", seq, run)
		}
	}
	if got, want := strings.Join(imageArgs(run, "lockhttp"), " "), "lockhttp console --profile uat"; got != want {
		t.Errorf("image and command %q, want %q", got, want)
	}
	if hasSeq(run, "-it") {
		t.Errorf("a terminal without one: %q", run)
	}
}

// A stopped console of the same name is removed first.
func TestLauncherStaleConsole(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, f.root, []string{"DOCKER_INSPECT=false"}, "console")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	removed := false
	for _, c := range calls {
		if hasSeq(c, "rm", "lockhttp-console") {
			removed = true
		}
	}
	if !removed {
		t.Errorf("stopped console not removed: %q", calls)
	}
}

// Each command runs with the account and the volumes it needs; only the
// console's commands get its home volume; the docker socket is never
// mounted.
func TestLauncherAccountsPerCommand(t *testing.T) {
	f := newLauncherFixture(t)
	me := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	cadir := filepath.Join(f.root, "ca")
	for _, tc := range []struct {
		args, cmd  []string
		want, deny [][]string
	}{
		{[]string{"init", "--trusted", "a.com b.com"}, nil, [][]string{{"--user", "lockhttp"}, {"-v", "lockhttp-home:/home/lockhttp"}}, [][]string{{"-v", "lockhttp-run:/run/lockhttp"}}},
		{[]string{"policy", "edit"}, nil, [][]string{{"--user", "lockhttp"}, {"-v", "lockhttp-home:/home/lockhttp"}}, [][]string{{"-v", "lockhttp-run:/run/lockhttp"}}},
		{[]string{"doctor"}, nil, [][]string{{"--user", "lockhttp"}, {"-v", "lockhttp-home:/home/lockhttp"}}, [][]string{{"-v", "lockhttp-run:/run/lockhttp"}}},
		{[]string{"gate", "--upstream", "http://squid:3128"}, []string{"gate", "--listen", "0.0.0.0:3130", "--upstream", "http://squid:3128"},
			[][]string{{"--user", "gate"}, {"--name", "lockhttp-gate"}, {"-v", "lockhttp-run:/run/lockhttp"}, {"-p", "127.0.0.1:3130:3130"}},
			[][]string{{"-v", "lockhttp-home:/home/lockhttp"}}},
		{[]string{"gate", "--listen=0.0.0.0:3131"}, nil, [][]string{{"--user", "gate"}}, nil},
		{[]string{"signer", "--listen", "/run/lockhttp-signer/s.sock"}, nil, [][]string{{"--user", "signer"}, {"-v", "lockhttp-signer:/run/lockhttp-signer"}}, [][]string{{"-v", "lockhttp-run:/run/lockhttp"}, {"-v", "lockhttp-home:/home/lockhttp"}}},
		{[]string{"ca", "init", "--dir", cadir, "--force"}, []string{"ca", "init", "--dir", cadir, "--force", "--name", hostname(t)}, [][]string{{"--user", me}, {"-v", cadir + ":" + cadir}}, [][]string{{"-v", "lockhttp-home:/home/lockhttp"}}},
		{[]string{"ca", "init", "--name", "my host", "--dir=" + cadir}, []string{"ca", "init", "--name", "my host", "--dir=" + cadir}, [][]string{{"--user", me}}, nil},
		{[]string{"help"}, nil, nil, [][]string{{"--user"}, {"-v", "lockhttp-home:/home/lockhttp"}, {"-v", "lockhttp-run:/run/lockhttp"}}},
		{nil, nil, nil, [][]string{{"--user"}, {"-v", "lockhttp-home:/home/lockhttp"}}},
	} {
		out, calls, err := f.run(t, f.project, nil, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, out)
		}
		run := lastRun(t, calls)
		for _, seq := range tc.want {
			if !hasSeq(run, seq...) {
				t.Errorf("%v: lacks %q:\n%q", tc.args, seq, run)
			}
		}
		for _, seq := range tc.deny {
			if hasSeq(run, seq...) {
				t.Errorf("%v: has %q:\n%q", tc.args, seq, run)
			}
		}
		want := tc.cmd
		if want == nil {
			want = tc.args
		}
		if got := imageArgs(run, "lockhttp")[1:]; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%v: command %q, want %q", tc.args, got, want)
		}
		for _, a := range run {
			if strings.Contains(a, "docker.sock") {
				t.Errorf("%v: the docker socket is mounted: %q", tc.args, run)
			}
		}
	}
	if _, err := os.Stat(cadir); err != nil {
		t.Errorf("ca init did not create --dir: %v", err)
	}
	if out, _, err := f.run(t, f.project, nil, "ca", "init"); err == nil || !strings.Contains(out, "name the directory") {
		t.Errorf("ca init without --dir: %v %s", err, out)
	}
}

func hostname(t *testing.T) string {
	t.Helper()
	b, err := exec.Command("uname", "-n").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// LOCKHTTP_PUBLISH moves the gate's published port.
func TestLauncherGatePublish(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, []string{"LOCKHTTP_PUBLISH=0.0.0.0:8130"}, "gate")
	if err != nil {
		t.Fatal(err)
	}
	if run := lastRun(t, calls); !hasSeq(run, "-p", "0.0.0.0:8130:3130") {
		t.Errorf("%q", run)
	}
}

// The image: a release's launcher runs its own version from the registry;
// LOCKHTTP_IMAGE overrides it.
func TestLauncherImage(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "1.2.3")
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{nil, "ghcr.io/davidgodefroid/lockhttp:1.2.3"},
		{[]string{"LOCKHTTP_IMAGE=my/lockhttp:x"}, "my/lockhttp:x"},
	} {
		_, calls, err := f.run(t, f.project, tc.env, "doctor")
		if err != nil {
			t.Fatal(err)
		}
		if imageArgs(lastRun(t, calls), tc.want) == nil {
			t.Errorf("%v: image %q not run: %q", tc.env, tc.want, lastRun(t, calls))
		}
	}
}

// A launcher installed with a verified image runs it by digest.
func TestLauncherRunsTheVerifiedDigest(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersionDigests(t, "1.2.3", fakeDigest)
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{nil, "ghcr.io/davidgodefroid/lockhttp@" + fakeDigest},
		{[]string{"LOCKHTTP_IMAGE=mine"}, "mine"},
	} {
		_, calls, err := f.run(t, f.project, tc.env, "console")
		if err != nil {
			t.Fatal(err)
		}
		if imageArgs(lastRun(t, calls), tc.want) == nil {
			t.Errorf("%v: %q not run: %q", tc.env, tc.want, lastRun(t, calls))
		}
	}
}

// version prints the launcher's version and its image's.
func TestLauncherVersion(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "1.2.3")
	out, calls, err := f.run(t, f.project, nil, "version")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "lockhttp launcher 1.2.3 (image ghcr.io/davidgodefroid/lockhttp:1.2.3)") || !strings.Contains(out, "lockhttp 9.9.9") {
		t.Errorf("output:\n%s", out)
	}
	if got := imageArgs(lastRun(t, calls), "ghcr.io/davidgodefroid/lockhttp:1.2.3"); len(got) != 2 || got[1] != "version" {
		t.Errorf("run %q", lastRun(t, calls))
	}
}

// LOCKHTTP_DOCKER_ARGS go before the image, split on spaces.
func TestLauncherExtraDockerArgs(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, []string{"LOCKHTTP_DOCKER_ARGS=--network shop"}, "console")
	if err != nil {
		t.Fatal(err)
	}
	run := lastRun(t, calls)
	if !hasSeq(run, "--network", "shop") || len(imageArgs(run, "shop")) <= len(imageArgs(run, "lockhttp")) {
		t.Errorf("%q", run)
	}
}

func TestLauncherWithoutDocker(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.Remove(filepath.Join(f.bin, "docker")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"doctor"}, {"console"}} {
		out, _, err := f.run(t, f.project, nil, args...)
		if err == nil || !strings.Contains(out, "docker is required") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
	}
}

// update replaces the launcher with a release's, after the signature and
// checksum checks, then pulls that release's image.
func TestLauncherUpdate(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	rel := newShFixture(t)
	rel.cosign(t, true)
	for _, tool := range []string{"curl", "cosign"} {
		if err := os.Symlink(filepath.Join(rel.bin, tool), filepath.Join(f.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	out, calls, err := f.run(t, f.project, nil, "update", "v"+shVersion)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b, _ := os.ReadFile(f.script)
	if !strings.Contains(string(b), "\nlauncher_version="+shVersion+"\n") || !strings.Contains(string(b), "\nimage_digest="+fakeDigest+"\n") {
		t.Fatalf("launcher not replaced:\n%s", out)
	}
	if len(calls) != 1 || !hasSeq(calls[0], "pull", "ghcr.io/davidgodefroid/lockhttp@"+fakeDigest) {
		t.Errorf("calls %q", calls)
	}
	args, _ := os.ReadFile(rel.cosignArgs)
	if !strings.Contains(string(args), ReleaseCertIdentityRegexp) {
		t.Errorf("cosign args %s", args)
	}
}

func TestLauncherUpdateRefusesABadSignature(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	rel := newShFixture(t)
	rel.cosign(t, false)
	for _, tool := range []string{"curl", "cosign"} {
		if err := os.Symlink(filepath.Join(rel.bin, tool), filepath.Join(f.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	out, calls, err := f.run(t, f.project, nil, "update", "v"+shVersion)
	if err == nil || !strings.Contains(out, "does not verify") || len(calls) != 0 {
		t.Fatalf("%v, calls %q\n%s", err, calls, out)
	}
	b, _ := os.ReadFile(f.script)
	if !strings.Contains(string(b), "\nlauncher_version=0.9.0\n") {
		t.Fatal("launcher replaced")
	}
}

// update refuses a release whose image does not verify, and keeps the
// launcher.
func TestLauncherUpdateRefusesAnUnverifiedImage(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	rel := newShFixture(t)
	rel.cosignImages(t, true, false)
	for _, tool := range []string{"curl", "cosign"} {
		if err := os.Symlink(filepath.Join(rel.bin, tool), filepath.Join(f.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	out, calls, err := f.run(t, f.project, nil, "update", "v"+shVersion)
	if err == nil || !strings.Contains(out, "does not verify") || len(calls) != 0 {
		t.Fatalf("%v, calls %q\n%s", err, calls, out)
	}
	b, _ := os.ReadFile(f.script)
	if !strings.Contains(string(b), "\nlauncher_version=0.9.0\n") {
		t.Fatal("launcher replaced")
	}
}

// The launcher pins the identity lockhttp update checked.
func TestLauncherPinsTheReleaseIdentity(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "lockhttp"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "identity='"+ReleaseCertIdentityRegexp+"'") {
		t.Error("scripts/lockhttp does not pin", ReleaseCertIdentityRegexp)
	}
}
