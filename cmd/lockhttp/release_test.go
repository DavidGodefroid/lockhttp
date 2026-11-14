//go:build unix

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// releaseFixture is a fake release for the launcher's update: curl serves
// files from a directory, and cosign, when present, records its arguments.
// bin holds only the tools the launcher needs, so that a cosign installed on
// the machine is not found.
type releaseFixture struct {
	release, bin, cosignArgs string
}

const releaseVersion = "0.9.1"

// The identity the release workflow signs with, pinned in the launcher and .goreleaser.yaml's verification comment.
const (
	ReleaseCertIdentityRegexp = `^https://github\.com/DavidGodefroid/lockhttp/\.github/workflows/release\.yml@refs/tags/v[0-9]`
	releaseOIDCIssuer         = "https://token.actions.githubusercontent.com"
)

// releaseIdentity is the exact identity update checks: the
// release workflow run for that very tag.
func releaseIdentity(tag string) string {
	return "https://github.com/DavidGodefroid/lockhttp/.github/workflows/release.yml@refs/tags/" + tag
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	root := t.TempDir()
	f := &releaseFixture{
		release:    filepath.Join(root, "release"),
		bin:        filepath.Join(root, "bin"),
		cosignArgs: filepath.Join(root, "cosign-args"),
	}
	for _, d := range []string{f.release, f.bin} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"sh", "awk", "sha256sum", "shasum", "tar", "gzip", "install", "mktemp", "rm", "mkdir", "uname", "cat", "sed", "tr", "tail", "printf", "grep"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// curl -fsSL -o OUT URL: the last path segment of URL, from the release.
	writeExec(t, filepath.Join(f.bin, "curl"), `#!/bin/sh
out=""; while [ $# -gt 1 ]; do [ "$1" = -o ] && { out=$2; shift; }; shift; done
cat "`+f.release+`/${1##*/}" > "$out"
`)

	osName := map[string]string{"linux": "linux", "darwin": "darwin"}[runtime.GOOS]
	if osName == "" {
		t.Skip("the launcher supports Linux and macOS only")
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("the launcher supports amd64 and arm64 only")
	}
	archive := "lockhttp_" + releaseVersion + "_" + osName + "_" + arch + ".tar.gz"
	launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "lockhttp"))
	if err != nil {
		t.Fatal(err)
	}
	data := tarGz(t, map[string][]byte{"lockhttp": []byte("#!/bin/sh\necho lockhttp " + releaseVersion + "\n"), "scripts/lockhttp": launcher})
	if err := os.WriteFile(filepath.Join(f.release, archive), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.release, "checksums.txt"), []byte(hexSum(data)+"  "+archive+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.release, "checksums.txt.sigstore.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// cosign installs a fake cosign that records its arguments and accepts the
// signature when ok.
func (f *releaseFixture) cosign(t *testing.T, ok bool) {
	t.Helper()
	f.cosignImages(t, ok, ok)
}

// Digests the fake cosign reports for the release images.
var fakeDigest = "sha256:" + strings.Repeat("a", 64)

// cosignImages installs a fake cosign that records its arguments (every
// call, appended), accepts the signature of checksums.txt when blobOK, and
// verifies the release images, printing their digests, when imageOK.
func (f *releaseFixture) cosignImages(t *testing.T, blobOK, imageOK bool) {
	t.Helper()
	code := func(ok bool) string {
		if ok {
			return "0"
		}
		return "1"
	}
	writeExec(t, filepath.Join(f.bin, "cosign"), `#!/bin/sh
printf '%s\n' "$@" >> '`+f.cosignArgs+`'
case "$1" in
verify-blob) exit `+code(blobOK)+` ;;
verify)
	[ `+code(imageOK)+` = 0 ] || exit 1
	for a in "$@"; do ref=$a; done
	d='`+fakeDigest+`'
	printf '[{"critical":{"identity":{"docker-reference":"%s"},"image":{"docker-manifest-digest":"%s"},"type":"cosign container image signature"}}]\n' "${ref%:*}" "$d"
	;;
esac
`)
}

func writeExec(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The verification command in .goreleaser.yaml's comment is the one users
// copy: it pins the same identity.
func TestGoreleaserCommentPinsTheIdentity(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "--certificate-identity-regexp '"+ReleaseCertIdentityRegexp+"'") {
		t.Errorf(".goreleaser.yaml does not show the pinned identity %s", ReleaseCertIdentityRegexp)
	}
}

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
