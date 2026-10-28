// Package separate builds the one-time root setup that separates a
// product's console from the agent: a console account, a clients group the
// agent's account joins, the root-owned system file the console requires
// (lockkit sysconf), the shared socket directory, and a root-owned copy of
// the binary. It is parameterised by kit.Product and holds no product
// name of its own. It only builds and checks; running the script (sudo) is
// the caller's.
package separate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/kit"
)

var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Options are the accounts of a separated setup.
type Options struct {
	// Client is the account the agent runs as; Service the console
	// account; Group the clients group.
	Client, Service, Group string
	// AllowedUIDs may reach the console besides the group's members: the
	// gate's uid as the host sees it.
	AllowedUIDs []int
}

// Fill sets the defaults: p's account and clients group, and the account
// sudo was run from (else the current one) as the client.
func Fill(p kit.Product, o *Options) {
	if o.Service == "" {
		o.Service = p.Account
	}
	if o.Group == "" {
		o.Group = p.ClientsGroup
	}
	if o.Client != "" {
		return
	}
	if s := os.Getenv("SUDO_USER"); s != "" {
		o.Client = s
	} else if u, err := user.Current(); err == nil {
		o.Client = u.Username
	}
}

// Check refuses invalid or identical account names.
func Check(o Options) error {
	for _, f := range []struct{ flag, v string }{{"--client", o.Client}, {"--user", o.Service}, {"--group", o.Group}} {
		if !accountRe.MatchString(f.v) {
			return fmt.Errorf("invalid %s %q", f.flag, f.v)
		}
	}
	if o.Client == o.Service {
		return errors.New("the agent's account and the console account must differ")
	}
	return nil
}

// InstalledBinary is where the setup puts the binary the console runs.
func InstalledBinary(p kit.Product) string { return "/usr/local/bin/" + p.Name }

// SocketDir is the shared socket directory on goos (as kit.Product's
// SharedSocketDir on that system).
func SocketDir(p kit.Product, goos string) string {
	if goos == "darwin" {
		return "/usr/local/var/run/" + p.Name
	}
	return "/run/" + p.Name
}

// FileSum is the hex sha256 of the file at path.
func FileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SourceRefusal returns the refusal to print when bin, the binary the
// setup would copy as root, could have been changed by an account other
// than root (a binary the agent replaced would become the one the console
// trusts); "" for a root-owned binary neither group nor others may write.
func SourceRefusal(p kit.Product, bin string) (string, error) {
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return "", err
	}
	why, err := untrusted(resolved)
	if err != nil {
		return "", err
	}
	if why == "" {
		return "", nil
	}
	sum, err := FileSum(resolved)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`%s install: %s %s and could have been replaced by the agent;
install a release into a root-owned directory (scripts/install.sh with the default /usr/local/bin),
or pass --trust-binary to copy this one (sha256 %s, checked again by the root script).
`, p.Name, resolved, why, sum), nil
}

// untrusted returns why an account other than root could change the file
// at path (itself, a hard link elsewhere, or any parent directory), or "".
func untrusted(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	uid, ok := fileOwner(fi)
	if !ok {
		return "has an unknown owner", nil
	}
	if uid != 0 {
		owner := fmt.Sprintf("uid %d", uid)
		if u, err := user.LookupId(fmt.Sprint(uid)); err == nil {
			owner = u.Username
		}
		return "is owned by " + owner, nil
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return "is owned by root but writable by group or others", nil
	}
	if n, ok := fileLinks(fi); ok && n > 1 {
		return "has other hard links", nil
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		di, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		duid, ok := fileOwner(di)
		if !ok || duid != 0 {
			return "sits in " + dir + ", not owned by root,", nil
		}
		if di.Mode().Perm()&0o022 != 0 && di.Mode()&os.ModeSticky == 0 {
			return "sits in " + dir + ", writable by group or others,", nil
		}
		if dir == filepath.Dir(dir) {
			return "", nil
		}
	}
}

// ShellQuote quotes s for sh.
func ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// SystemTOML is the system file of the setup (lockkit sysconf).
func SystemTOML(p kit.Product, svc, group, dir string, allowed []int) string {
	s := fmt.Sprintf(`# %s: the console runs as service_user; members of client_group reach it.
service_user = %q
client_group = %q
socket_dir   = %q
x11          = "refuse"
`, p.Name, svc, group, dir)
	if len(allowed) > 0 {
		ids := make([]string, len(allowed))
		for i, u := range allowed {
			ids[i] = strconv.Itoa(u)
		}
		s += "# the gate's uid as the host sees it\nallowed_uids = [" + strings.Join(ids, ", ") + "]\n"
	}
	return s
}

// SubUID maps a uid inside a rootless container of user to the host uid
// (/etc/subuid content): uid 0 is the user itself, uid n >= 1 is
// subuid_start + n - 1.
func SubUID(subuid, user string, userUID, uid int) (int, error) {
	if uid == 0 {
		return userUID, nil
	}
	for _, line := range strings.Split(subuid, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) != 3 || (f[0] != user && f[0] != strconv.Itoa(userUID)) {
			continue
		}
		start, err1 := strconv.Atoi(f[1])
		count, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		if uid-1 >= count {
			return 0, fmt.Errorf("uid %d is outside %s's subuid range (%d ids)", uid, user, count)
		}
		return start + uid - 1, nil
	}
	return 0, fmt.Errorf("no /etc/subuid range for %s", user)
}

// PinnedSource is the start of a root script that copies bin to a
// root-owned temporary file and checks it against the sha256 pin (sumCmd
// checks a "<sha256>  <path>" line on stdin), stopping before any change
// on a mismatch; src is the file to install. Without a pin, bin itself is
// the source (SourceRefusal accepted it).
func PinnedSource(p kit.Product, bin, pin, sumCmd string) (prefix, src string) {
	if pin == "" {
		return "", ShellQuote(bin)
	}
	return fmt.Sprintf(`tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat %s > "$tmp"
echo '%s  '"$tmp" | %s >/dev/null 2>&1 || { echo '%s install: the binary changed since its sha256 was printed; nothing installed' >&2; exit 1; }
`, ShellQuote(bin), pin, sumCmd, p.Name), `"$tmp"`
}

// copyBinary installs src as the installed binary, or nothing when the
// running binary is that file already (install(1) refuses a copy onto
// itself).
func copyBinary(p kit.Product, bin, pin, src, group string) string {
	if pin == "" && bin == InstalledBinary(p) {
		return ""
	}
	return fmt.Sprintf("install -m 0755 -o root -g %s %s %s\n", group, src, InstalledBinary(p))
}

// Script is the root script of a separated setup on goos (linux or
// darwin). pin, when set, is the sha256 the copied binary must match
// (--trust-binary).
func Script(p kit.Product, goos, bin string, o Options, pin string) string {
	dir := SocketDir(p, goos)
	n := p.Name
	if goos == "darwin" {
		prefix, src := PinnedSource(p, bin, pin, "shasum -a 256 -c -")
		return fmt.Sprintf(`set -eu
%[7]sdseditgroup -o read %[3]s >/dev/null 2>&1 || dseditgroup -o create %[3]s
id -u %[2]s >/dev/null 2>&1 || sysadminctl -addUser %[2]s -fullName "%[8]s console" -password -
dseditgroup -o edit -a %[1]s -t user %[3]s
%[4]sinstall -d -m 0755 -o root -g wheel /etc/%[8]s
cat > /etc/%[8]s/system.toml <<'SYSTEM_TOML'
%[5]sSYSTEM_TOML
chown root:wheel /etc/%[8]s/system.toml
chmod 0644 /etc/%[8]s/system.toml
install -d -m 0755 -o root -g wheel /usr/local/var/run
install -d -m 0710 -o %[2]s -g %[3]s %[6]s
`, o.Client, o.Service, o.Group, copyBinary(p, bin, pin, src, "wheel"), SystemTOML(p, o.Service, o.Group, dir, o.AllowedUIDs), dir, prefix, n)
	}
	// The socket directory is setgid: the console's account is not in the
	// clients group, and Linux lets it give its socket only to a group it
	// belongs to or to the directory's, which setgid makes the clients
	// group.
	prefix, src := PinnedSource(p, bin, pin, "sha256sum -c -")
	return fmt.Sprintf(`set -eu
%[7]sgetent group %[3]s >/dev/null || groupadd --system %[3]s
id -u %[2]s >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment "%[8]s console" %[2]s
chmod 0700 "$(getent passwd %[2]s | cut -d: -f6)"
usermod -aG %[3]s %[1]s
%[4]sinstall -d -m 0755 -o root -g root /etc/%[8]s
cat > /etc/%[8]s/system.toml <<'SYSTEM_TOML'
%[5]sSYSTEM_TOML
chown root:root /etc/%[8]s/system.toml
chmod 0644 /etc/%[8]s/system.toml
install -d -m 0755 -o root -g root /etc/tmpfiles.d
printf 'd %[6]s 2710 %[2]s %[3]s -\n' > /etc/tmpfiles.d/%[8]s.conf
systemd-tmpfiles --create /etc/tmpfiles.d/%[8]s.conf 2>/dev/null || install -d -m 2710 -o %[2]s -g %[3]s %[6]s
`, o.Client, o.Service, o.Group, copyBinary(p, bin, pin, src, "root"), SystemTOML(p, o.Service, o.Group, dir, o.AllowedUIDs), dir, prefix, n)
}

// FileOwner returns the owner of a file (ok false off Unix).
func FileOwner(fi os.FileInfo) (uid int, ok bool) { return fileOwner(fi) }

// FileLinks returns the hard link count of a file (ok false off Unix).
func FileLinks(fi os.FileInfo) (n int, ok bool) { return fileLinks(fi) }
