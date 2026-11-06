package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
)

// SecretsVersion is the version of the gate's secrets file.
const SecretsVersion = 1

// MinSecretLen is the shortest secret value the gate accepts: shorter
// values would match ordinary text in the leak check.
const MinSecretLen = 8

// secretsFile is the gate's secrets file: the values the policy's
// injections name. It lives in the gate's container only (never the
// agent's), readable by the gate's uid alone.
type secretsFile struct {
	Version int               `json:"version"`
	Secrets map[string]string `json:"secrets"`
}

// Secrets holds the values of the gate's secrets file, reloaded when the
// file changes. An unreadable, group- or world-readable or invalid file
// is broken: every injection fails closed (E_INJECT), and the values
// last loaded stay in the leak check.
type Secrets struct {
	path string

	mu      sync.Mutex
	vals    map[string]string
	err     error
	modTime time.Time
	// known keeps every value ever loaded, for the leak check: a secret
	// rotated out is still not sent by the agent.
	known map[string]string
	// forms caches the forms of known (nil: to compute).
	forms *formSet
}

// NewSecrets loads path ("" for none: no injection, no leak check).
func NewSecrets(path string) *Secrets {
	s := &Secrets{path: path, known: map[string]string{}}
	s.Reload()
	return s
}

// Err is the file's last load error (nil when it loaded, or with no file).
func (s *Secrets) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Reload reads the file again when it changed.
func (s *Secrets) Reload() {
	if s == nil || s.path == "" {
		return
	}
	fi, err := os.Stat(s.path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && s.vals != nil && fi.ModTime().Equal(s.modTime) {
		return
	}
	vals, err := loadSecrets(s.path, fi, err)
	if err != nil {
		s.vals, s.err = nil, err
		return
	}
	s.vals, s.err, s.modTime = vals, nil, fi.ModTime()
	for k, v := range vals {
		if _, ok := s.known[k+"\x00"+v]; !ok {
			s.known[k+"\x00"+v] = v
			s.forms = nil
		}
	}
}

func loadSecrets(path string, fi os.FileInfo, statErr error) (map[string]string, error) {
	if statErr != nil {
		return nil, fmt.Errorf("secrets file: %w", statErr)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secrets file %s is readable by others (mode %o): chmod 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets file: %w", err)
	}
	var f secretsFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		// Never echo the content: it holds secrets.
		return nil, errors.New("secrets file: not valid JSON of the form {\"version\":1,\"secrets\":{\"name\":\"value\"}}")
	}
	if f.Version != SecretsVersion {
		return nil, fmt.Errorf("secrets file: version must be %d", SecretsVersion)
	}
	vals := map[string]string{}
	for k, v := range f.Secrets {
		if !policy.CredentialName(k) {
			return nil, errors.New("secrets file: a secret's name uses lower-case letters, digits, '_', '-' or '.' (at most 32, no run of 17 letters or digits)")
		}
		if len(v) < MinSecretLen {
			return nil, fmt.Errorf("secrets file: secret %s is shorter than %d bytes", k, MinSecretLen)
		}
		for i := 0; i < len(v); i++ {
			// A header value: no control character (CR and LF would split
			// the request), no space at either end, printable ASCII.
			c := v[i]
			if ok := (c >= 0x21 && c <= 0x7e) || (c == ' ' && i > 0 && i < len(v)-1); !ok {
				return nil, fmt.Errorf("secrets file: secret %s holds a character a header value may not", k)
			}
		}
		vals[k] = v
	}
	return vals, nil
}

// Value returns the secret named name.
func (s *Secrets) Value(name string) (string, error) {
	if s == nil || s.path == "" {
		return "", errors.New("the gate has no secrets file (--secrets)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	v, ok := s.vals[name]
	if !ok {
		return "", fmt.Errorf("the gate's secrets file has no secret %q", name)
	}
	return v, nil
}

// Leak reports the name of a secret found in what the agent sent: its
// path, query, header values or held body, as is, URL-escaped (in any
// case), hex or base64 (at any alignment). The agent never holds an
// injected secret: one in its request is refused, whatever the host.
func (s *Secrets) Leak(parts ...[]byte) (string, bool) {
	fs := s.Forms()
	for _, p := range parts {
		if name, ok := fs.findDecoded(p); ok {
			return name, true
		}
	}
	return "", false
}

// Forms returns the forms of every value ever loaded (nil with none).
func (s *Secrets) Forms() *formSet {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.known) == 0 {
		return nil
	}
	if s.forms == nil {
		vals := map[string][]string{}
		for k, v := range s.known {
			name, _, _ := strings.Cut(k, "\x00")
			vals[name] = append(vals[name], v)
		}
		s.forms = formsOf(vals)
	}
	return s.forms
}

// Active reports whether the gate holds any secret value: the streams the
// agent sends are then scanned for them.
func (s *Secrets) Active() bool { return !s.Forms().empty() }
