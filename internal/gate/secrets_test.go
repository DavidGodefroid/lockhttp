//go:build unix

package gate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretsLoad(t *testing.T) {
	p := writeSecrets(t, map[string]string{"ha-token": haSecret})
	s := NewSecrets(p)
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Value("ha-token"); err != nil || v != haSecret {
		t.Fatalf("value %q %v", v, err)
	}
	if _, err := s.Value("other"); err == nil || !strings.Contains(err.Error(), `no secret "other"`) {
		t.Fatalf("missing: %v", err)
	}
	if name, ok := s.Leak([]byte("x " + haSecret)); !ok || name != "ha-token" {
		t.Fatalf("leak %q %v", name, ok)
	}
	if _, ok := s.Leak([]byte("nothing here")); ok {
		t.Fatal("false leak")
	}
	// Rotated: the new value is served, the old one is still a leak.
	if err := os.WriteFile(p, []byte(`{"version":1,"secrets":{"ha-token":"rotated-value-123"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(p, future, future)
	s.Reload()
	if v, _ := s.Value("ha-token"); v != "rotated-value-123" {
		t.Fatalf("not reloaded: %q", v)
	}
	if _, ok := s.Leak([]byte(haSecret)); !ok {
		t.Fatal("a rotated-out value must stay in the leak check")
	}
}

// A rewrite that keeps the size and the mtime (a rotation within one
// mtime tick) is still reloaded: Reload compares the content's sha256.
func TestSecretsReloadSameMtime(t *testing.T) {
	p := writeSecrets(t, map[string]string{"ha-token": haSecret})
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSecrets(p)
	rotated := strings.Repeat("r", len(haSecret))
	rewrite := func(content string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
			t.Fatal(err)
		}
		if got, err := os.Stat(p); err != nil || !got.ModTime().Equal(fi.ModTime()) {
			t.Fatalf("mtime not set back: %v", err)
		}
	}
	rewrite(`{"version":1,"secrets":{"ha-token":"` + rotated + `"}}`)
	s.Reload()
	if v, err := s.Value("ha-token"); err != nil || v != rotated {
		t.Fatalf("same-mtime rewrite not reloaded: %q %v", v, err)
	}
	for _, v := range []string{haSecret, rotated} {
		if name, ok := s.Leak([]byte(v)); !ok || name != "ha-token" {
			t.Fatalf("%q not in the leak check", v)
		}
	}

	// Unchanged: not parsed again, the forms are kept.
	vals, forms := s.vals, s.Forms()
	s.Reload()
	if fmt.Sprintf("%p", s.vals) != fmt.Sprintf("%p", vals) || s.Forms() != forms {
		t.Fatal("an unchanged file was parsed again")
	}

	// Invalid with the same mtime: fail-closed, the values stay leaks.
	rewrite(`{"version":1,"secrets":{"ha-token":"` + rotated + `"`)
	s.Reload()
	if s.Err() == nil {
		t.Fatal("an invalid same-mtime rewrite must set Err")
	}
	if _, err := s.Value("ha-token"); err == nil {
		t.Fatal("an invalid file must refuse every injection")
	}
	if _, ok := s.Leak([]byte(rotated)); !ok {
		t.Fatal("the last values must stay in the leak check")
	}
}

func TestSecretsNone(t *testing.T) {
	s := NewSecrets("")
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	if _, err := s.Value("x"); err == nil {
		t.Fatal("no file serves no secret")
	}
	if _, ok := s.Leak([]byte("anything")); ok {
		t.Fatal("no file, no leak")
	}
}

func TestSecretsRefused(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		body string
		mode os.FileMode
		want string
	}{
		"world readable": {`{"version":1,"secrets":{"a":"abcdefghij"}}`, 0o644, "readable by others"},
		"bad json":       {`{"version":1,"secrets":{"a":"abcdefghij-SECRETVAL"`, 0o600, "not valid JSON"},
		"unknown key":    {`{"version":1,"secrets":{},"x":1}`, 0o600, "not valid JSON"},
		"version":        {`{"version":2,"secrets":{}}`, 0o600, "version"},
		"short":          {`{"version":1,"secrets":{"a":"short"}}`, 0o600, "shorter than"},
		"newline":        {`{"version":1,"secrets":{"a":"abcdefgh\r\nX-Evil: 1"}}`, 0o600, "may not"},
		"edge space":     {`{"version":1,"secrets":{"a":" abcdefgh"}}`, 0o600, "may not"},
		"bad name":       {`{"version":1,"secrets":{"A B":"abcdefghij"}}`, 0o600, "name"},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(c.body), c.mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, c.mode)
		s := NewSecrets(p)
		err := s.Err()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "SECRETVAL") {
			t.Errorf("%s: the error echoes the file", name)
		}
		if _, err := s.Value("a"); err == nil {
			t.Errorf("%s: a broken file served a secret", name)
		}
	}
	if s := NewSecrets(filepath.Join(dir, "absent.json")); s.Err() == nil {
		t.Error("an absent file must be an error")
	}
}
