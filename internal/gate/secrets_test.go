//go:build unix

package gate

import (
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
