package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// AuditRetention is how long the gate keeps its daily audit files.
const AuditRetention = 30 * 24 * time.Hour

// AuditLog is the gate's JSONL audit of FREE and DENY decisions (the
// console audits the asks): one file per UTC day, gate-YYYY-MM-DD.jsonl,
// kept 30 days. With no directory it writes to w (stderr) or nowhere.
type AuditLog struct {
	dir string
	w   io.Writer
	now func() time.Time

	mu  sync.Mutex
	day string
	f   *os.File
}

// NewAuditLog opens dir (created 0700) or, when dir is "", writes to w.
func NewAuditLog(dir string, w io.Writer, now func() time.Time) (*AuditLog, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
	}
	return &AuditLog{dir: dir, w: w, now: now}, nil
}

type stamped struct {
	TS string `json:"ts"`
	wire.Record
}

// Append writes one record.
func (l *AuditLog) Append(rec wire.Record) {
	if l == nil {
		return
	}
	now := l.now().UTC()
	b, err := json.Marshal(stamped{TS: now.Format("2006-01-02T15:04:05.000Z"), Record: rec})
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dir == "" {
		if l.w != nil {
			_, _ = l.w.Write(b)
		}
		return
	}
	day := now.Format(time.DateOnly)
	if day != l.day || l.f == nil {
		if l.f != nil {
			_ = l.f.Close()
		}
		f, err := os.OpenFile(filepath.Join(l.dir, "gate-"+day+".jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			l.f = nil
			return
		}
		l.f, l.day = f, day
		l.prune(now)
	}
	_, _ = l.f.Write(b)
}

// prune removes daily files older than AuditRetention.
func (l *AuditLog) prune(now time.Time) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		d, ok := strings.CutPrefix(name, "gate-")
		if !ok || !strings.HasSuffix(d, ".jsonl") {
			continue
		}
		t, err := time.Parse(time.DateOnly, strings.TrimSuffix(d, ".jsonl"))
		if err == nil && now.Sub(t) > AuditRetention {
			_ = os.Remove(filepath.Join(l.dir, name))
		}
	}
}

// Close closes the current file.
func (l *AuditLog) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}

// Status is the status file lea reads (docs/lea.md §5).
type Status struct {
	Version            int            `json:"version"`
	Console            string         `json:"console"`
	Pending            int            `json:"pending"`
	PendingByContainer map[string]int `json:"pending_by_container"`
	PolicyFP           string         `json:"policy_fp,omitempty"`
	Updated            string         `json:"updated"`
}

// writeStatus writes s to path atomically.
func writeStatus(path string, s Status) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
