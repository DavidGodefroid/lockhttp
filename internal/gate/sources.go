package gate

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// ContractVersion is the version of the files lea writes for the gate.
const ContractVersion = 1

// sourcesFile is sources.json (docs/lea.md §2.3).
type sourcesFile struct {
	Version  int `json:"version"`
	Networks []struct {
		LocalIP   string `json:"local_ip"`
		Container string `json:"container"`
		Project   string `json:"project"`
	} `json:"networks"`
	Keyproxy struct {
		TokenSHA256 string `json:"token_sha256"`
	} `json:"keyproxy"`
	Agents []struct {
		TokenSHA256 string `json:"token_sha256"`
		Container   string `json:"container"`
		Agent       string `json:"agent"`
		Role        string `json:"role"`
		Parent      string `json:"parent"`
		TaskID      string `json:"task_id"`
		Branch      string `json:"branch"`
		SessionID   string `json:"session_id"`
	} `json:"agents"`
}

// sourceMap is a loaded sources file.
type sourceMap struct {
	byIP     map[netip.Addr]wire.Source
	byName   map[string]wire.Source
	keyproxy []byte
	agents   map[string]wire.Source // by token sha256 hex
}

func parseSources(b []byte) (*sourceMap, error) {
	var f sourcesFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("sources: %w", err)
	}
	if f.Version != ContractVersion {
		return nil, fmt.Errorf("sources: version %d, this gate reads version %d", f.Version, ContractVersion)
	}
	m := &sourceMap{byIP: map[netip.Addr]wire.Source{}, byName: map[string]wire.Source{}, agents: map[string]wire.Source{}}
	for i, n := range f.Networks {
		ip, err := netip.ParseAddr(n.LocalIP)
		if err != nil || n.Container == "" {
			// The entry's place, never its values.
			return nil, fmt.Errorf("sources: networks entry %d: local_ip must be an IP address and container is required", i+1)
		}
		s := wire.Source{Container: n.Container, Project: n.Project}
		m.byIP[ip.Unmap()] = s
		m.byName[n.Container] = s
	}
	if f.Keyproxy.TokenSHA256 != "" {
		k, err := hex.DecodeString(f.Keyproxy.TokenSHA256)
		if err != nil || len(k) != sha256.Size {
			return nil, errors.New("sources: keyproxy.token_sha256 is not a sha256")
		}
		m.keyproxy = k
	}
	for _, a := range f.Agents {
		if _, err := hex.DecodeString(a.TokenSHA256); err != nil || len(a.TokenSHA256) != 64 {
			return nil, errors.New("sources: an agent token_sha256 is not a sha256")
		}
		m.agents[a.TokenSHA256] = wire.Source{Container: a.Container, Agent: a.Agent, Role: a.Role, Parent: a.Parent,
			TaskID: a.TaskID, Branch: a.Branch, SessionID: a.SessionID}
	}
	return m, nil
}

// Sources resolves who sent a connection. With no file it runs in
// standalone mode: every connection is container "local".
type Sources struct {
	path string

	mu      sync.Mutex
	m       *sourceMap
	err     error
	modTime time.Time
	size    int64
}

// NewSources loads path ("" for standalone mode).
func NewSources(path string) *Sources {
	s := &Sources{path: path}
	s.Reload()
	return s
}

// Reload reads the file again when it changed. A file that cannot be read
// or parsed fails closed: every lookup is refused until it is fixed.
func (s *Sources) Reload() {
	if s.path == "" {
		return
	}
	fi, err := os.Stat(s.path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && s.m != nil && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return
	}
	if err != nil {
		s.m, s.err = nil, fmt.Errorf("sources: %w", err)
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		s.m, s.err = nil, fmt.Errorf("sources: %w", err)
		return
	}
	m, err := parseSources(b)
	s.m, s.err = m, err
	s.modTime, s.size = fi.ModTime(), fi.Size()
}

// Err is the load error, if any.
func (s *Sources) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// errUnknownSource refuses a connection the map does not name.
var errUnknownSource = errors.New("unknown source")

// Resolve names the source of a request that arrived on local address
// local, with the agent and token of its Proxy-Authorization (if any)
// and the X-Lea-Source header (keyproxy only).
func (s *Sources) Resolve(local netip.Addr, user, token, leaSource string) (wire.Source, error) {
	local = local.Unmap()
	if s.path == "" {
		src := wire.Source{Container: "local", Via: "direct", Agent: user, Attribution: "none"}
		if user != "" {
			src.Attribution = "proxy-auth"
		}
		return src, nil
	}
	s.mu.Lock()
	m, err := s.m, s.err
	s.mu.Unlock()
	if m == nil {
		if err == nil {
			err = errUnknownSource
		}
		return wire.Source{}, err
	}
	sum := sha256.Sum256([]byte(token))
	if local.IsLoopback() {
		// keyproxy, inside the proxy container: it must prove itself with
		// its token, and names the container it relays for.
		if token == "" || m.keyproxy == nil || subtle.ConstantTimeCompare(sum[:], m.keyproxy) != 1 {
			return wire.Source{}, fmt.Errorf("%w: loopback without the keyproxy token", errUnknownSource)
		}
		src, ok := m.byName[leaSource]
		if !ok {
			return wire.Source{}, fmt.Errorf("%w: keyproxy relays for unknown container %q", errUnknownSource, leaSource)
		}
		src.Via, src.Agent, src.Attribution = "keyproxy", "keyproxy", "keyproxy"
		return src, nil
	}
	src, ok := m.byIP[local]
	if !ok {
		return wire.Source{}, fmt.Errorf("%w: local address %s", errUnknownSource, local)
	}
	src.Via, src.Attribution = "direct", "none"
	if token == "" {
		return src, nil
	}
	a, ok := m.agents[hex.EncodeToString(sum[:])]
	switch {
	case !ok:
		src.Agent, src.Attribution = user, "unverified"
	case a.Container != src.Container:
		src.Agent, src.Attribution = user, "ambiguous"
	default:
		src.Agent, src.Role, src.Parent, src.TaskID, src.Branch, src.SessionID = a.Agent, a.Role, a.Parent, a.TaskID, a.Branch, a.SessionID
		src.Attribution = "proxy-auth"
		if a.Agent == "nested" {
			src.Via, src.Attribution = "nested", "nested"
		}
	}
	return src, nil
}

// credentialsFile is credentials.json (docs/lea.md §2.4).
type credentialsFile struct {
	Version    int                 `json:"version"`
	Containers map[string][]string `json:"containers"`
	Keyproxy   []string            `json:"keyproxy"`
}

// Credentials implements decide.Credentials from credentials.json; with
// no file the check is off. An unreadable file fails closed: every
// credential is unknown.
type Credentials struct {
	path string

	mu      sync.Mutex
	f       *credentialsFile
	broken  bool
	modTime time.Time
}

// NewCredentials loads path ("" for none).
func NewCredentials(path string) *Credentials {
	c := &Credentials{path: path}
	c.Reload()
	return c
}

// Reload reads the file again when it changed.
func (c *Credentials) Reload() {
	if c.path == "" {
		return
	}
	fi, err := os.Stat(c.path)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil && c.f != nil && fi.ModTime().Equal(c.modTime) {
		return
	}
	var f credentialsFile
	b, err := os.ReadFile(c.path)
	if err == nil {
		err = json.Unmarshal(b, &f)
	}
	if err != nil || f.Version != ContractVersion {
		c.f, c.broken = nil, true
		return
	}
	c.f, c.broken = &f, false
	if fi != nil {
		c.modTime = fi.ModTime()
	}
}

// Known implements decide.Credentials.
func (c *Credentials) Known(container, via, sum string) (bool, bool) {
	if c.path == "" {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return true, false
	}
	list := c.f.Containers[container]
	if via == "keyproxy" {
		list = c.f.Keyproxy
	}
	for _, s := range list {
		if subtle.ConstantTimeCompare([]byte(s), []byte(sum)) == 1 {
			return true, true
		}
	}
	return true, false
}
