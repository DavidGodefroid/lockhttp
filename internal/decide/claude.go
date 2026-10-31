package decide

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/product"
)

// Credentials knows the hashes of the credentials each container (and
// keyproxy) may send to the Claude API.
type Credentials interface {
	// Known reports whether the check is on, and whether the sha256 hex of
	// the credential belongs to container (or to keyproxy when via is
	// "keyproxy").
	Known(container, via, sha256hex string) (on, ok bool)
}

// NoCredentials is the check switched off.
type NoCredentials struct{}

// Known implements Credentials.
func (NoCredentials) Known(string, string, string) (bool, bool) { return false, false }

// serverToolsFree are the server tools that run nothing outside the
// model's provider (decision D10).
var serverToolsFree = []string{"web_search"}

// claude decides a request to the Anthropic domains (§6.5).
func claude(r Request, creds Credentials) Decision {
	host := r.Host
	exact := slices.Contains(policy.ClaudeHosts, host)
	if r.Phase == PhaseConnect {
		if exact {
			return Decision{Verdict: Free, Rule: "claude:host", Class: "claude"}
		}
		return Decision{Verdict: Ask, Rule: "claude:other-host", Class: "claude", NeverAuto: true,
			Warnings: append([]string{"another host under the Anthropic domains: " + host}, connectWarning(r)...)}
	}
	if !exact {
		return Decision{Verdict: Ask, Rule: "claude:other-host", Class: "claude", NeverAuto: true,
			Warnings: []string{"another host under the Anthropic domains: " + host}}
	}
	if d, ok := claudeCredential(r, creds); ok {
		return d
	}
	path := r.Path
	switch {
	case isOAuth(host, path):
		return Decision{Verdict: Free, Rule: "claude:oauth", Class: "claude"}
	case host == "api.anthropic.com" && r.Method == http.MethodPost &&
		(path == "/v1/messages" || path == "/v1/messages/count_tokens"):
		return claudeMessages(r)
	case host == "api.anthropic.com" && strings.HasPrefix(path, "/v1/files"):
		return Decision{Verdict: Ask, Rule: "claude:files", Class: "claude", NeverAuto: true, Red: r.Method != http.MethodGet,
			Code: product.CodeClaudeParam, Warnings: []string{"Claude Files API: " + r.Method + " " + path}}
	case isRead(r):
		return Decision{Verdict: Free, Rule: "claude:read", Class: "claude"}
	}
	return Decision{Verdict: Ask, Rule: "claude:other-path", Class: "claude", NeverAuto: true,
		Code: product.CodeClaudeParam, Warnings: []string{"a Claude endpoint outside the allowlist: " + r.Method + " " + host + path}}
}

func isOAuth(host, path string) bool {
	switch host {
	case "claude.ai":
		return strings.HasPrefix(path, "/oauth/") || strings.HasPrefix(path, "/v1/oauth/")
	case "console.anthropic.com", "api.anthropic.com":
		return strings.HasPrefix(path, "/v1/oauth/")
	}
	return false
}

// claudeCredential denies a credential that is not the caller's. Every
// value of Authorization and X-Api-Key counts: two credentials, or a
// header sent twice, are denied (a server may read either one).
func claudeCredential(r Request, creds Credentials) (Decision, bool) {
	if creds == nil || r.Header == nil {
		return Decision{}, false
	}
	var found []string
	for _, a := range r.Header.Values("Authorization") {
		if v, ok := strings.CutPrefix(a, "Bearer "); ok {
			a = v
		}
		found = append(found, strings.TrimSpace(a))
	}
	for _, k := range r.Header.Values("X-Api-Key") {
		found = append(found, strings.TrimSpace(k))
	}
	if len(found) == 0 {
		return Decision{}, false
	}
	if len(found) > 1 {
		return deny("claude:credential", product.CodeSecretEgress, "more than one credential in one request"), true
	}
	sum := sha256.Sum256([]byte(found[0]))
	on, ok := creds.Known(r.Container, r.Via, hex.EncodeToString(sum[:]))
	if on && !ok {
		return deny("claude:credential", product.CodeSecretEgress, "a credential that is not this container's (third-party key)"), true
	}
	return Decision{}, false
}

// errAmbiguous marks JSON another parser could read differently: a
// duplicate key, or a key equal to a checked one but for its case.
var errAmbiguous = errors.New("ambiguous JSON")

// strictObject decodes a JSON object into its members, refusing duplicate
// keys and keys that fold to one of watch without matching it exactly
// (Go's decoder is case-insensitive, the API's may not be).
func strictObject(data []byte, watch ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		if _, dup := out[k]; dup {
			return nil, errAmbiguous
		}
		for _, w := range watch {
			if k != w && strings.EqualFold(k, w) {
				return nil, errAmbiguous
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// claudeMessages applies the parameter allowlist of /v1/messages.
func claudeMessages(r Request) Decision {
	ask := func(w ...string) Decision {
		return Decision{Verdict: Ask, Rule: "claude:messages-params", Class: "claude", NeverAuto: true, Red: true,
			Code: product.CodeClaudeParam, Warnings: w}
	}
	if r.Body == nil {
		return ask("the request body was not held: its parameters are unknown")
	}
	top, err := strictObject(r.Body, "mcp_servers", "tools", "container")
	if err != nil {
		return ask("the body is not an unambiguous JSON object")
	}
	var warns []string
	if raw, ok := top["mcp_servers"]; ok && string(raw) != "null" {
		var servers []json.RawMessage
		if err := json.Unmarshal(raw, &servers); err != nil {
			return ask("mcp_servers is not a list")
		}
		for _, sr := range servers {
			m, err := strictObject(sr, "url", "name")
			if err != nil {
				return ask("an mcp_servers entry is ambiguous")
			}
			var addr, name string
			_ = json.Unmarshal(m["url"], &addr)
			_ = json.Unmarshal(m["name"], &name)
			warns = append(warns, fmt.Sprintf("mcp_servers: %q %s (the API calls this server for the agent)", name, mcpServerURL(addr)))
		}
	}
	if raw, ok := top["tools"]; ok && string(raw) != "null" {
		var tools []json.RawMessage
		if err := json.Unmarshal(raw, &tools); err != nil {
			return ask("tools is not a list")
		}
		for _, tr := range tools {
			m, err := strictObject(tr, "type", "name")
			if err != nil {
				return ask("a tools entry is ambiguous")
			}
			var typ string
			if raw, ok := m["type"]; ok {
				if err := json.Unmarshal(raw, &typ); err != nil {
					return ask("a tool type is not a string")
				}
			}
			if typ == "" || typ == "custom" {
				continue
			}
			base := typ
			if i := strings.LastIndex(base, "_20"); i > 0 {
				base = base[:i]
			}
			if slices.Contains(serverToolsFree, base) || isClientTool(base) {
				continue
			}
			warns = append(warns, "server tool "+typ+" (runs outside lea)")
		}
	}
	if raw, ok := top["container"]; ok && string(raw) != "null" {
		warns = append(warns, "container parameter (code execution session)")
	}
	if len(warns) > 0 {
		return ask(warns...)
	}
	return Decision{Verdict: Free, Rule: "claude:messages", Class: "claude"}
}

// isClientTool reports an Anthropic-defined tool the client runs itself
// (its calls come back to the agent; nothing runs at Anthropic).
func isClientTool(base string) bool {
	switch base {
	case "bash", "text_editor", "computer", "memory":
		return true
	}
	return false
}

// mcpServerURL is an MCP server URL for the warnings (shown and audited):
// without its userinfo, query or fragment, which may carry a credential.
// The host and path stay: the human decides on the server they name.
func mcpServerURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(not an absolute URL)"
	}
	hidden := u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != ""
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	if hidden {
		return u.String() + " (credentials, query or fragment not shown)"
	}
	return u.String()
}
