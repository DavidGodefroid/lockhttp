package decide

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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

// claudeCredential denies a credential that is not the caller's.
func claudeCredential(r Request, creds Credentials) (Decision, bool) {
	if creds == nil || r.Header == nil {
		return Decision{}, false
	}
	var cred string
	if a := r.Header.Get("Authorization"); a != "" {
		if v, ok := strings.CutPrefix(a, "Bearer "); ok {
			cred = strings.TrimSpace(v)
		} else {
			cred = a
		}
	}
	if k := r.Header.Get("X-Api-Key"); k != "" {
		if cred != "" {
			return deny("claude:credential", product.CodeSecretEgress, "two credentials in one request"), true
		}
		cred = k
	}
	if cred == "" {
		return Decision{}, false
	}
	sum := sha256.Sum256([]byte(cred))
	on, ok := creds.Known(r.Container, r.Via, hex.EncodeToString(sum[:]))
	if on && !ok {
		return deny("claude:credential", product.CodeSecretEgress, "a credential that is not this container's (third-party key)"), true
	}
	return Decision{}, false
}

type messagesBody struct {
	MCPServers []json.RawMessage `json:"mcp_servers"`
	Tools      []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"tools"`
	Container json.RawMessage `json:"container"`
}

type mcpServer struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

// claudeMessages applies the parameter allowlist of /v1/messages.
func claudeMessages(r Request) Decision {
	if r.Body == nil {
		return Decision{Verdict: Ask, Rule: "claude:messages", Class: "claude", NeverAuto: true,
			Code: product.CodeClaudeParam, Warnings: []string{"the request body was not held: its parameters are unknown"}}
	}
	var b messagesBody
	if err := json.Unmarshal(r.Body, &b); err != nil {
		return Decision{Verdict: Ask, Rule: "claude:messages", Class: "claude", NeverAuto: true,
			Code: product.CodeClaudeParam, Warnings: []string{"the body is not JSON"}}
	}
	var warns []string
	for _, raw := range b.MCPServers {
		var s mcpServer
		_ = json.Unmarshal(raw, &s)
		warns = append(warns, fmt.Sprintf("mcp_servers: %q %s (the API calls this server for the agent)", s.Name, s.URL))
	}
	for _, t := range b.Tools {
		if t.Type == "" || t.Type == "custom" {
			continue
		}
		base := t.Type
		if i := strings.LastIndex(base, "_20"); i > 0 {
			base = base[:i]
		}
		if slices.Contains(serverToolsFree, base) {
			continue
		}
		if isClientTool(base) {
			continue
		}
		warns = append(warns, "server tool "+t.Type+" (runs outside lea)")
	}
	if len(b.Container) > 0 && string(b.Container) != "null" {
		warns = append(warns, "container parameter (code execution session)")
	}
	if len(warns) > 0 {
		return Decision{Verdict: Ask, Rule: "claude:messages-params", Class: "claude", NeverAuto: true, Red: true,
			Code: product.CodeClaudeParam, Warnings: warns}
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
