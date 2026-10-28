// Package wire is the protocol between the gate (a lockkit client) and
// the console: the methods, their parameters and results, and the audit
// record both sides write.
package wire

import (
	"github.com/DavidGodefroid/lockkit/audit"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
)

// Methods the console serves to the gate.
const (
	// MethodApprove asks the human about one held request.
	MethodApprove = "http.approve"
	// MethodPolicy returns the approved policy in force.
	MethodPolicy = "policy.get"
)

// Limits on what the gate may send (the console refuses more).
const (
	MaxPreview  = 1024
	MaxText     = 512
	MaxWarnings = 16
	MaxRefs     = 32
)

// Source says who sent a request: the container (from the network the
// connection arrived on, reliable), the agent (from Proxy-Authorization,
// declarative) and lea's task metadata.
type Source struct {
	Container   string `json:"container,omitempty"`
	Project     string `json:"project,omitempty"`
	Via         string `json:"via,omitempty"`
	Agent       string `json:"agent,omitempty"`
	Attribution string `json:"attribution,omitempty"`
	Role        string `json:"role,omitempty"`
	Parent      string `json:"parent,omitempty"`
	TaskID      string `json:"task_id,omitempty"`
	Branch      string `json:"branch,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
}

// Target is what a request does, never with its body or secret values.
type Target struct {
	Phase  string `json:"phase,omitempty"`
	TLS    string `json:"tls,omitempty"` // connect, mitm, plain
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	// QueryLen and QueryHash stand for the query string.
	QueryLen   int      `json:"query_len,omitempty"`
	QueryHash  string   `json:"query_hash,omitempty"`
	ReqHeaders []string `json:"req_headers,omitempty"`
	ReqBytes   int64    `json:"req_bytes,omitempty"`
	// BodyFP is the normalised body fingerprint.
	BodyFP string `json:"body_fp,omitempty"`
}

// ApproveParams describe one held request (one item: requests of the same
// fingerprint share it).
type ApproveParams struct {
	RequestID string `json:"request_id"`
	Source
	Target
	ContentType string `json:"content_type,omitempty"`
	// Preview is the start of the body, masked (personal data, secrets).
	Preview string `json:"preview,omitempty"`
	// Refs are the refs a git push updates.
	Refs []string `json:"refs,omitempty"`
	// Rule is what decided ASK; RuleAuto claims a verdict="auto" rule,
	// which the console checks against its own approved policy.
	Rule      string   `json:"rule,omitempty"`
	RuleAuto  bool     `json:"rule_auto,omitempty"`
	NeverAuto bool     `json:"never_auto"`
	Red       bool     `json:"red,omitempty"`
	Class     string   `json:"class,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Score     int      `json:"score,omitempty"`
	// Pending counts the distinct items waiting under the same container,
	// host, method and path (this one included).
	Pending int `json:"pending,omitempty"`
	// ClientGone: the agent's client left; approving creates a
	// single-use authorisation (10 min) for the same request.
	ClientGone bool `json:"client_gone,omitempty"`
	// ReplayOf names the item this request replays with another body.
	ReplayOf string `json:"replay_of,omitempty"`
	// Grant is how long an approved CONNECT opens the host (seconds).
	Grant int64 `json:"grant,omitempty"`
}

// ApproveResult is the console's answer when the human (or auto mode)
// approved. A denial, a timeout or a gone client is an RPC error.
type ApproveResult struct {
	Approved bool `json:"approved"`
	Auto     bool `json:"auto,omitempty"`
}

// PolicyResult is the approved policy in force and its fingerprint.
type PolicyResult struct {
	Policy      policy.Policy `json:"policy"`
	Fingerprint string        `json:"fingerprint"`
}

// Record is lockhttp's audit record: lockkit's Base and the request's
// correlation and HTTP fields (never a body, a query or a secret).
type Record struct {
	audit.Base
	RequestID string `json:"request_id,omitempty"`
	Source
	Target
	Rule        string `json:"rule,omitempty"`
	Class       string `json:"class,omitempty"`
	Score       int    `json:"score,omitempty"`
	ShadowScore int    `json:"shadow_score,omitempty"`
	Shadow      string `json:"shadow,omitempty"`
	Status      int    `json:"status,omitempty"`
	RespBytes   int64  `json:"resp_bytes,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	PolicyFP    string `json:"policy_fp,omitempty"`
}
