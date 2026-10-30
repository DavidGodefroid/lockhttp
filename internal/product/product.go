// Package product declares lockhttp's names for lockkit and its refusal
// codes.
package product

import (
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/refusal"
)

// P is lockhttp as a lockkit product: its binary, directories, console
// account, clients group, keychain service and environment prefix.
var P = kit.Product{
	Name:            "lockhttp",
	Tagline:         "Your AI browses. You hold the key.",
	Account:         "lockhttp",
	ClientsGroup:    "lockhttp-clients",
	KeychainService: "lockhttp",
	EnvPrefix:       "LOCKHTTP_",
}

// Refusal codes of lockhttp. They are part of the gate's protocol (the
// X-LockHTTP-Code header of a refusal): never rename one.
const (
	CodeDenied        refusal.Code = "E_DENIED"
	CodeTimeout       refusal.Code = "E_TIMEOUT"
	CodeHostUnknown   refusal.Code = "E_HOST_UNKNOWN"
	CodeFloor         refusal.Code = "E_FLOOR"
	CodeMethod        refusal.Code = "E_METHOD"
	CodeExfilSuspect  refusal.Code = "E_EXFIL_SUSPECT"
	CodeSecretEgress  refusal.Code = "E_SECRET_EGRESS"
	CodePinned        refusal.Code = "E_PINNED"
	CodeBodyTooLarge  refusal.Code = "E_BODY_TOO_LARGE"
	CodePending       refusal.Code = "E_PENDING"
	CodeNoConsole     refusal.Code = "E_NO_CONSOLE"
	CodeClaudeParam   refusal.Code = "E_CLAUDE_API_PARAM"
	CodeSourceUnknown refusal.Code = "E_SOURCE_UNKNOWN"
	CodeRule          refusal.Code = "E_RULE"
	CodeWithdrawn     refusal.Code = "E_WITHDRAWN"
)

func init() {
	refusal.Register(CodeDenied, refusal.RetryAskUser,
		"the human denied the request", "do not retry the same request; ask the user what they want instead")
	refusal.Register(CodeTimeout, refusal.RetryAskUser,
		"nobody answered the approval in time", "ask the user to watch the lockhttp console, then retry")
	refusal.Register(CodeHostUnknown, refusal.RetryAskUser,
		"the host is not trusted and needs a human", "ask the user to approve the host in the lockhttp console")
	refusal.Register(CodeFloor, refusal.RetryStop,
		"the request hits the network floor (IP literal, DoH, private range, port, SNI mismatch, h2c)", "use a named public host on port 80 or 443")
	refusal.Register(CodeMethod, refusal.RetryAskUser,
		"the method is not allowed for this host", "ask the user for a rule allowing it")
	refusal.Register(CodeExfilSuspect, refusal.RetryAskUser,
		"the request looks like data exfiltration", "send less data in the URL and headers, or ask the user")
	refusal.Register(CodeSecretEgress, refusal.RetryStop,
		"the request carries a credential outside its legitimate host", "never send a credential to another host")
	refusal.Register(CodePinned, refusal.RetryStop,
		"the client refused the gate's certificate (pinning)", "ask the user to add the host to the splice list")
	refusal.Register(CodeBodyTooLarge, refusal.RetryAskUser,
		"the body is larger than the buffer limit", "send a smaller body, or ask the user for a rule")
	refusal.Register(CodePending, refusal.RetryAskUser,
		"the request waits for the human", "retry the same request in a moment: once approved it goes through")
	refusal.Register(CodeNoConsole, refusal.RetryAskUser,
		"no lockhttp console is running", "ask the user to run: lockhttp console")
	refusal.Register(CodeClaudeParam, refusal.RetryAskUser,
		"a Claude API parameter needs a human (mcp_servers, a server tool, files)", "ask the user to approve it in the lockhttp console")
	refusal.Register(CodeSourceUnknown, refusal.RetryStop,
		"the gate cannot tell which container sent the request", "connect through the proxy address lea gave you")
	refusal.Register(CodeWithdrawn, refusal.RetryRewrite,
		"the hub ticket of this request was withdrawn: the gate now runs without its hub", "send the same request again: the human answers it in the lockhttp console")
	refusal.Register(CodeRule, refusal.RetryAskUser,
		"a policy rule denies the request", "ask the user to change the rule")
}
