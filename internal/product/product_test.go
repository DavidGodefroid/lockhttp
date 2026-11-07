package product

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/refusal"
)

// No refusal hint the agent reads names lockhub's deprecated lox up, and
// the missing-console one names lox run.
func TestRefusalHintsNameLoxRun(t *testing.T) {
	for _, c := range []refusal.Code{CodeDenied, CodeTimeout, CodeHostUnknown, CodeFloor,
		CodeMethod, CodeExfilSuspect, CodeSecretEgress, CodePinned, CodeBodyTooLarge,
		CodePending, CodeNoConsole, CodeClaudeParam, CodeSourceUnknown, CodeRule, CodeInject} {
		if h := refusal.New(c, "x").Info("", 0).Hint; strings.Contains(h, "lox up") {
			t.Errorf("%s hint = %q names lox up", c, h)
		}
	}
	if h := refusal.New(CodeNoConsole, "x").Info("", 0).Hint; !strings.Contains(h, "lox run") {
		t.Errorf("%s hint = %q, want it to name lox run", CodeNoConsole, h)
	}
}
