package gate

import (
	"strings"
	"testing"
)

// The agent's hint for a missing console names the command that starts
// it: lox run, not lockhub's deprecated lox up.
func TestNoConsoleHintNamesLoxRun(t *testing.T) {
	h := hintFor("E_NO_CONSOLE")
	if !strings.Contains(h, "lox run") || strings.Contains(h, "lox up") {
		t.Errorf("E_NO_CONSOLE hint = %q, want it to name lox run", h)
	}
}
