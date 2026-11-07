package policy

import (
	"strings"
	"testing"
)

func TestDefaultConfigComments(t *testing.T) {
	c := DefaultConfig("web", false, nil)
	if strings.Contains(c, `verdict = "auto"`) {
		t.Error("default config must not show verdict = \"auto\"")
	}
	if strings.Contains(c, "auto mode") {
		t.Error("stale: lockhub has no auto mode for the gate's asks")
	}
	if !strings.Contains(c, "lox attach") || !strings.Contains(c, ":review") {
		t.Error("say how :review is reached under lox run")
	}
}
