package gate

import (
	"strings"
	"testing"
)

// JSON written by a logger escapes blanks: a value right after a `\t`,
// `\n` or `&`-style escape is masked as after the blank (lockkit
// v0.8.0 pii).
func TestPreviewMasksAfterJSONEscapes(t *testing.T) {
	for _, body := range []string{
		`{"msg":"tel:\t0475123456"}`,
		`{"msg":"line\njane.doe@example.com"}`,
		`{"q":"a&mail=jane.doe@example.com"}`,
	} {
		p := Preview("application/json", []byte(body))
		if strings.Contains(p, "0475123456") || strings.Contains(p, "jane.doe@example.com") {
			t.Errorf("%s: %s", body, p)
		}
	}
}
