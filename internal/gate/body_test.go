package gate

import (
	"strings"
	"testing"
)

// JSON written by a logger escapes blanks and delimiters: a value right
// after a `\t`, `\n` or `\u0026`-style escape is masked as after the
// character it stands for (lockkit v0.8.0 pii). lockkit v0.6.0 missed
// each case: the escape's last letter or digit ran into the value. (An
// email is found after one either way: its local part may start with a
// letter or digit.)
func TestPreviewMasksAfterJSONEscapes(t *testing.T) {
	for _, c := range []struct{ body, value string }{
		{`{"msg":"tel:\t0475123456"}`, "0475123456"},
		{`{"msg":"line\n0475123456"}`, "0475123456"},
		{`{"q":"a\u0026BE68539007547034"}`, "BE68539007547034"},
		{`{"q":"x\u003c0475123456\u003e"}`, "0475123456"},
	} {
		if p := Preview("application/json", []byte(c.body)); strings.Contains(p, c.value) {
			t.Errorf("%s: %s", c.body, p)
		}
	}
}
