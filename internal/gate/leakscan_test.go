package gate

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

func testForms() *formSet {
	return formsOf(map[string][]string{"ha-token": {haSecret}})
}

// The value is found in every form, base64 at each alignment inside a
// longer blob.
func TestFormsFindEncodings(t *testing.T) {
	fs := testForms()
	v := []byte(haSecret)
	cases := map[string]string{
		"raw":       "x" + haSecret + "y",
		"hex":       "k=" + hex.EncodeToString(v),
		"HEX":       "k=" + strings.ToUpper(hex.EncodeToString(v)),
		"lowercase": "k=" + strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(string(v), "-", "%2D"), "0", "%30")),
	}
	for pre := 0; pre < 3; pre++ {
		blob := append(append(bytes.Repeat([]byte("Z"), pre), v...), []byte("tail")...)
		cases["b64 offset "+string(rune('0'+pre))] = base64.StdEncoding.EncodeToString(blob)
		cases["b64url offset "+string(rune('0'+pre))] = base64.RawURLEncoding.EncodeToString(blob)
	}
	for name, s := range cases {
		if n, ok := fs.findDecoded([]byte(s)); !ok || n != "ha-token" {
			t.Errorf("%s: %q not matched", name, s)
		}
	}
	if _, ok := fs.findDecoded([]byte("nothing to see " + base64.StdEncoding.EncodeToString([]byte("ha-long-lived")))); ok {
		t.Fatal("a prefix of the value matched")
	}
}

// The streaming check aborts before a value split across reads goes out
// whole.
func TestScanReaderAbortsSplitValue(t *testing.T) {
	fs := testForms()
	src := strings.Repeat("a", 100000) + haSecret + strings.Repeat("b", 1000)
	sr := &scanReader{r: iotest.OneByteReader(strings.NewReader(src)), fs: fs}
	got, err := io.ReadAll(sr)
	if !errors.Is(err, errLeak) || len(sr.found) != 1 || sr.found[0] != "ha-token" {
		t.Fatalf("err %v found %v", err, sr.found)
	}
	if bytes.Contains(got, []byte(haSecret[:len(haSecret)-1])) {
		t.Fatal("the value went out (all but its last byte)")
	}
	// A clean stream passes whole.
	clean := strings.Repeat("c", 70000)
	sr = &scanReader{r: iotest.HalfReader(strings.NewReader(clean)), fs: fs}
	if got, err := io.ReadAll(sr); err != nil || string(got) != clean {
		t.Fatalf("clean stream: %v, %d bytes", err, len(got))
	}
}

func TestScanReaderRedacts(t *testing.T) {
	fs := testForms()
	src := "head " + haSecret + " mid " + base64.StdEncoding.EncodeToString([]byte(haSecret)) + " end"
	sr := &scanReader{r: iotest.OneByteReader(strings.NewReader(src)), fs: fs, redact: true}
	got, err := io.ReadAll(sr)
	if err != nil || len(got) != len(src) {
		t.Fatalf("err %v, %d bytes for %d", err, len(got), len(src))
	}
	if strings.Contains(string(got), haSecret) || strings.Contains(string(got), base64.StdEncoding.EncodeToString([]byte(haSecret))[:20]) {
		t.Fatalf("not redacted: %q", got)
	}
	if !strings.HasPrefix(string(got), "head ****") || !strings.HasSuffix(string(got), " end") {
		t.Fatalf("redacted the wrong bytes: %q", got)
	}
}

func wsFrame(payload []byte, key [4]byte) []byte {
	f := []byte{0x81}
	switch {
	case len(payload) < 126:
		f = append(f, 0x80|byte(len(payload)))
	default:
		f = append(f, 0x80|126)
		f = binary.BigEndian.AppendUint16(f, uint16(len(payload)))
	}
	f = append(f, key[:]...)
	for i, b := range payload {
		f = append(f, b^key[i%4])
	}
	return f
}

// A masked frame is unmasked to be matched, across frames too; the frame
// that completes the value is not sent.
func TestCopyWebSocket(t *testing.T) {
	fs := testForms()
	k := [4]byte{1, 2, 3, 4}
	var in bytes.Buffer
	in.Write(wsFrame([]byte("hello"), k))
	in.Write(wsFrame(bytes.Repeat([]byte("x"), 300), k))
	half := len(haSecret) / 2
	in.Write(wsFrame([]byte("a "+haSecret[:half]), k))
	in.Write(wsFrame([]byte(haSecret[half:]+" b"), k))
	in.Write(wsFrame([]byte("after"), k))
	var out bytes.Buffer
	n, leak, oversized := copyWebSocket(&out, &in, fs, 1<<20)
	if leak != "ha-token" || oversized {
		t.Fatalf("leak %q oversized %v", leak, oversized)
	}
	want := len(wsFrame([]byte("hello"), k)) + len(wsFrame(bytes.Repeat([]byte("x"), 300), k)) + len(wsFrame([]byte("a "+haSecret[:half]), k))
	if int(n) != want || out.Len() != want {
		t.Fatalf("sent %d bytes, want %d (the frames before the one completing the value)", n, want)
	}
	// An oversized frame stops the copy.
	in.Reset()
	in.Write(wsFrame(bytes.Repeat([]byte("y"), 2000), k))
	out.Reset()
	if _, _, oversized := copyWebSocket(&out, &in, fs, 1000); !oversized || out.Len() != 0 {
		t.Fatalf("oversized frame: %v, %d bytes sent", oversized, out.Len())
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return b.Bytes()
}

func TestEncodedLeak(t *testing.T) {
	fs := testForms()
	if n, why := encodedLeak("gzip", gz(t, "token="+haSecret), false, fs); n != "ha-token" || why != "" {
		t.Fatalf("gzip: %q %q", n, why)
	}
	if n, why := encodedLeak("gzip", gz(t, "clean"), false, fs); n != "" || why != "" {
		t.Fatalf("clean gzip: %q %q", n, why)
	}
	if _, why := encodedLeak("br", []byte("x"), false, fs); why == "" {
		t.Fatal("br was not refused")
	}
	if _, why := encodedLeak("gzip", []byte("not gzip"), false, fs); why == "" {
		t.Fatal("invalid gzip was not refused")
	}
	if _, why := encodedLeak("gzip", nil, true, fs); why == "" {
		t.Fatal("a streamed encoded body was not refused")
	}
	if n, why := encodedLeak("identity", []byte(haSecret), false, fs); n != "" || why != "" {
		t.Fatal("identity is the plain check's")
	}
}

func TestRedactResponse(t *testing.T) {
	fs := testForms()
	resp := &http.Response{Status: "200 " + haSecret, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  http.Header{"X-Echo": {"Bearer " + haSecret}, "Content-Encoding": {"gzip"}},
		Trailer: http.Header{"X-T": {haSecret}}, Body: io.NopCloser(bytes.NewReader(gz(t, "you sent "+haSecret))), ContentLength: -1}
	var rec wire.Record
	if why := redactResponse(resp, fs, &rec); why != "" {
		t.Fatal(why)
	}
	var out bytes.Buffer
	if err := resp.Write(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), haSecret) || !strings.Contains(out.String(), "you sent ****") {
		t.Fatalf("response:\n%s", out.String())
	}
	if w := strings.Join(rec.Warnings, "|"); !strings.Contains(w, "from the response") || !strings.Contains(w, "from the response body") {
		t.Fatalf("warnings: %v", rec.Warnings)
	}
	resp = &http.Response{Header: http.Header{"Content-Encoding": {"br"}}, Body: io.NopCloser(strings.NewReader("x"))}
	if why := redactResponse(resp, fs, &rec); why == "" {
		t.Fatal("a br response was not refused")
	}
}
