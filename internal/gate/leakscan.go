package gate

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/DavidGodefroid/lockhttp/internal/policy"
	"github.com/DavidGodefroid/lockhttp/internal/wire"
)

// secretForm is one byte form of a secret the gate matches: as is,
// URL-escaped, hex, or base64 at any alignment.
type secretForm struct {
	name string
	b    []byte
	// fold is b in lower case, for the names (findFold).
	fold []byte
}

// formSet is the forms of a set of secrets, and the length of the
// longest (a streaming scan holds back one byte less).
type formSet struct {
	forms []secretForm
	max   int
}

// formsOf returns the forms of the values, by secret name.
func formsOf(vals map[string][]string) *formSet {
	fs := &formSet{}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, n := range names {
		for _, v := range vals[n] {
			for _, f := range valueForms([]byte(v)) {
				if len(f) == 0 || seen[string(f)] {
					continue
				}
				seen[string(f)] = true
				fs.forms = append(fs.forms, secretForm{name: n, b: f, fold: bytes.ToLower(f)})
				fs.max = max(fs.max, len(f))
			}
		}
	}
	return fs
}

// valueForms are the forms of one value: as is, query- and
// path-escaped, hex (both cases), and base64 in the standard and URL
// alphabets at each of the 3 alignments a value can take inside a longer
// encoded blob (the characters that also depend on the bytes around it
// dropped).
func valueForms(v []byte) [][]byte {
	out := [][]byte{v, []byte(url.QueryEscape(string(v))), []byte(url.PathEscape(string(v))),
		[]byte(hex.EncodeToString(v)), []byte(strings.ToUpper(hex.EncodeToString(v)))}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for k := 0; k < 3; k++ {
			s := enc.EncodeToString(append(make([]byte, k), v...))
			s = s[[3]int{0, 2, 3}[k]:]
			if (k+len(v))%3 != 0 {
				s = s[:len(s)-1]
			}
			out = append(out, []byte(s))
		}
	}
	return out
}

func (fs *formSet) empty() bool { return fs == nil || len(fs.forms) == 0 }

// decodeRounds is how many times every scanner percent-decodes what it
// matches (each round in two ways: '+' kept and '+' as a space), so that
// the held checks, the streamed ones and the names all accept the same
// forms of a value.
const decodeRounds = 2

// expansion is how many bytes of the agent's one byte of a form may take
// after decodeRounds rounds of escaping (%XX: 3 per round): a streaming
// scan holds back that many times the longest form.
const expansion = 9

// hold is how many bytes a streaming scan holds back (or keeps as
// history): one byte less than the longest form fully escaped
// decodeRounds times, so that no form goes out whole before it is
// matched.
func (fs *formSet) hold() int {
	if fs.empty() {
		return 0
	}
	return max(expansion*fs.max-1, 0)
}

// unhex is the value of a hex digit, or -1.
func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// pctDecode decodes every valid %XX escape (either case) of data, and with
// plus a '+' as a space. An invalid escape stays as is: a strict decoder
// would let one stray '%' hide every escape around it. With pos, it also
// returns, for each byte of the output, the offset in data where it
// starts, and len(data) last.
func pctDecode(data []byte, plus, pos bool) ([]byte, []int) {
	out := make([]byte, 0, len(data))
	var at []int
	if pos {
		at = make([]int, 0, len(data)+1)
	}
	for i := 0; i < len(data); {
		c, w := data[i], 1
		if c == '%' && i+2 < len(data) && unhex(data[i+1]) >= 0 && unhex(data[i+2]) >= 0 {
			c, w = byte(unhex(data[i+1])<<4|unhex(data[i+2])), 3
		} else if c == '+' && plus {
			c = ' '
		}
		out = append(out, c)
		if pos {
			at = append(at, i)
		}
		i += w
	}
	if pos {
		at = append(at, len(data))
	}
	return out, at
}

// variant is data or one of its percent-decoded forms, with (when asked)
// the offset in data where each of its bytes starts (nil: data itself).
type variant struct {
	b   []byte
	pos []int
}

// variants returns data and its distinct percent-decoded forms, '+' kept
// and '+' as a space, up to decodeRounds rounds (at most 7: no round
// repeats a form already there). With pos, each carries its offsets in
// data.
func variants(data []byte, pos bool) []variant {
	out := []variant{{b: data}}
	frontier := out
	for r := 0; r < decodeRounds && len(frontier) > 0; r++ {
		var next []variant
		for _, v := range frontier {
			pct, pl := bytes.IndexByte(v.b, '%') >= 0, bytes.IndexByte(v.b, '+') >= 0
			for _, plus := range []bool{false, true} {
				if (!plus && !pct) || (plus && !pl) {
					continue
				}
				d, at := pctDecode(v.b, plus, pos)
				if hasVariant(out, d) {
					continue
				}
				if pos && v.pos != nil {
					for i, o := range at {
						at[i] = v.pos[o]
					}
				}
				nv := variant{b: d, pos: at}
				out = append(out, nv)
				next = append(next, nv)
			}
		}
		frontier = next
	}
	return out
}

func hasVariant(vs []variant, b []byte) bool {
	for _, v := range vs {
		if bytes.Equal(v.b, b) {
			return true
		}
	}
	return false
}

// findRaw reports the name of a secret one of whose forms is in data, as
// is (no decoding).
func (fs *formSet) findRaw(data []byte) (string, bool) {
	if fs.empty() {
		return "", false
	}
	for _, f := range fs.forms {
		if bytes.Contains(data, f.b) {
			return f.name, true
		}
	}
	return "", false
}

// find reports the name of a secret one of whose forms is in data, as is
// or percent-decoded (any case of the escapes, '+' kept or as a space, up
// to decodeRounds rounds). Every scanner of what the agent sends uses it:
// the held parts, the streamed body, the decoded body, a WebSocket's
// frames, a tunnel.
func (fs *formSet) find(data []byte) (string, bool) {
	if fs.empty() {
		return "", false
	}
	for _, v := range variants(data, false) {
		if n, ok := fs.findRaw(v.b); ok {
			return n, ok
		}
	}
	return "", false
}

// findDecoded is find (the name the held checks use).
func (fs *formSet) findDecoded(data []byte) (string, bool) { return fs.find(data) }

// maxFoldName bounds a name findFold matches (a header name; a host is
// bounded lower by the callers, see Secrets.LeakNames).
const maxFoldName = 1024

// findFold is find, ignoring ASCII case, on data and on data without its
// dots, each percent-decoded up to decodeRounds rounds (and folded
// again): for a host name (DNS ignores case, a label boundary may split
// the value) and a header name (canonicalized on the way in). It is
// iterative and deduplicated: at most a few dozen candidates, each as
// long as data at most. A name longer than maxFoldName is not scanned:
// it reports ("", true), refused as unscannable.
func (fs *formSet) findFold(data []byte) (string, bool) {
	if fs.empty() {
		return "", false
	}
	if len(data) > maxFoldName {
		return "", true
	}
	var seen [][]byte
	frontier := [][]byte{data}
	for r := 0; r <= decodeRounds && len(frontier) > 0; r++ {
		var next [][]byte
		for _, f := range frontier {
			low := bytes.ToLower(f)
			for _, c := range [][]byte{low, bytes.ReplaceAll(low, []byte("."), nil)} {
				if containsSlice(seen, c) {
					continue
				}
				seen = append(seen, c)
				for _, form := range fs.forms {
					if bytes.Contains(c, form.fold) {
						return form.name, true
					}
				}
				if r == decodeRounds {
					continue
				}
				for _, plus := range []bool{false, true} {
					if d, _ := pctDecode(c, plus, false); !bytes.Equal(d, c) && !containsSlice(next, d) {
						next = append(next, d)
					}
				}
			}
		}
		frontier = next
	}
	return "", false
}

func containsSlice(s [][]byte, b []byte) bool {
	for _, x := range s {
		if bytes.Equal(x, b) {
			return true
		}
	}
	return false
}

// redact overwrites every form found in data, as is or percent-decoded
// (as find matches it), with '*' over the bytes of data it takes (a
// framing length stays right), and returns the names found. data is
// copied first when it changes.
func (fs *formSet) redact(data []byte) ([]byte, []string) {
	if fs.empty() {
		return data, nil
	}
	var names []string
	var out []byte
	for _, v := range variants(data, true) {
		for _, f := range fs.forms {
			for off := 0; ; {
				i := bytes.Index(v.b[off:], f.b)
				if i < 0 {
					break
				}
				from, to := off+i, off+i+len(f.b)
				if v.pos != nil {
					from, to = v.pos[from], v.pos[to]
				}
				if out == nil {
					out = append([]byte(nil), data...)
				}
				for j := from; j < to; j++ {
					out[j] = '*'
				}
				names = appendOnce(names, f.name)
				off += i + 1
			}
		}
	}
	if out == nil {
		return data, nil
	}
	return out, names
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// errLeak is the error a scanning reader returns when the agent sends an
// injected secret: the transport aborts the request with it.
var errLeak = errors.New("the agent sent an injected secret")

// scanReader passes r through, holding back the last fs.hold() bytes so
// that no form of a secret goes out whole before it is matched. With
// redact, a form is overwritten (same length) and the stream goes on;
// without, the read fails with errLeak and nothing of the form goes out.
type scanReader struct {
	r      io.Reader
	fs     *formSet
	redact bool
	// cap bounds the bytes read (0: none): past it the read fails.
	cap  int64
	read int64

	held  []byte
	out   []byte
	err   error
	found []string
}

func (s *scanReader) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		buf := make([]byte, 32<<10)
		n, err := s.r.Read(buf)
		s.read += int64(n)
		if s.cap > 0 && s.read > s.cap {
			err = errTooLarge
		}
		data := append(s.held, buf[:n]...)
		s.held = nil
		if s.redact {
			var names []string
			data, names = s.fs.redact(data)
			for _, n := range names {
				s.found = appendOnce(s.found, n)
			}
		} else if name, ok := s.fs.find(data); ok {
			s.found = appendOnce(s.found, name)
			s.err = errLeak
			return 0, errLeak
		}
		if err != nil {
			s.out, s.err = data, err
			break
		}
		cut := max(len(data)-s.fs.hold(), 0)
		s.out, s.held = data[:cut], append([]byte(nil), data[cut:]...)
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

var errTooLarge = errors.New("too large to check")

// scanWriter matches what is written, keeping the last fs.hold() bytes as
// history so that a form split across writes is matched too.
type scanWriter struct {
	fs    *formSet
	hist  []byte
	n     int64
	cap   int64
	found string
}

func (s *scanWriter) Write(p []byte) (int, error) {
	s.n += int64(len(p))
	if s.cap > 0 && s.n > s.cap {
		return 0, errTooLarge
	}
	data := append(s.hist, p...)
	if name, ok := s.fs.find(data); ok {
		s.found = name
		return 0, errLeak
	}
	keep := min(len(data), s.fs.hold())
	s.hist = append([]byte(nil), data[len(data)-keep:]...)
	return len(p), nil
}

// copyScanned copies src to dst, matching the stream with fs (history
// across reads); it stops before writing a read that completes a form,
// and returns the secret's name.
func copyScanned(dst io.Writer, src io.Reader, fs *formSet) (int64, string) {
	sw := &scanWriter{fs: fs}
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := src.Read(buf)
		if k > 0 {
			if _, werr := sw.Write(buf[:k]); werr != nil {
				return n, sw.found
			}
			w, werr := dst.Write(buf[:k])
			n += int64(w)
			if werr != nil {
				return n, ""
			}
		}
		if err != nil {
			return n, ""
		}
	}
}

// copyWebSocket copies the client's WebSocket frames to dst, unmasking
// each frame's payload to match it (history across frames) before the
// frame goes out. A frame larger than limit, or one that completes a
// form, is not sent: the copy stops and returns the secret's name ("" for
// an oversized frame or the stream's end).
func copyWebSocket(dst io.Writer, src io.Reader, fs *formSet, limit int64) (n int64, leak string, oversized bool) {
	sw := &scanWriter{fs: fs}
	for {
		hdr := make([]byte, 2, 14)
		if _, err := io.ReadFull(src, hdr); err != nil {
			return n, "", false
		}
		masked := hdr[1]&0x80 != 0
		plen := int64(hdr[1] & 0x7f)
		switch plen {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(src, ext); err != nil {
				return n, "", false
			}
			hdr = append(hdr, ext...)
			plen = int64(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(src, ext); err != nil {
				return n, "", false
			}
			hdr = append(hdr, ext...)
			u := binary.BigEndian.Uint64(ext)
			if u > uint64(limit) {
				return n, "", true
			}
			plen = int64(u)
		}
		if plen > limit {
			return n, "", true
		}
		var key []byte
		if masked {
			key = make([]byte, 4)
			if _, err := io.ReadFull(src, key); err != nil {
				return n, "", false
			}
			hdr = append(hdr, key...)
		}
		payload := make([]byte, plen)
		if _, err := io.ReadFull(src, payload); err != nil {
			return n, "", false
		}
		plain := payload
		if masked {
			plain = make([]byte, plen)
			for i := range payload {
				plain[i] = payload[i] ^ key[i%4]
			}
		}
		if _, err := sw.Write(plain); err != nil {
			return n, sw.found, false
		}
		w, err := dst.Write(append(hdr, payload...))
		n += int64(w)
		if err != nil {
			return n, "", false
		}
	}
}

// maxDecoded bounds what the gate decodes of a compressed body to scan
// it (a small body may expand a lot).
const maxDecoded = 256 << 20

// decodeChain wraps r to undo ce (a Content-Encoding list, applied in
// order), or says why it cannot: gzip and deflate only.
func decodeChain(ce string, r io.Reader) (io.Reader, string) {
	encs := strings.Split(ce, ",")
	for i := len(encs) - 1; i >= 0; i-- {
		switch e := strings.ToLower(strings.TrimSpace(encs[i])); e {
		case "", "identity":
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(r)
			if err != nil {
				return nil, "the body is not valid gzip"
			}
			r = zr
		case "deflate":
			zr, err := zlib.NewReader(r)
			if err != nil {
				return nil, "the body is not valid deflate"
			}
			r = zr
		default:
			return nil, "the body is encoded with " + e
		}
	}
	return r, ""
}

func identityEncoding(ce string) bool {
	for _, e := range strings.Split(ce, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" && e != "identity" {
			return false
		}
	}
	return true
}

// encodedLeak decodes a held body with a Content-Encoding and matches it:
// the name of the secret found, or why it cannot be checked (a streamed
// encoded body, an encoding other than gzip and deflate, one that does
// not decode or expands too much).
func encodedLeak(ce string, body []byte, streamed bool, fs *formSet) (name, why string) {
	if identityEncoding(ce) {
		return "", ""
	}
	if streamed {
		return "", "the body is encoded (" + ce + ") and over the buffer limit"
	}
	r, why := decodeChain(ce, bytes.NewReader(body))
	if why != "" {
		return "", why
	}
	sw := &scanWriter{fs: fs, cap: maxDecoded}
	if _, err := io.Copy(sw, r); err != nil {
		switch {
		case errors.Is(err, errLeak):
			return sw.found, ""
		case errors.Is(err, errTooLarge):
			return "", "the decoded body exceeds " + policy.FormatSize(maxDecoded)
		default:
			return "", "the encoded body does not decode"
		}
	}
	return "", ""
}

// redactResponse overwrites the injected values in the response to an
// injected request (status, header names and values, body) and drops its
// trailers, recording what it redacted in rec. A gzip or deflate body is
// decoded first (sent to the agent decoded); any other encoding is why it
// cannot be checked.
func redactResponse(resp *http.Response, fs *formSet, rec *wire.Record) string {
	var names []string
	add := func(ns []string) {
		for _, n := range ns {
			names = appendOnce(names, n)
		}
	}
	st, ns := fs.redact([]byte(resp.Status))
	resp.Status = string(st)
	add(ns)
	h := http.Header{}
	for k, vs := range resp.Header {
		kb, ns := fs.redact([]byte(k))
		add(ns)
		for _, v := range vs {
			vb, ns := fs.redact([]byte(v))
			add(ns)
			h[string(kb)] = append(h[string(kb)], string(vb))
		}
	}
	resp.Header = h
	resp.Trailer = nil
	if ce := resp.Header.Get("Content-Encoding"); !identityEncoding(ce) {
		r, why := decodeChain(ce, resp.Body)
		if why != "" {
			return strings.Replace(why, "the body", "the response", 1)
		}
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Body = io.NopCloser(r)
	}
	sr := &scanReader{r: resp.Body, fs: fs, redact: true}
	resp.Body = &redactBody{scanReader: sr, rec: rec}
	if len(names) > 0 {
		rec.Warnings = append(rec.Warnings, "redacted the injected secret "+strings.Join(names, ", ")+" from the response")
	}
	return ""
}

// redactBody records, once read, the secrets redacted from the body.
type redactBody struct {
	*scanReader
	rec  *wire.Record
	done bool
}

func (b *redactBody) Read(p []byte) (int, error) {
	n, err := b.scanReader.Read(p)
	if err != nil && !b.done {
		b.done = true
		if found := b.scanReader.found; len(found) > 0 {
			b.rec.Warnings = append(b.rec.Warnings, "redacted the injected secret "+strings.Join(found, ", ")+" from the response body")
		}
	}
	return n, err
}

func (b *redactBody) Close() error { return nil }
