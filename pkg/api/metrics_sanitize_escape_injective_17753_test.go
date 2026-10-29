// #17753: #16707's \xNN escaping is not injective against valid values
// that literally spell an escape. sanitizeMetricLabelValue returned every
// valid UTF-8 string unchanged, so the raw byte string "web\xffallow"
// (byte 0xff) and the valid literal `web\xffallow` (backslash, x, f, f)
// both sanitized to `web\xffallow` and emitted duplicate
// xpf_policy_hits_total series; ContinueOnError salvaged the scrape but
// silently dropped one policy's counters.
//
// Fix: escape the escape introducer itself. A backslash in the raw value
// is escaped as \x5c before/with any \xNN invalid-byte escapes, so the
// sanitized spelling is unambiguous and decodable byte-for-byte. Only
// clean valid values (no backslash, valid UTF-8) keep the byte-identical
// allocation-free fast path.
//
// FAIL-ON-REVERT: removing the backslash escape (or restoring the
// valid-passthrough for backslash-bearing values) makes the literal and
// the invalid-byte spellings collide again — the unit uniqueness check
// fails and the scrape below drops to two policy series with a gather
// error.
package api

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// unescapeSanitizedLabel17753 is the test-local inverse of the sanitized
// spelling: \xNN sequences decode to the single byte NN, every other
// byte copies verbatim. A correct sanitizer round-trips every raw byte
// string through this decoder.
func unescapeSanitizedLabel17753(t *testing.T, s string) string {
	t.Helper()
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+3 >= len(s) || s[i+1] != 'x' {
			t.Fatalf("sanitized %q: backslash at %d is not a \\xNN escape", s, i)
		}
		hi, okHi := hexNibble17753(s[i+2])
		lo, okLo := hexNibble17753(s[i+3])
		if !okHi || !okLo {
			t.Fatalf("sanitized %q: malformed \\xNN escape at %d", s, i)
		}
		b.WriteByte(hi<<4 | lo)
		i += 4
	}
	return b.String()
}

func hexNibble17753(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

// TestSanitizeMetricLabelValueInjective17753 pins the injective,
// round-trippable contract over invalid bytes AND valid lookalikes in
// one uniqueness set (the #16707 test kept them in separate sets, which
// is exactly how this collision shipped).
func TestSanitizeMetricLabelValueInjective17753(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		// Invalid bytes: escaped as \xNN, as in #16707.
		{"web\xffallow", `web\xffallow`, false},
		{"web\xfeallow", `web\xfeallow`, false},
		{"\xff", `\xff`, false},
		{"x\xc3y", `x\xc3y`, false},
		{"ok\xc3\xa9\xffend", "oké\\xffend", false},
		// Valid literals that spell an escape: the backslash itself is
		// escaped as \x5c, so they cannot collide with the rows above.
		{`web\xffallow`, `web\x5cxffallow`, true},
		{`web\xfeallow`, `web\x5cxfeallow`, true},
		{`\xff`, `\x5cxff`, true},
		// Lone, trailing, and non-escape backslashes are escaped too.
		{`\`, `\x5c`, true},
		{`a\`, `a\x5c`, true},
		{`a\b`, `a\x5cb`, true},
		{`a\q`, `a\x5cq`, true},
		{`A\XFF`, `A\x5cXFF`, true},
		{`\\`, `\x5c\x5c`, true},
		// Backslash adjacent to an invalid byte: both are escaped.
		{"a\\\xff", `a\x5c\xff`, false},
		{"\xff\\", `\xff\x5c`, false},
		// Clean valid values: byte-identical fast path, ok=true.
		{"web-allow", "web-allow", true},
		{"ok\xc3\xa9end", "okéend", true},
		{"", "", true},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		got, ok := sanitizeMetricLabelValue(tc.in)
		if ok != tc.ok {
			t.Errorf("sanitize(%q): ok=%v, want %v", tc.in, ok, tc.ok)
		}
		if got != tc.want {
			t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if prev, dup := seen[got]; dup && prev != tc.in {
			t.Errorf("sanitize collision: %q and %q both -> %q", prev, tc.in, got)
		}
		seen[got] = tc.in
		if rt := unescapeSanitizedLabel17753(t, got); rt != tc.in {
			t.Errorf("round-trip: decode(sanitize(%q)) = %q, want original", tc.in, rt)
		}
	}

	// Exhaustive-ish corpus: every invalid byte, every literal \xNN
	// spelling of it, and backslash forms must all stay distinct and
	// round-trip. This is the collision class in bulk, not just \xff.
	corpus := []string{"", "plain", "é", `\`, `\\`, "a\\b"}
	for b := range 256 {
		corpus = append(corpus, "v"+string([]byte{byte(b)})+"w")
		corpus = append(corpus, `v\x`+hex2ForTest17753(byte(b))+`w`)
	}
	corpusSeen := map[string]string{}
	for _, in := range corpus {
		got, _ := sanitizeMetricLabelValue(in)
		if prev, dup := corpusSeen[got]; dup && prev != in {
			t.Errorf("corpus collision: %q and %q both -> %q", prev, in, got)
		}
		corpusSeen[got] = in
		if rt := unescapeSanitizedLabel17753(t, got); rt != in {
			t.Errorf("corpus round-trip: decode(sanitize(%q)) = %q", in, rt)
		}
	}
}

func hex2ForTest17753(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}

// TestMetricsScrapeSanitizeLiteralEscapeCollision17753 is the real-
// collector reproduction: a policy named with raw byte 0xff and a policy
// literally named `web\xffallow` in the same trust->untrust scope must
// publish TWO distinct xpf_policy_hits_total series with no gather drop.
func TestMetricsScrapeSanitizeLiteralEscapeCollision17753(t *testing.T) {
	collector, _ := collidingStore16707(t, []string{"web\xffallow", `web\xffallow`})
	ts := httptest.NewServer(newMetricsHandler(collector, 5*time.Second))
	defer ts.Close()

	status, body := scrape16707(t, ts)
	if status != http.StatusOK {
		t.Fatalf("literal-escape collision scrape status = %d, want 200; body:\n%s", status, body)
	}
	if n := countSeries16707(body, "xpf_policy_hits_total{"); n != 3 {
		t.Errorf("xpf_policy_hits_total series = %d, want 3 (2 rules + default); a dropped series means the sanitizer still collides; body:\n%s", n, body)
	}
	// Wire form doubles each sanitized backslash (Prometheus text
	// escaping): raw-0xff rule -> web\xffallow, literal rule ->
	// web\x5cxffallow.
	if !strings.Contains(body, `rule="web\\xffallow"`) {
		t.Errorf("escaped raw-0xff series missing; body:\n%s", body)
	}
	if !strings.Contains(body, `rule="web\\x5cxffallow"`) {
		t.Errorf("escaped literal-backslash series missing; body:\n%s", body)
	}
	if n := collector.invalidLabelValues.Load(); n != 1 {
		t.Errorf("invalidLabelValues = %d, want 1 (one value carried invalid UTF-8)", n)
	}
	if n := collector.gatherErrors.Load(); n != 0 {
		t.Errorf("gatherErrors = %d, want 0: injective sanitization must not drop any series", n)
	}
}

// TestSanitizeLabelValuesRepeatedEmit17753 pins the copy-on-write
// contract: production collectors build a label slice once and spread it
// into many emits. Sanitizing must never mutate that caller slice —
// otherwise its own escaped backslash is re-escaped on later emits, so
// the same entity appears under a different label value in each family.
func TestSanitizeLabelValuesRepeatedEmit17753(t *testing.T) {
	desc := prometheus.NewDesc("xpf_sanitize_repeat_17753", "repeat-emit regression", []string{"from", "to", "rule"}, nil)
	extractRule := func(t *testing.T, m prometheus.Metric) string {
		t.Helper()
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		for _, l := range pb.GetLabel() {
			if l.GetName() == "rule" {
				return l.GetValue()
			}
		}
		t.Fatal("emitted metric has no rule label")
		return ""
	}
	cases := []struct {
		raw  string
		want string
	}{
		{"run\xff", `run\xff`},
		{"run\\xff\xff", `run\x5cxff\xff`},
		{`run\xff`, `run\x5cxff`},
		{"clean", "clean"},
	}
	for _, tc := range cases {
		labels := []string{"trust", "untrust", tc.raw}
		original := slices.Clone(labels)
		collector := &xpfCollector{}
		var spellings []string
		for range 3 {
			for _, c := range []*xpfCollector{collector, nil} {
				m, err := newConstMetric(c, desc, prometheus.GaugeValue, 1, labels...)
				if err != nil {
					t.Fatalf("newConstMetric: %v", err)
				}
				spellings = append(spellings, extractRule(t, m))
			}
		}
		for i, got := range spellings {
			if got != tc.want {
				t.Errorf("raw %q emit %d: spelling %q, want %q (re-escaped or under-escaped)", tc.raw, i, got, tc.want)
			}
		}
		if !slices.Equal(labels, original) {
			t.Errorf("caller slice mutated for raw %q: got %#q, want unchanged %#q", tc.raw, labels, original)
		}
	}
}
