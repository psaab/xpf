package termsafe

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

// #10009: the #7389 bound emission can fall mid-rune. Holding a partial line
// until its newline (or the bound) keeps runes intact across read boundaries --
// but the bound path emitted the whole buffer including a trailing partial
// rune, which the sanitizer then escaped bytewise. Byte-identical valid
// streams rendered differently depending on write boundaries. The bound path
// must retain a bounded incomplete UTF-8 suffix for the next write, while a
// genuinely invalid tail still escapes immediately and Flush still emits the
// residual (end-of-stream truncation is invalid, not incomplete).

// A rune straddling the bound must survive: the bound fires with 1-3 partial
// bytes trailing, those bytes are held, and the completed rune renders intact.
// Every split point of a 2-, 3-, and 4-byte rune is exercised.
func TestBoundEmissionRetainsPartialRune_10009(t *testing.T) {
	for _, r := range []string{"é", "€", "𝄞"} {
		rb := []byte(r)
		for split := 1; split < len(rb); split++ {
			prefix := bytes.Repeat([]byte("a"), maxBufferedLine-1)
			var out bytes.Buffer
			w := NewSanitizingWriter(&out)
			if _, err := w.Write(prefix); err != nil {
				t.Fatalf("rune %q split %d: Write(prefix): %v", r, split, err)
			}
			if _, err := w.Write(rb[:split]); err != nil {
				t.Fatalf("rune %q split %d: Write(partial): %v", r, split, err)
			}
			// The bound fired; every complete byte is emitted and only the
			// partial rune is held. Emitting the partial bytes here would
			// escape them as invalid UTF-8, corrupting valid text.
			if out.Len() != len(prefix) {
				t.Errorf("rune %q split %d/%d: emitted %d bytes after bound write, want %d (complete prefix only)",
					r, split, len(rb), out.Len(), len(prefix))
			}
			rest := append(append([]byte{}, rb[split:]...), "tail\n"...)
			if _, err := w.Write(rest); err != nil {
				t.Fatalf("rune %q split %d: Write(rest): %v", r, split, err)
			}
			if err := w.Flush(); err != nil {
				t.Fatalf("rune %q split %d: Flush: %v", r, split, err)
			}
			want := append(append(append([]byte{}, prefix...), rb...), "tail\n"...)
			if !bytes.Equal(out.Bytes(), want) {
				gs, ws := out.String(), string(want)
				if len(gs) > 32 {
					gs = gs[len(gs)-32:]
				}
				if len(ws) > 32 {
					ws = ws[len(ws)-32:]
				}
				t.Errorf("rune %q split %d/%d: got tail %q want tail %q (len %d vs %d)",
					r, split, len(rb), gs, ws, out.Len(), len(want))
			}
		}
	}
}

// The streaming shape: the straddling rune arrives one byte per Write after
// the bound fires. The final render must equal the unfragmented stream.
func TestBoundEmissionRuneDeliveredByteAtATime_10009(t *testing.T) {
	for _, r := range []string{"é", "€", "𝄞"} {
		rb := []byte(r)
		prefix := bytes.Repeat([]byte("a"), maxBufferedLine-1)
		var out bytes.Buffer
		w := NewSanitizingWriter(&out)
		if _, err := w.Write(prefix); err != nil {
			t.Fatalf("rune %q: Write(prefix): %v", r, err)
		}
		for _, b := range rb {
			if _, err := w.Write([]byte{b}); err != nil {
				t.Fatalf("rune %q: Write(byte): %v", r, err)
			}
		}
		if _, err := w.Write([]byte("tail\n")); err != nil {
			t.Fatalf("rune %q: Write(tail): %v", r, err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("rune %q: Flush: %v", r, err)
		}
		want := append(append(append([]byte{}, prefix...), rb...), "tail\n"...)
		if !bytes.Equal(out.Bytes(), want) {
			gs, ws := out.String(), string(want)
			if len(gs) > 32 {
				gs = gs[len(gs)-32:]
			}
			if len(ws) > 32 {
				ws = ws[len(ws)-32:]
			}
			t.Errorf("rune %q byte-at-a-time: got tail %q want tail %q (len %d vs %d)",
				r, gs, ws, out.Len(), len(want))
		}
	}
}

// Invalid bytes can never complete into a rune, so the bound must emit (and
// escape) them immediately rather than hold them. Pins the safety invariant
// through the writer path: no raw invalid UTF-8 reaches the terminal.
func TestBoundEmissionEscapesInvalidTailImmediately_10009(t *testing.T) {
	cases := []struct {
		name string
		tail []byte
		want string // escaped form the sanitizer emits for the tail
	}{
		{"invalid leader", []byte{0xff}, `\xff`},
		{"lone continuation", []byte{0x80}, `\x80`},
		{"bad continuation", []byte{0xe2, 0x28}, `\xe2(`},
		{"overlong", []byte{0xc0, 0xaf}, `\xc0\xaf`},
		{"surrogate", []byte{0xed, 0xa0, 0x80}, `\xed\xa0\x80`},
	}
	for _, tc := range cases {
		prefix := bytes.Repeat([]byte("a"), maxBufferedLine-1)
		var out bytes.Buffer
		w := NewSanitizingWriter(&out)
		if _, err := w.Write(prefix); err != nil {
			t.Fatalf("%s: Write(prefix): %v", tc.name, err)
		}
		if _, err := w.Write(tc.tail); err != nil {
			t.Fatalf("%s: Write(tail): %v", tc.name, err)
		}
		if wantLen := len(prefix) + len(tc.want); out.Len() != wantLen {
			t.Errorf("%s: emitted %d bytes after bound write, want %d (nothing held)",
				tc.name, out.Len(), wantLen)
		}
		if _, err := w.Write([]byte("ok\n")); err != nil {
			t.Fatalf("%s: Write(ok): %v", tc.name, err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("%s: Flush: %v", tc.name, err)
		}
		want := string(prefix) + tc.want + "ok\n"
		if out.String() != want {
			gs, ws := out.String(), want
			if len(gs) > 32 {
				gs = gs[len(gs)-32:]
			}
			if len(ws) > 32 {
				ws = ws[len(ws)-32:]
			}
			t.Errorf("%s: got tail %q want tail %q (len %d vs %d)",
				tc.name, gs, ws, out.Len(), len(want))
		}
		if !utf8.ValidString(out.String()) {
			t.Errorf("%s: output is not valid UTF-8", tc.name)
		}
	}
}

// Flush ends the stream: a trailing partial rune there is truncation, not a
// fragment awaiting completion, so it escapes (never raw, never dropped).
func TestFlushEscapesTruncatedTail_10009(t *testing.T) {
	cases := []struct {
		name string
		tail []byte
		want string
	}{
		{"two-byte lead", []byte{0xc3}, `\xc3`},
		{"three-byte partial", []byte{0xe2, 0x82}, `\xe2\x82`},
		{"four-byte partial", []byte{0xf0, 0x9f, 0x98}, `\xf0\x9f\x98`},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		w := NewSanitizingWriter(&out)
		in := append([]byte("ab"), tc.tail...)
		if _, err := w.Write(in); err != nil {
			t.Fatalf("%s: Write: %v", tc.name, err)
		}
		if out.Len() != 0 {
			t.Fatalf("%s: emitted a partial line before Flush: %q", tc.name, out.String())
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("%s: Flush: %v", tc.name, err)
		}
		if want := "ab" + tc.want; out.String() != want {
			t.Errorf("%s: got %q want %q", tc.name, out.String(), want)
		}
		if !utf8.ValidString(out.String()) {
			t.Errorf("%s: Flush emitted raw invalid UTF-8: %q", tc.name, out.String())
		}
	}
}

// Held bytes that never complete into a rune must converge to the same output
// as if they had never been held: escaped, with valid UTF-8 overall.
func TestBoundHeldSuffixCompletedByInvalidByteStaysSafe_10009(t *testing.T) {
	prefix := bytes.Repeat([]byte("a"), maxBufferedLine-1)
	var out bytes.Buffer
	w := NewSanitizingWriter(&out)
	if _, err := w.Write(prefix); err != nil {
		t.Fatalf("Write(prefix): %v", err)
	}
	if _, err := w.Write([]byte{0xe2, 0x82}); err != nil {
		t.Fatalf("Write(partial): %v", err)
	}
	// 0x28 is not a valid continuation of E2 82: the held bytes can never
	// complete and must escape, exactly as if they had never been held.
	if _, err := w.Write([]byte("(\n")); err != nil {
		t.Fatalf("Write(rest): %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	want := string(prefix) + `\xe2\x82(` + "\n"
	if out.String() != want {
		gs, ws := out.String(), want
		if len(gs) > 32 {
			gs = gs[len(gs)-32:]
		}
		if len(ws) > 32 {
			ws = ws[len(ws)-32:]
		}
		t.Errorf("got tail %q want tail %q (len %d vs %d)", gs, ws, out.Len(), len(want))
	}
	if !utf8.ValidString(out.String()) {
		t.Errorf("output is not valid UTF-8")
	}
}
