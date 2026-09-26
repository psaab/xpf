package termsafe

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// hasTerminalControl reports whether s still carries any byte or rune a
// terminal would interpret as a control: a C0 byte (0x00-0x1F), DEL (0x7F), a
// C1 control rune (0x80-0x9F), or an invalid UTF-8 byte. It is the security
// invariant SanitizeForDisplay must guarantee about its output. C0/DEL are
// checked at the byte level (they are never UTF-8 continuation or lead bytes,
// so this cannot false-positive on multibyte runes); C1 is checked at the rune
// level so a legitimate continuation byte in 0x80-0x9F is not mistaken for one.
// SanitizeForDisplay escapes newline/tab too (they must not appear mid-cell in
// a table), so a bare sanitized field legitimately has no control byte at all.
func hasTerminalControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 || b == 0x7f {
			return true
		}
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return true // invalid UTF-8 byte survived
		}
		if unicode.IsControl(r) {
			return true // C1 control rune survived
		}
		i += size
	}
	return false
}

// TestSanitizeForDisplayStripsEscapeSequences is the #6468 fail-on-revert
// guard: a device-supplied DHCP lease hostname carrying terminal escape
// sequences (OSC 52 clipboard write, CSI erase, a lone C1 CSI introducer, an
// invalid UTF-8 byte) must never reach the operator's terminal as raw control
// bytes. Neutralizing SanitizeForDisplay to a pass-through fails this on a
// clean assertion (the raw ESC/BEL bytes reappear in the output).
func TestSanitizeForDisplayStripsEscapeSequences(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"osc52-clipboard-hijack", "laptop\x1b]52;c;YWFhYWFh\x07host"},
		{"csi-erase-and-spoof", "\x1b[2J\x1b[Hcommit complete"},
		{"bare-c1-csi-introducer", "roid\x9b2Kfake"},
		{"nul-and-del", "ab\x00cd\x7fef"},
		{"invalid-utf8-byte", "host\xffname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := SanitizeForDisplay(tc.in)
			if hasTerminalControl(out) {
				t.Fatalf("SanitizeForDisplay(%q) = %q: output still contains raw terminal control bytes",
					tc.in, out)
			}
			// The escaped form must be visible so the operator sees what was
			// sent rather than a silently swallowed byte.
			if strings.ContainsRune(tc.in, 0x1b) && !strings.Contains(out, `\x1b`) {
				t.Fatalf("SanitizeForDisplay(%q) = %q: ESC was not rendered as a visible \\x1b escape",
					tc.in, out)
			}
		})
	}
}

// TestSanitizeForDisplayPreservesLegitimate verifies the sanitizer does not
// corrupt clean, operator-meaningful names: a plain ASCII hostname and a valid
// multibyte UTF-8 hostname both pass through byte-for-byte unchanged (no
// over-sanitization).
func TestSanitizeForDisplayPreservesLegitimate(t *testing.T) {
	clean := []string{
		"laptop-01",
		"host.example.com",
		"aa:bb:cc:dd:ee:ff",
		"café-server",   // U+00E9, printable Latin-1
		"naïve-box",     // U+00EF
		"主机-42",         // CJK, multibyte
		"prn-résumé-01", // mixed accents
		"",              // empty is trivially safe
	}
	for _, in := range clean {
		if got := SanitizeForDisplay(in); got != in {
			t.Errorf("SanitizeForDisplay(%q) = %q, want unchanged", in, got)
		}
	}
	// DisplaySafe must agree with the fast-path decision.
	for _, in := range clean {
		if !DisplaySafe(in) {
			t.Errorf("DisplaySafe(%q) = false, want true", in)
		}
	}
	if DisplaySafe("x\x1by") {
		t.Errorf("DisplaySafe(%q) = true, want false", "x\x1by")
	}
}

func TestQuoteFieldForDisplayBoundsAndKeepsEscapesWhole(t *testing.T) {
	got := QuoteFieldForDisplay("123456789\u2029long", 20)
	want := `"123456789\u2029..."`
	if got != want {
		t.Fatalf("QuoteFieldForDisplay() = %q, want %q", got, want)
	}
	if len(got) > 20 {
		t.Errorf("QuoteFieldForDisplay() produced %d columns for width 20: %q", len(got), got)
	}

	if got := QuoteFieldForDisplay("界", 8); got != `"\u754c"` {
		t.Errorf("QuoteFieldForDisplay() did not bound wide Unicode as ASCII: %q", got)
	}
}
