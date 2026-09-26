// Package termsafe escapes device-originated strings before they are printed
// to an operator's terminal. Several fields the CLI displays are
// attacker-controlled — a DHCP lease hostname (DHCP option 12) and client
// hardware address are supplied by a device on a served segment and stored
// opaque by Kea, and the DHCP dynamic-DNS forward record name is built from
// that same client hostname. Printed verbatim, such a value can carry terminal
// escape sequences (an OSC 52 clipboard write, an OSC 8 hyperlink, CSI
// cursor/erase controls) that the operator's terminal would ACT on when the
// table is displayed — clipboard hijack and output spoofing (a forged "commit
// complete" line, or a rogue lease row erased from view).
//
// The same class covers more than lease data. A DDNS provider's response body
// reaches the operator through the `show services dynamic-dns` LastError column
// (Cloudflare and Route 53 embed the provider message with %s), and captured
// `vtysh` stdout carries text a BGP or IS-IS peer advertised — the BGP hostname
// capability, IS-IS dynamic hostname TLVs. Anything a remote party can put
// bytes into and an operator then reads on a terminal belongs here.
//
// Two entry points, chosen by the SHAPE of the value, not by its source:
//
//   - SanitizeForDisplay for a single-line FIELD rendered into a row the caller
//     formats. LF and TAB are escaped along with everything else, because an
//     embedded newline in a field is itself a forgery vector — it fakes a row.
//   - SanitizeBlockForDisplay for a MULTI-LINE blob whose own line structure is
//     the output (vtysh stdout). LF and TAB are preserved so the table survives;
//     CR and the Unicode line/paragraph separators are not, because they forge
//     or overwrite rows.
//
// Both escape U+2028/U+2029. Neither is Unicode category Cc, so unicode.IsControl
// does not reach them, but a terminal or pager that honors either as a break can
// forge a row with it — the same argument that escapes CR in the block variant
// and LF in the field variant.
//
// What this package does NOT do: it makes device text safe to PRINT, not
// trustworthy to READ. It neutralizes terminal-protocol control bytes; it leaves
// every printable rune alone, so it cannot tell a genuine field value from a
// plausible-looking one a peer supplied. A row whose columns were derived by
// splitting peer-controlled text on whitespace stays terminal-safe and can still
// display materially false values — see #6590 and SanitizeRowForDisplay.
//
// This is a leaf package (it imports only the standard library) so BOTH the
// in-process CLI renderer (pkg/cli) and the gRPC text renderer that feeds the
// remote `cli`'s verbatim terminal print (pkg/grpcapi) can guard the same
// device-originated values with one implementation. Every guarded surface must
// be applied on BOTH renderers — the remote `cli` is the more common operator
// posture, and a fix on one alone leaves the other at pre-fix behavior.
// Sanitizing happens at the display boundary only: stored lease data, the
// DDNS status views, and the gRPC/JSON structs are unchanged, so machine
// consumers still receive the raw value. See #6468.
package termsafe

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// QuoteFieldForDisplay returns an ASCII-quoted representation of an untrusted
// single-line table cell, bounded to maxWidth terminal columns. Non-ASCII text,
// terminal controls, invalid UTF-8, Unicode line separators, and non-printing
// format characters such as bidi overrides are escaped, so the quoted byte
// length also matches its terminal width.
//
// Long values are shortened only between complete Go escape sequences and end
// with an ellipsis inside the quotes, so a peer-controlled value cannot move
// later columns or leave a partial escape that looks like data.
func QuoteFieldForDisplay(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	quoted := strconv.QuoteToASCII(s)
	if len(quoted) <= maxWidth {
		return quoted
	}
	if maxWidth < 5 {
		return strings.Repeat(".", maxWidth)
	}

	content := quoted[1 : len(quoted)-1]
	budget := maxWidth - 5 // opening/closing quote plus the three dots
	end := 0
	for end < len(content) {
		size := 1
		if content[end] == '\\' {
			switch content[end+1] {
			case 'x':
				size = 4
			case 'u':
				size = 6
			case 'U':
				size = 10
			default:
				if content[end+1] >= '0' && content[end+1] <= '7' {
					size = 4
				} else {
					size = 2
				}
			}
		} else {
			_, size = utf8.DecodeRuneInString(content[end:])
		}
		if end+size > budget {
			break
		}
		end += size
	}
	return `"` + content[:end] + "..." + `"`
}

// SanitizeForDisplay escapes the terminal-protocol control bytes in a
// device-originated string so the terminal does not ACT on embedded escape
// sequences when the value is printed. Every C0 control byte (0x00-0x1F,
// including ESC), DEL (0x7F), C1 control byte (0x80-0x9F), and invalid UTF-8
// byte is replaced with a visible backslash-hex escape (e.g. an ESC becomes the
// four printable characters \x1b) so the operator sees exactly what the device
// sent instead of the terminal interpreting it. Every printable rune —
// including legitimate multibyte UTF-8, so an international hostname is not
// corrupted — passes through unchanged.
//
// U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are escaped too, as
// \u2028 / \u2029 (a \xHH byte escape cannot represent a rune above U+00FF).
// Neither is Unicode category Cc, so unicode.IsControl does not reach them; they
// are escaped because this variant's whole premise is that the value occupies ONE
// line of a row the caller formats, and a rune a terminal or pager may honor as a
// line break forges a row exactly as an embedded LF does. Escaping LF but passing
// U+2028 would be incoherent: this variant is the STRICTER of the two about line
// breaks, and SanitizeBlockForDisplay — which preserves LF — already escapes them.
//
// Scope is otherwise deliberately narrow. This neutralizes the terminal-protocol
// control bytes and invalid UTF-8 that drive escape-sequence injection (OSC
// clipboard writes, CSI cursor/erase), plus the two line separators. It does NOT
// address Unicode display-order spoofing: bidirectional overrides (U+200E,
// U+202A-U+202E) and zero-width format (Cf) characters are printable runes and
// pass through unchanged. They can reorder characters WITHIN a line but cannot
// forge or erase a row, so Trojan-Source-style bidi reordering is a separate,
// lower-severity concern and out of scope here.
func SanitizeForDisplay(s string) string {
	// Fast path: the overwhelming majority of names are already clean, so
	// return the input without allocating a builder.
	if DisplaySafe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte — escape the raw byte value so a crafted
			// non-UTF-8 sequence cannot smuggle bytes past the rune checks.
			writeHexEscape(&b, s[i])
			i++
			continue
		}
		if unicode.IsControl(r) {
			// Control runes (Unicode category Cc) are all <= U+009F, so a
			// single \xHH byte escape represents each one exactly.
			writeHexEscape(&b, byte(r))
			i += size
			continue
		}
		if isLineSeparator(r) {
			writeUnicodeEscape(&b, r)
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// SanitizeBlockForDisplay is SanitizeForDisplay for a MULTI-LINE device- or
// remote-supplied blob — captured `vtysh` stdout, a provider response body, any
// text whose own line structure is part of the output.
//
// It neutralizes the same terminal-protocol control bytes but PRESERVES the two
// layout controls that carry the block's shape: LF (0x0A) and TAB (0x09).
// SanitizeForDisplay escapes those too — correctly, for a single-field value
// where an embedded newline is itself a forgery vector (it can fake a new table
// row) — but applying it to a table would collapse the whole thing into one
// `\x0a`-laden line, which is a display regression rather than a fix.
//
// CR (0x0D) is deliberately NOT preserved. A bare carriage return re-homes the
// cursor and lets later text overwrite a line the operator has already read —
// the same class of display forgery the ESC escaping defends against, and not
// something a legitimate line-oriented blob needs.
//
// U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are escaped. Neither is
// Unicode category Cc, so unicode.IsControl does not reach them; they are
// escaped because the whole premise of this variant is that the blob's LINE
// STRUCTURE is meaningful output, and a terminal or pager that honors U+2028 as
// a break lets a peer-advertised hostname forge a row in the same table this
// function is keeping printable. Escaping them is the same argument that
// escapes CR. SanitizeForDisplay escapes them too, for the mirror-image reason:
// a line break of any kind inside a single-line FIELD forges a row. They render
// as the visible escapes
// \u2028 / \u2029 (a \xHH byte escape cannot represent a rune above U+00FF).
//
// Bidi overrides and other Cf runes remain out of scope here, as in
// SanitizeForDisplay: they can reorder characters WITHIN a line but cannot
// forge or erase a row, so they are a different, lower-severity class.
//
// This makes the blob safe to PRINT; it does not make its contents true. The
// text is rendered faithfully, so whatever a remote party put in it is still
// what the operator reads.
func SanitizeBlockForDisplay(s string) string {
	if blockDisplaySafe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			writeHexEscape(&b, s[i])
			i++
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			i += size
			continue
		}
		if unicode.IsControl(r) {
			writeHexEscape(&b, byte(r))
			i += size
			continue
		}
		if isLineSeparator(r) {
			writeUnicodeEscape(&b, r)
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// SanitizeRowForDisplay sanitizes every cell of ONE table row and returns them
// ready to spread into a fmt.Printf / fmt.Fprintf argument list:
//
//	fmt.Printf("  %-20s %-14s %-10s %-10s %s\n",
//		termsafe.SanitizeRowForDisplay(a.SystemID, a.Interface, a.Level, a.State, a.HoldTime)...)
//
// It exists to make the WHOLE-ROW rule unskippable. The tempting alternative is
// to guard only the one column believed to carry device text — and that is
// wrong twice over for a table scraped out of a command's stdout:
//
//   - Column identity is not stable. A value carrying whitespace in an EARLY
//     column shifts every later column, so peer bytes land in cells the
//     per-column analysis marked safe. `strings.Fields` splits on whitespace
//     only, so an ESC, DEL, C1 or BEL rides INSIDE a token untouched while a
//     space in the same value splits it — the attacker picks which.
//   - "This column is numeric" is a property of the current upstream, not of
//     the protocol. FRR already substitutes a peer-advertised IS-IS dynamic
//     hostname for the numeric system ID, and `bgp default show-hostname` does
//     the same for BGP; a column that is an address today can be free text
//     after an upstream bump.
//
// # What this does NOT fix
//
// The column shift above is the REASON to guard every cell; it is not something
// guarding every cell REPAIRS. This makes the row safe to print. It does not
// make the row correct. A peer hostname containing a space still shifts the
// split, so `State` can end up holding a token the peer chose, and every value
// here stays plausible printable text that no sanitizer can tell apart from a
// genuine one. A displayed row can be terminal-safe and materially false.
// Fixing THAT needs the parse to change — structured JSON, or right-anchored
// columns with malformed rows reported rather than rendered — which is #6590,
// deliberately not this helper's job. Do not cite a call to this function as
// evidence that a rendered row is trustworthy.
//
// Cells are single-line FIELDS of a caller-formatted row, so this uses
// SanitizeForDisplay, not the block variant: an embedded newline here forges a
// table row rather than carrying structure. (For a cell produced by
// `strings.Fields` the two variants happen to agree, because every whitespace
// rune was already consumed by the split; for a cell decoded out of JSON a
// newline can survive, and there the distinction is load-bearing.)
//
// Call this on the CELLS, before the caller's width format — not on the
// finished row. `%-20s` pads whatever it is handed, so sanitizing afterwards
// pads the RAW cell and then expands each escape, pushing every later column
// right by the expansion. Guarding per cell is what keeps the widths honest.
//
// # Cost
//
// Sanitizing a clean cell is genuinely free: SanitizeForDisplay returns the
// input string on an allocation-free fast path. The HELPER is not free — it
// allocates the returned []any. Measured over a 10k-row 3-cell render (values
// from struct fields, as production has them, not the string constants a naive
// microbenchmark constant-folds):
//
//	no sanitizer at all                    30,034 allocs   3.73 MB
//	per-cell SanitizeForDisplay, no helper 30,035 allocs   3.73 MB
//	SanitizeRowForDisplay(...)...          40,037 allocs   4.21 MB
//
// So the cost is ONE extra allocation and 48 bytes per row — the []any itself.
// The 3-per-row boxing is inherent to fmt's variadic any and is paid by the
// unguarded path too; it is not attributable to this helper. That is accepted
// here: these are `show`-command render loops already gated by a vtysh
// fork/exec and a whole-table string materialization, not a packet path. If a
// future renderer ever needs it back, the fix is for the caller to hoist a
// scratch []any out of the loop and refill it per row — not to revert to
// guarding a hand-picked subset of columns. BenchmarkSanitizedRow* in
// row_6468_test.go keeps these numbers checkable.
func SanitizeRowForDisplay(cells ...string) []any {
	out := make([]any, len(cells))
	for i, c := range cells {
		out[i] = SanitizeForDisplay(c)
	}
	return out
}

// blockDisplaySafe is DisplaySafe with LF and TAB treated as printable and the
// Unicode line/paragraph separators treated as unsafe, so a clean multi-line
// blob keeps the allocation-free fast path while a row-forging separator does
// not slip past it.
func blockDisplaySafe(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return false
		}
		if isLineSeparator(r) {
			return false
		}
		i += size
	}
	return true
}

// isLineSeparator reports whether r is a Unicode line/paragraph separator —
// category Zl/Zp, which unicode.IsControl does not cover. BOTH sanitizers treat
// these as unsafe: they forge a row in a block whose line structure is the
// output, and equally in a single-line field the caller formats into a row.
func isLineSeparator(r rune) bool {
	return r == '\u2028' || r == '\u2029'
}

// DisplaySafe reports whether s can be printed to a terminal verbatim: it holds
// no control rune, no Unicode line/paragraph separator, and no invalid UTF-8
// byte, so SanitizeForDisplay would return it unchanged. Splitting this out
// keeps the common (clean) path allocation-free.
//
// This predicate MUST stay in lockstep with SanitizeForDisplay's escaping rules
// — it is that function's fast-path guard, so anything it calls safe is returned
// unsanitized.
func DisplaySafe(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if unicode.IsControl(r) {
			return false
		}
		if isLineSeparator(r) {
			return false
		}
		i += size
	}
	return true
}

// writeHexEscape appends a \xHH escape for a single byte.
func writeHexEscape(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0x0f])
}

// writeUnicodeEscape appends a \uHHHH escape for a rune in the Basic
// Multilingual Plane. The \xHH form writeHexEscape emits cannot represent a
// rune above U+00FF, so the line/paragraph separators the block sanitizer
// escapes need this wider form.
func writeUnicodeEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0x0f])
	}
}
