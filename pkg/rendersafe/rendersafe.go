// Package rendersafe holds render-side belts shared by the config generators
// that interpolate operator-supplied text into a third-party daemon's
// configuration file (#6833).
//
// # A function here is NOT a security boundary on its own
//
// Everything in this package is a PRIMITIVE: it performs a byte substitution
// and knows nothing about the grammar it is protecting. Whether that
// substitution is SAFE is a per-consumer fact, because the substituted byte has
// to be ordinary text in the consuming parser. That fact belongs at the call
// site, not here, and every caller is expected to state it.
//
// The failure this package exists to prevent is the one #6833 describes: two
// packages carried byte-identical sanitizers whose doc comments justified them
// by newline injection, while neither recorded whether the SPACE they substitute
// in was safe for its own consumer. A sanitizer whose apparent purpose is "no
// control characters" while the load-bearing constraint is something else invites
// a future edit relaxing it to "printable ASCII" — an edit that looks like a
// cleanup, still blocks the newline the comment names, and admits the byte that
// actually matters. Duplicating the body means that edit can be made twice,
// independently.
//
// So: the body lives here once, and the JUSTIFICATION lives at each call site.
// # Predicates name their grammar; primitives must not
//
// A second kind of member shares this package: PREDICATES that state a
// consumer-grammar property renderers need answered identically
// (RendersAsOnePattern). Unlike a primitive, a predicate necessarily names
// the grammar it checks — the property IS the grammar fact — so the
// "knows nothing about the grammar" rule above does not apply to it. What
// still applies is the second half: the predicate answers the question and
// NOTHING ELSE. Whether a "no" means refuse, drop, or escape is the
// per-consumer decision, and it still lives at each call site.
package rendersafe

import "strings"

// ReplaceControlBytes returns s with every ASCII C0 control byte (0x00-0x1F,
// which includes CR and LF) and DEL (0x7F) replaced by repl. All other bytes,
// including every byte of a multi-byte UTF-8 sequence, are returned unchanged —
// C0 and DEL cannot appear as a continuation byte, so this is safe on UTF-8
// input and never splits a rune.
//
// It returns s itself when there is nothing to replace, so the common clean path
// allocates nothing.
//
// # Choosing repl is the caller's decision, and it is the load-bearing one
//
// repl must be a byte the CONSUMING parser treats as ordinary text. A space is
// the usual choice and is wrong wherever the consumer's grammar makes whitespace
// significant — a whitespace-separated list key, or a
// <selector><whitespace><action> line grammar, where substituting a space
// manufactures the very delimiter the sanitizer was supposed to be protecting.
// See #6829 for a case where the space, not the newline, was the live byte.
//
// This function cannot check that for you. State it where you call it.
func ReplaceControlBytes(s string, repl byte) string {
	isCtl := func(c byte) bool { return c < 0x20 || c == 0x7f }

	clean := true
	for i := 0; i < len(s); i++ {
		if isCtl(s[i]) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if isCtl(b[i]) {
			b[i] = repl
		}
	}
	return string(b)
}

// The separator set RendersAsOnePattern refuses is the UNION of what the two
// consumers treat as splitting, and the union is the safe direction on both
// sides:
//
//   - The kernel forbids the whole ASCII whitespace set in device names
//     (dev_valid_name rejects ASCII isspace, net/core/dev.c), so a name
//     carrying one of these bytes can NEVER be a real device. Refusing it
//     cannot break a working config — the #6564 direction.
//   - systemd reads [Match] Name= (and its siblings) as a whitespace-separated
//     list of globs, so a name carrying one of these bytes occupies two or
//     more slots and claims devices other than the intended one (#9886).
//
// Two deliberate edges, both pinned by tests:
//
//   - \v and \f are REFUSED although systemd's own WHITESPACE macro lists
//     only space/tab/CR/LF. The kernel forbids them, so a refused \v/\f name
//     was never a real device; loud refusal beats the silent no-match
//     rendering it would otherwise produce.
//   - Unicode spaces (NBSP, NEL, U+2028/9) PASS. The kernel allows them and
//     systemd treats them atomically, so they are working single-pattern
//     names; strings.Fields would split them, which is why this predicate
//     does not use it. A pre-gate config carrying one keeps booting.
//
// What this predicate does NOT check: glob metacharacters (*?[]) are exactly
// one pattern and PASS here. They are refused at commit for interfaces
// (#6834) but have no render-side belt yet; that is #10089, not this
// predicate. A caller that needs "one LITERAL pattern" must check the glob
// class itself until #10089 lands.
func RendersAsOnePattern(name string) bool {
	return name != "" && !strings.ContainsAny(name, " \t\n\v\f\r")
}

// containsControlBytes reports whether s carries any ASCII control byte (C0
// set or DEL). The byte-wise scan is correct for UTF-8 input because
// multi-byte sequences never contain bytes below 0x80.
func containsControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// SafeInterfaceName is the RENDER contract for a name interpolated into a
// systemd unit's Name=/OriginalName= slot (#9886): exactly one match-list
// pattern AND free of control bytes. Render callers (the networkd belt, the
// linksetup .link guard) check this, not RendersAsOnePattern alone.
//
// WHY CONTROLS ARE REFUSED AT RENDER EVEN THOUGH THE KERNEL ALLOWS MOST OF
// THEM. dev_valid_name forbids only '/', ':' and ASCII whitespace, so a
// device named "ge\x010" is kernel-legal. But what systemd makes of a raw
// control byte in a unit file — literal match, dropped directive, misparse —
// is version-dependent and unanalyzed, and a root-written unit file is no
// place for unanalyzed bytes. Refusal is fail-closed: no file, loud error.
// The population it can strand is hand-crafted kernel names only (udev and
// systemd never mint control bytes; the strict commit path rejects them and
// the lenient path scrubs them), and the recovery is a rename.
//
// What this predicate does NOT check: glob metacharacters (*?[]) PASS — they
// are one pattern and control-free. Render-side glob refusal is #10089.
func SafeInterfaceName(name string) bool {
	return RendersAsOnePattern(name) && !containsControlBytes(name)
}
