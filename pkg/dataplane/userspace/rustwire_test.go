package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// #17142: ONE struct-scoped Rust-source serde scanner for every Go wire
// lockstep cell in this package.
//
// The seven divergent hand-written copies that preceded it disagreed on
// struct scoping, struct end, visibility and attribute carry. Two of their
// defects are what this issue is filed on:
//
//   - the #11070 ingress-identity cell used a FILE-WIDE first-match regex
//     (the old rustSerdeRenameIn), so it read ExceptionStatus's
//     `ingress_ifindex` (binding.rs, declared first) instead of
//     SessionDeltaInfo's. Swapping SessionDeltaInfo's ingress and NAT-scope
//     renames therefore passed every Go cell (mutant C): the key SET is
//     unchanged by a swap and the one per-field cell was scoped to the
//     wrong struct. Control C' proved the cell would have caught the swap
//     if scoped correctly.
//   - the #6949 key-set copy matched fields with `^\s*pub ([a-z0-9_]+)`,
//     so a legal `pub` -> `pub(crate)` visibility edit made a real wire
//     field vanish from the parsed set and reported false drift (mutant B).
//
// The semantics here are the union of the fixes the individual copies
// accumulated, stated once:
//
//   - scanning is COMMENT/STRING-AWARE: a state machine blanks line
//     comments, (nested) block comments, doc comments, string and raw-string
//     contents, and char literals before any declaration or brace is
//     counted, so a fake `pub struct SessionDeltaInfo { … }` written in a
//     `/* */` comment (or a brace inside a string) can neither win the
//     lookup nor truncate a real struct (review 18193 B1). The stripper
//     preserves bytes and newlines, so offsets and multi-line attributes
//     survive; quoted serde renames are read from the ORIGINAL text,
//     sliced by the stripped-text offsets;
//   - struct lookup is EXACT (`struct Name {`, never a prefix — a
//     SessionDeltaInfoV2 sibling cannot shadow SessionDeltaInfo) and
//     visibility-agnostic (`pub`, `pub(crate)`, `pub(in path)`, or no
//     visibility all match);
//   - struct end is found by BRACE COUNTING over the stripped text, not a
//     fixed line count, a first "\n}" or a first column-0 "}" (two of the
//     old copies' bugs), and braces in comments/strings never count;
//   - a field is `pub(<vis>)? name:` at the struct's own brace depth, so
//     nested-brace contents cannot register as fields, and visibility
//     changes on a field cannot hide it;
//   - `#[serde(...)]` attributes may span lines and may carry a rename on
//     any line of the attribute; a multi-line rename is still read (the
//     secure_tunnel attribute in snapshot.rs spans four lines);
//   - serde skip shapes (skip, skip_serializing, skip_serializing_if) mark
//     a field as not serialized; deserialize-only skips keep it serialized;
//   - a field with no rename serializes under its own identifier, which is
//     serde's default naming — callers decide whether that is acceptable
//     (see requireRename on rustWireKeyInStruct).
//
// Cells that pin a key to a FIELD (not just the key set) must use
// rustWireKeyInStruct / rustWireKeyInProtocolStruct; cells that pin sets
// use rustWireKeysInStruct. The contract directory search preserves the
// #7160 lesson: a struct that crosses the modularity floor and moves
// files must be found by NAME, and a duplicate declaration of the same
// struct name — whether across two files under protocol/ or twice inside
// ONE file (valid Rust in sibling `mod` blocks) — is itself drift that
// fails loudly rather than silently binding the first (review 18193 B2).

// rustWireTB is the minimal test handle the scanner helpers need.
// *testing.T satisfies it, and the review-18193 adversarial probes
// satisfy it with a recording Fatalf so an expected loud failure can be
// asserted instead of unwinding the probe goroutine (testing.TB itself
// cannot be implemented outside the testing package).
type rustWireTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// rustStructWireField is one field of a Rust struct as it appears on the
// JSON wire: the Rust identifier, the serialized key, whether an explicit
// serde rename stated that key, and whether serde skips serializing it.
type rustStructWireField struct {
	Name    string
	WireKey string
	Renamed bool
	SkipSer bool
}

var rustWireRenameRE = regexp.MustCompile(`rename\s*=\s*"([^"]+)"`)

// rustStripCommentsAndStrings blanks every byte that belongs to a Rust
// comment or string/char literal, replacing it with a space while
// preserving newlines, total length and therefore every byte offset.
// Line comments, nested block comments, doc comments, string literals
// with escapes, raw strings r".." / r#".."# / r##".."##, byte strings
// b"..", byte-raw strings br".."#, and char literals ('x', '\”,
// '\u{1F600}') are blanked. Lifetimes ('a, &'a mut, '_) are not char
// literals and pass through: a quote only opens a char literal when a
// closing quote follows on the same line.
//
// Code that must read a literal's TEXT (a serde rename) slices the
// ORIGINAL source with offsets found in the stripped source; the two
// have identical offsets by construction.
func rustStripCommentsAndStrings(src string) string {
	out := []byte(src)
	blank := func(i int) {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}
	for i := 0; i < len(src); {
		switch {
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '/':
			for ; i < len(src) && src[i] != '\n'; i++ {
				blank(i)
			}
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
			depth := 0
			for i < len(src) {
				if src[i] == '/' && i+1 < len(src) && src[i+1] == '*' {
					blank(i)
					blank(i + 1)
					i += 2
					depth++
					continue
				}
				if src[i] == '*' && i+1 < len(src) && src[i+1] == '/' {
					blank(i)
					blank(i + 1)
					i += 2
					depth--
					if depth == 0 {
						break
					}
					continue
				}
				blank(i)
				i++
			}
		case src[i] == '"':
			i = rustBlankQuoted(src, blank, i)
		case src[i] == 'r' && rustRawStringStart(src, i) >= 0:
			i = rustBlankRawString(src, blank, i)
		case src[i] == 'b' && i+1 < len(src) && src[i+1] == '"':
			blank(i)
			i = rustBlankQuoted(src, blank, i+1)
		case src[i] == 'b' && i+2 < len(src) && src[i+1] == 'r' && rustRawStringStart(src, i+1) >= 0:
			blank(i)
			i = rustBlankRawString(src, blank, i+1)
		case src[i] == '\'' && rustIsCharLiteralStart(src, i):
			i = rustBlankChar(src, blank, i)
		default:
			i++
		}
	}
	return string(out)
}

// rustBlankQuoted blanks a "..." string starting at src[i]=='"' (escapes
// honoured) and returns the index just past the closing quote.
func rustBlankQuoted(src string, blank func(int), i int) int {
	blank(i)
	i++
	for i < len(src) {
		if src[i] == '\\' && i+1 < len(src) {
			blank(i)
			blank(i + 1)
			i += 2
			continue
		}
		c := src[i]
		blank(i)
		i++
		if c == '"' {
			break
		}
	}
	return i
}

// rustRawStringStart returns the index of the opening '"' of a raw
// string whose 'r' is at i, or -1 if src[i:] does not start one. The
// 'r' must not be glued to a preceding identifier byte or '.'.
func rustRawStringStart(src string, i int) int {
	if i > 0 {
		p := src[i-1]
		if p == '_' || p == '.' || ('a' <= p && p <= 'z') || ('A' <= p && p <= 'Z') || ('0' <= p && p <= '9') {
			return -1
		}
	}
	j := i + 1
	for j < len(src) && src[j] == '#' {
		j++
	}
	if j < len(src) && src[j] == '"' {
		return j
	}
	return -1
}

// rustBlankRawString blanks r###"..."### starting at src[i]=='r' and
// returns the index just past the closer.
func rustBlankRawString(src string, blank func(int), i int) int {
	quote := rustRawStringStart(src, i)
	hashes := quote - (i + 1)
	for k := i; k <= quote; k++ {
		blank(k)
	}
	i = quote + 1
	for i < len(src) {
		if src[i] == '"' {
			j := i + 1
			for j < len(src) && src[j] == '#' && j-i-1 < hashes {
				j++
			}
			if j-i-1 == hashes {
				for k := i; k < j; k++ {
					blank(k)
				}
				return j
			}
		}
		blank(i)
		i++
	}
	return i
}

// rustIsCharLiteralStart reports whether src[i]=='\” opens a char
// literal rather than a lifetime. A Rust char literal is exactly one
// character (or one escape) between quotes: 'x', '}', '\n', '\”,
// '\u{1F600}'. A lifetime is an identifier with no closing quote in
// that shape: 'a, &'a mut, <'a>, '_ . Testing the closing shape —
// rather than "any quote later on this line" — is what keeps
// `fn keep<'a>(x: &'a str)` from being eaten as two char literals
// with the code between them blanked.
func rustIsCharLiteralStart(src string, i int) bool {
	j := i + 1
	if j >= len(src) {
		return false
	}
	if src[j] == '\\' {
		return true // escape-led char: '\n', '\'', '\u{…}'
	}
	// One non-quote, non-newline character immediately followed by the
	// closing quote is a char; a lifetime name runs on past one char.
	return src[j] != '\'' && src[j] != '\n' && j+1 < len(src) && src[j+1] == '\''
}

// rustBlankChar blanks a char literal starting at src[i]=='\” and
// returns the index just past the closing quote.
func rustBlankChar(src string, blank func(int), i int) int {
	blank(i)
	i++
	for i < len(src) {
		if src[i] == '\\' && i+1 < len(src) {
			blank(i)
			blank(i + 1)
			i += 2
			continue
		}
		c := src[i]
		blank(i)
		i++
		if c == '\'' {
			break
		}
	}
	return i
}

// rustStructDeclRE matches an exact, visibility-agnostic struct
// declaration in STRIPPED source (no comments/strings survive there).
func rustStructDeclRE(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+` +
		regexp.QuoteMeta(name) + `\s*\{`)
}

// rustStructBodies returns the stripped and original bodies of EVERY
// declaration of the named struct in src. Returning all of them (not
// the first) lets callers fail on duplicates instead of silently
// first-matching (review 18193 B2).
func rustStructBodies(t rustWireTB, src, name string) (strippedBodies, origBodies []string) {
	t.Helper()
	stripped := rustStripCommentsAndStrings(src)
	decl := rustStructDeclRE(name)
	for _, loc := range decl.FindAllStringIndex(stripped, -1) {
		open := loc[1] - 1 // the '{' itself, in stripped and original alike
		depth := 0
		closed := -1
		for i := open; i < len(stripped); i++ {
			switch stripped[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					closed = i
				}
			}
			if closed >= 0 {
				break
			}
		}
		if closed < 0 {
			t.Fatalf("Rust struct %q has no closing brace; the parse cannot be scoped and a "+
				"file-wide match would bind the wrong struct (#17142)", name)
		}
		strippedBodies = append(strippedBodies, stripped[open+1:closed])
		origBodies = append(origBodies, src[open+1:closed])
	}
	return strippedBodies, origBodies
}

// rustStructBody returns the body (between the outer braces) of the
// named Rust struct in src, in ORIGINAL text. The declaration is found
// and the end is brace-counted over comment/string-stripped text, so a
// brace in a comment or string can neither truncate the struct nor
// open one; the returned slice preserves the original bytes (including
// quoted serde renames) at the same extent. Exactly one declaration
// must exist: zero fails as not-found, two or more fail as a duplicate
// — in-file duplicates (sibling `mod` blocks) included.
func rustStructBody(t rustWireTB, src, name string) string {
	t.Helper()
	_, body := rustSingleStructBodies(t, src, name)
	return body
}

// rustSingleStructBodies enforces exactly-one declaration and returns
// its (stripped, original) bodies. On the fatal paths it returns zero
// values after Fatalf: with a real *testing.T the Fatalf unwinds before
// the return is reached, and with a non-unwinding captured TB (the
// review-18193 probe TB) the zero values keep the probe from panicking
// on an empty slice — the recorded fatal is the result.
func rustSingleStructBodies(t rustWireTB, src, name string) (strippedBody, origBody string) {
	t.Helper()
	stripped, orig := rustStructBodies(t, src, name)
	switch len(stripped) {
	case 0:
		t.Fatalf("Rust struct %q not found — if it was renamed or moved, update this guard "+
			"rather than deleting it (#17142)", name)
		return "", ""
	case 1:
	default:
		t.Fatalf("Rust struct %q is declared %d times in one source. Two declarations of one "+
			"wire struct is the drift this guard exists to catch; refusing to silently bind "+
			"the first (#17142, review 18193 B2)", name, len(stripped))
		return "", ""
	}
	return stripped[0], orig[0]
}

// rustStructFields parses the fields of a Rust struct body (as returned
// by rustStructBody, i.e. ORIGINAL text) into their wire shape. It
// strips comments/strings for structure (so a doc-comment brace or a
// `default = "…{"` literal cannot skew depth or masquerade as a field)
// while reading attribute literals from the original text at the same
// line offsets. Multi-line #[serde(...)] attributes are accumulated
// until the closing `)]`; rename_all on the container is NOT handled
// here (no protocol struct this helper serves uses it; the #16132 Rust
// census models rename_all separately and panics on shapes it cannot
// model — extend deliberately, never guess).
func rustStructFields(t rustWireTB, body string) []rustStructWireField {
	t.Helper()
	return rustStructFieldsPair(t, rustStripCommentsAndStrings(body), body)
}

// rustStructFieldsPair parses fields from a stripped struct body,
// reading attribute literal text (serde renames) from origBody at the
// same line offsets. Both bodies come from rustStructBodies, so they
// differ only inside blanked comments/strings. Multi-line #[serde(...)]
// attributes are accumulated until the closing `)]`; rename_all on the
// container is NOT handled here (no protocol struct this helper serves
// uses it; the #16132 Rust census models rename_all separately and
// panics on shapes it cannot model — extend deliberately, never guess).
func rustStructFieldsPair(t rustWireTB, strippedBody, origBody string) []rustStructWireField {
	t.Helper()
	fieldRE := regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*:`)
	var out []rustStructWireField
	var pending strings.Builder
	var pendingOrig strings.Builder
	inAttr := false
	rename := ""
	skipSer := false
	depth := 1 // the struct body's own depth; fields live exactly here
	strippedLines := strings.Split(strippedBody, "\n")
	origLines := strings.Split(origBody, "\n")
	for li, line := range strippedLines {
		origLine := ""
		if li < len(origLines) {
			origLine = origLines[li]
		}
		trimmed := strings.TrimSpace(line)
		// Track brace depth over STRIPPED text so a field-looking line
		// inside a nested brace (a nested type's fields, a const block)
		// is not read as one of this struct's fields, and braces in
		// comments/strings (already blanked) never count.
		lineDepth := depth
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if lineDepth != 1 {
			continue
		}
		if inAttr || strings.HasPrefix(trimmed, "#") {
			pending.WriteString(line)
			pending.WriteString("\n")
			pendingOrig.WriteString(origLine)
			pendingOrig.WriteString("\n")
			if strings.Contains(line, ")]") {
				inAttr = false
				attrs := pending.String()
				pending.Reset()
				// Rename value lives in the blanked literal; read it
				// from the ORIGINAL attribute text. Skip detection uses
				// stripped text so `skip` inside a string cannot fire.
				if m := rustWireRenameRE.FindStringSubmatch(pendingOrig.String()); m != nil {
					rename = m[1]
				}
				pendingOrig.Reset()
				if rustWireSkipSerializing(attrs) {
					skipSer = true
				}
			} else {
				inAttr = true
			}
			continue
		}
		if m := fieldRE.FindStringSubmatch(line); m != nil {
			f := rustStructWireField{Name: m[1], WireKey: m[1]}
			if rename != "" {
				f.WireKey = rename
				f.Renamed = true
			}
			f.SkipSer = skipSer
			out = append(out, f)
			rename, skipSer = "", false
			continue
		}
		// Doc comments and blank lines leave a pending rename alone;
		// the reset happens on the next field match above, so a rename
		// can never leak across a field boundary.
	}
	return out
}

// rustWireSkipSerializing reports whether a serde attribute block skips
// SERIALIZATION (skip / skip_serializing / skip_serializing_if), as
// opposed to only deserialization (skip_deserializing), which still
// emits the key.
func rustWireSkipSerializing(attrs string) bool {
	if !strings.Contains(attrs, "skip") {
		return false
	}
	// Normalize directional forms: skip_deserializing alone is not a
	// serialization skip.
	if strings.Contains(attrs, "skip_serializing") {
		return true
	}
	// Bare `skip` (both directions) — but not when it only appears as
	// part of skip_deserializing.
	rest := strings.ReplaceAll(attrs, "skip_deserializing", "")
	return regexp.MustCompile(`\bskip\b`).MatchString(rest)
}

// rustWireFieldsInStruct returns the wire fields of the named Rust struct
// declared in the file at path.
func rustWireFieldsInStruct(t rustWireTB, path, structName string) []rustStructWireField {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the Go/Rust wire-key lockstep guard cannot run)", path, err)
	}
	return rustWireFieldsInStructSource(t, string(src), structName)
}

// rustWireFieldsInStructSource is rustWireFieldsInStruct over source text
// already in memory.
func rustWireFieldsInStructSource(t rustWireTB, src, structName string) []rustStructWireField {
	t.Helper()
	strippedBody, origBody := rustSingleStructBodies(t, src, structName)
	return rustStructFieldsPair(t, strippedBody, origBody)
}

// rustWireFieldsInProtocolStruct finds the named struct by searching every
// .rs file under userspace-dp/src/protocol/ for its declaration (#7160: a
// struct that moves files when its file crosses the modularity floor must
// still be found; zero or duplicate declarations fail loudly rather than
// silently binding the first). Duplicates are counted per DECLARATION on
// comment/string-stripped text: two declarations in one file (sibling
// `mod` blocks) fail exactly like two declarations in two files, and a
// fake declaration inside a comment counts for nothing (review 18193).
func rustWireFieldsInProtocolStruct(t rustWireTB, structName string) []rustStructWireField {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v (the Go/Rust wire-key lockstep guard cannot run)", dir, err)
	}
	total := 0
	var found []string
	var fields []rustStructWireField
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rs") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		strippedBodies, origBodies := rustStructBodies(t, string(src), structName)
		if len(strippedBodies) == 0 {
			continue
		}
		total += len(strippedBodies)
		for range strippedBodies {
			found = append(found, e.Name())
		}
		fields = rustStructFieldsPair(t, strippedBodies[0], origBodies[0])
	}
	switch total {
	case 0:
		t.Fatalf("no `struct %s` found under %s. If it was renamed or removed, UPDATE this "+
			"lockstep guard rather than deleting it (#7160/#17142)", structName, dir)
	case 1:
	default:
		t.Fatalf("`struct %s` is declared %d times under %s (%v). Two declarations of one "+
			"wire struct is the drift this guard exists to catch (#7160/#17142)",
			structName, total, dir, found)
	}
	return fields
}

// rustWireKeyInStruct returns the wire key of rustField on the named
// struct in the file at path. When requireRename is true a field that
// only relies on serde's default naming (its own identifier) fails:
// callers pinning a DELIBERATE wire spelling (the #7037/#6691 shape) pass
// true so losing the explicit rename cannot green; callers pinning
// whatever serde actually emits pass false.
func rustWireKeyInStruct(t rustWireTB, path, structName, rustField string, requireRename bool) string {
	t.Helper()
	for _, f := range rustWireFieldsInStruct(t, path, structName) {
		if f.Name == rustField {
			if requireRename && !f.Renamed {
				t.Fatalf("Rust field %q on %s in %s has no explicit #[serde(rename = ...)]: "+
					"it relies on serde's default naming, which this guard deliberately does "+
					"not accept — the wire spelling must be stated on both sides (#17142)",
					rustField, structName, path)
			}
			return f.WireKey
		}
	}
	t.Fatalf("no Rust field %q on struct %s in %s. If the field was renamed or removed, "+
		"UPDATE this lockstep guard rather than deleting it — without it nothing pins the "+
		"Go key to the key the Rust side writes, and a mismatch is silent on both planes (#17142)",
		rustField, structName, path)
	return ""
}

// rustWireKeyInProtocolStruct is rustWireKeyInStruct with the struct
// located by name under protocol/ (#7160).
func rustWireKeyInProtocolStruct(t rustWireTB, structName, rustField string, requireRename bool) string {
	t.Helper()
	for _, f := range rustWireFieldsInProtocolStruct(t, structName) {
		if f.Name == rustField {
			if requireRename && !f.Renamed {
				t.Fatalf("Rust field %q on %s has no explicit #[serde(rename = ...)]: it relies "+
					"on serde's default naming, which this guard deliberately does not accept "+
					"(#17142)", rustField, structName)
			}
			return f.WireKey
		}
	}
	t.Fatalf("no Rust field %q on struct %s under userspace-dp/src/protocol/. If the field "+
		"was renamed or removed, UPDATE this lockstep guard rather than deleting it (#17142)",
		rustField, structName)
	return ""
}

// rustWireKeysInStruct returns the set of JSON keys the named Rust struct
// in the file at path SERIALIZES: the serde rename when present, the
// field identifier otherwise, excluding serialization-skipped fields.
// Struct-scoped and visibility-agnostic (the #6949 mutant-B fix).
func rustWireKeysInStruct(t rustWireTB, path, structName string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range rustWireFieldsInStruct(t, path, structName) {
		if !f.SkipSer {
			out[f.WireKey] = true
		}
	}
	return out
}

// rustSerdeRenameOf keeps the #7037 call shape (body text + field) for the
// snapshot cells, now over the shared parser. It requires the explicit
// rename, as its original did. Callers pass the ORIGINAL-text body from
// rustStructBody; rustStructFields strips it for structure and reads
// the rename literals from the original at the same offsets.
func rustSerdeRenameOf(t rustWireTB, structBody, field string) string {
	t.Helper()
	for _, f := range rustStructFields(t, structBody) {
		if f.Name == field {
			if !f.Renamed {
				t.Fatalf("no #[serde(rename = ...)] found on Rust field %q. Either the field is gone "+
					"— in which case the Go emitter is writing a key nothing reads — or it now relies "+
					"on serde's default naming, which this guard deliberately does not accept: the "+
					"whole point is that the wire spelling is stated on both sides (#7037/#17142)", field)
			}
			return f.WireKey
		}
	}
	t.Fatalf("no Rust field %q in the given struct body. If the field was renamed or removed, "+
		"UPDATE this lockstep guard rather than deleting it (#17142)", field)
	return ""
}
