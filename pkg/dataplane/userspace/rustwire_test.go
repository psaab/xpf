package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
//   - struct lookup is EXACT (`struct Name {`, never a prefix — a
//     SessionDeltaInfoV2 sibling cannot shadow SessionDeltaInfo) and
//     visibility-agnostic (`pub`, `pub(crate)`, `pub(in path)`, or no
//     visibility all match);
//   - struct end is found by BRACE COUNTING, not a fixed line count, a
//     first "\n}" or a first column-0 "}" (two of the old copies' bugs);
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
// struct name under protocol/ is itself drift that fails loudly.

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

// rustStructBody returns the body (between the outer braces) of the named
// Rust struct in src. The declaration match is exact and
// visibility-agnostic; the end is found by counting braces from the
// opening brace, so nested braces inside field types cannot truncate it.
func rustStructBody(t *testing.T, src, name string) string {
	t.Helper()
	decl := regexp.MustCompile(`(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+` +
		regexp.QuoteMeta(name) + `\s*\{`)
	loc := decl.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("Rust struct %q not found — if it was renamed or moved, update this guard "+
			"rather than deleting it (#17142)", name)
	}
	open := loc[1] - 1 // the '{' itself
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i]
			}
		}
	}
	t.Fatalf("Rust struct %q has no closing brace; the parse cannot be scoped and a "+
		"file-wide match would bind the wrong struct (#17142)", name)
	return ""
}

// rustStructFields parses the fields of a Rust struct body (as returned
// by rustStructBody) into their wire shape. Multi-line #[serde(...)]
// attributes are accumulated until the closing `)]`; rename_all on the
// container is NOT handled here (no protocol struct this helper serves
// uses it; the #16132 Rust census models rename_all separately and
// panics on shapes it cannot model — extend deliberately, never guess).
func rustStructFields(t *testing.T, body string) []rustStructWireField {
	t.Helper()
	fieldRE := regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*:`)
	var out []rustStructWireField
	var pending strings.Builder
	inAttr := false
	rename := ""
	skipSer := false
	depth := 1 // the struct body's own depth; fields live exactly here
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		// Track brace depth so a field-looking line inside a nested
		// brace (a nested type's fields, a const block) is not read as
		// one of this struct's fields.
		lineDepth := depth
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if lineDepth != 1 {
			continue
		}
		if inAttr || strings.HasPrefix(trimmed, "#[") {
			pending.WriteString(line)
			pending.WriteString("\n")
			if strings.Contains(line, ")]") {
				inAttr = false
				attrs := pending.String()
				pending.Reset()
				if m := rustWireRenameRE.FindStringSubmatch(attrs); m != nil {
					rename = m[1]
				}
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
func rustWireFieldsInStruct(t *testing.T, path, structName string) []rustStructWireField {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the Go/Rust wire-key lockstep guard cannot run)", path, err)
	}
	return rustWireFieldsInStructSource(t, string(src), structName)
}

// rustWireFieldsInStructSource is rustWireFieldsInStruct over source text
// already in memory.
func rustWireFieldsInStructSource(t *testing.T, src, structName string) []rustStructWireField {
	t.Helper()
	return rustStructFields(t, rustStructBody(t, src, structName))
}

// rustWireFieldsInProtocolStruct finds the named struct by searching every
// .rs file under userspace-dp/src/protocol/ for its declaration (#7160: a
// struct that moves files when its file crosses the modularity floor must
// still be found; zero or duplicate declarations fail loudly rather than
// silently binding the first).
func rustWireFieldsInProtocolStruct(t *testing.T, structName string) []rustStructWireField {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v (the Go/Rust wire-key lockstep guard cannot run)", dir, err)
	}
	decl := regexp.MustCompile(`(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+` +
		regexp.QuoteMeta(structName) + `\s*\{`)
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
		if !decl.Match(src) {
			continue
		}
		found = append(found, e.Name())
		fields = rustWireFieldsInStructSource(t, string(src), structName)
	}
	switch len(found) {
	case 0:
		t.Fatalf("no `struct %s` found under %s. If it was renamed or removed, UPDATE this "+
			"lockstep guard rather than deleting it (#7160/#17142)", structName, dir)
	case 1:
	default:
		t.Fatalf("`struct %s` is declared in %d files under %s (%v). Two declarations of one "+
			"wire struct is the drift this guard exists to catch (#7160/#17142)",
			structName, len(found), dir, found)
	}
	return fields
}

// rustWireKeyInStruct returns the wire key of rustField on the named
// struct in the file at path. When requireRename is true a field that
// only relies on serde's default naming (its own identifier) fails:
// callers pinning a DELIBERATE wire spelling (the #7037/#6691 shape) pass
// true so losing the explicit rename cannot green; callers pinning
// whatever serde actually emits pass false.
func rustWireKeyInStruct(t *testing.T, path, structName, rustField string, requireRename bool) string {
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
func rustWireKeyInProtocolStruct(t *testing.T, structName, rustField string, requireRename bool) string {
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
func rustWireKeysInStruct(t *testing.T, path, structName string) map[string]bool {
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
// rename, as its original did.
func rustSerdeRenameOf(t *testing.T, structBody, field string) string {
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
