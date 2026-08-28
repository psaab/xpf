package userspace

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestEgressZoneWireKeyLockstepWithRust_7037 asserts the Go emitter and the Rust
// consumer AGREE on the wire spelling of the #6722 egress-zone field.
//
// #7037 was filed against the version NUMBER, on the finding that reverting
// ProtocolVersion left the suite green. That premise is no longer true — at
// current master the revert reds three tests (TestMixedVersionMatrix_6691,
// TestSnapshotProtocolVersionLockstepWithRust,
// TestSecureTunnelFieldIsNotIgnorableByAPreV5Helper), because #6691's pins
// landed after the issue was written. Adding the equality pin the issue asks
// for would be a third copy of the same literal, and adding a per-feature floor
// is ruled out by an explicit decision recorded in protocol.go: the acceptance
// question is answered in EXACTLY ONE place (ensureEgressZoneProtocolLocked's
// unconditional equality check), and a second gate would be the divergent copy
// #6649 forbids.
//
// What the version pins do NOT cover is the wire KEY they exist to protect.
// Both sides spell it independently:
//
//	Go    InterfaceSnapshot.EgressZone `json:"egress_zone"`
//	Rust  #[serde(rename = "egress_zone", default)] pub egress_zone: String
//
// and `default` on the Rust side is what makes a disagreement SILENT rather
// than loud: an absent key does not fail to decode, it fills the empty String.
// So a one-sided rename ships a snapshot in which every interface resolves
// egress zone "" while both planes still agree the version is 8 — the same
// silent-transit outcome #7037 names, reached by a route its proposed fix does
// not touch.
//
// This guard reads the Go side by REFLECTION rather than restating the literal.
// Pinning one side to a literal encodes which side you trust; the property is
// that the two AGREE. A consistent rename of BOTH sides passes here and is
// correct — and is separately caught by
// TestEgressZoneCrossesTheWireAndTheQuarantine_6722, which pins the Go literal
// against the emitted blob. The two together are what bind the key: this test
// says "the planes match", that one says "the match is the value we shipped".
//
// Parsed rather than mirrored, for the reason
// TestSnapshotProtocolVersionLockstepWithRust parses control.rs for the version:
// a constant restated in a comment is a copy that goes stale silently.
func TestEgressZoneWireKeyLockstepWithRust_7037(t *testing.T) {
	goKey := jsonKeyOf(t, reflect.TypeOf(InterfaceSnapshot{}), "EgressZone")

	// Test cwd is pkg/dataplane/userspace.
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the egress-zone wire-key lockstep guard cannot run)", path, err)
	}

	body := rustStructBody(t, string(src), "InterfaceSnapshot")
	rustKey := rustSerdeRenameOf(t, body, "egress_zone")

	if goKey != rustKey {
		t.Fatalf("egress-zone wire key skew: Go InterfaceSnapshot.EgressZone emits %q, Rust "+
			"InterfaceSnapshot reads %q. The Rust field carries #[serde(default)], so a "+
			"disagreement does NOT fail to decode — the key is simply absent and serde fills "+
			"the empty String. Every interface then resolves egress zone \"\" while both "+
			"planes still agree ProtocolVersion is %d, so no version gate fires and transit "+
			"fails closed silently. Rename BOTH sides or neither.",
			goKey, rustKey, ProtocolVersion)
	}
}

// jsonKeyOf returns the wire name a Go field serialises under, read off the
// struct rather than restated, so this guard cannot drift from the type it
// describes.
func jsonKeyOf(t *testing.T, typ reflect.Type, field string) string {
	t.Helper()
	f, ok := typ.FieldByName(field)
	if !ok {
		t.Fatalf("%s has no field %q — if it was renamed, update this guard rather than "+
			"deleting it; the wire key it binds is still on the wire", typ.Name(), field)
	}
	tag := f.Tag.Get("json")
	if tag == "" {
		t.Fatalf("%s.%s carries no json tag, so it serialises under its GO name. That is a "+
			"wire change on its own", typ.Name(), field)
	}
	return strings.Split(tag, ",")[0]
}

// rustStructBody returns the body of a named Rust struct: from its declaration
// to the first closing brace in column 0. Scoping matters — `egress_zone` also
// appears in control.rs and binding.rs on different structs, and a file-wide
// regex would bind whichever happened to come first.
func rustStructBody(t *testing.T, src, name string) string {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^(?:pub|pub\(crate\)) struct ` + regexp.QuoteMeta(name) + `\s*\{`)
	loc := decl.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("Rust struct %q not found — if it was renamed or moved, update this guard "+
			"rather than deleting it", name)
	}
	rest := src[loc[1]:]
	end := regexp.MustCompile(`(?m)^\}`).FindStringIndex(rest)
	if end == nil {
		t.Fatalf("Rust struct %q has no closing brace in column 0; the parse cannot be "+
			"scoped and a file-wide match would bind the wrong struct", name)
	}
	return rest[:end[0]]
}

// rustSerdeRenameOf returns the serde wire name of a Rust field. It requires the
// rename attribute: relying on serde's default (the field's own identifier)
// would make this guard pass on a struct that had lost the attribute entirely,
// which is one of the two ways the spellings can drift apart.
func rustSerdeRenameOf(t *testing.T, structBody, field string) string {
	t.Helper()
	re := regexp.MustCompile(`#\[serde\(rename = "([^"]+)"[^\]]*\)\]\s*pub ` +
		regexp.QuoteMeta(field) + `\s*:`)
	m := re.FindStringSubmatch(structBody)
	if m == nil {
		t.Fatalf("no #[serde(rename = ...)] found on Rust field %q. Either the field is gone "+
			"— in which case the Go emitter is writing a key nothing reads — or it now relies "+
			"on serde's default naming, which this guard deliberately does not accept: the "+
			"whole point is that the wire spelling is stated on both sides", field)
	}
	return m[1]
}
