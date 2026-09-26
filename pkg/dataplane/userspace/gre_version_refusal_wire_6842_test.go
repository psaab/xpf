package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestGreDecapUnsupportedVersionRefusalsWireKeyLockstepWithRust pins the JSON
// key of ProcessStatus.GreDecapUnsupportedVersionRefusalsTotal to the key
// userspace-dp actually emits (#6842).
//
// NEITHER SIDE IS PINNED TO A LITERAL. The Rust key is read out of the
// `#[serde(rename = ...)]` attribute on the Rust field; the Go key is read out
// of the struct tag by reflection; the test asserts they AGREE. A literal here
// would encode which of the two spellings is trusted, and the failure this
// guards is precisely that one plane moved and the other did not.
//
// The failure is silent on both planes, which is why it needs a guard at all.
// The counter is additive and `default`-ed on the Rust side and `omitempty` on
// the Go side, so a key mismatch does not fail a decode — it yields 0 forever.
// Zero is also the correct reading for "no PPTP offered to a GRE endpoint", so
// a broken wire is indistinguishable from a healthy firewall on every operator
// surface: `show`, the Prometheus counter, and the JSON itself.
//
// FAIL-ON-REVERT: change the Go struct tag or the Rust rename without changing
// the other and this reds.
func TestGreDecapUnsupportedVersionRefusalsWireKeyLockstepWithRust(t *testing.T) {
	const rustField = "gre_decap_unsupported_version_refusals_total"
	const goField = "GreDecapUnsupportedVersionRefusalsTotal"

	// #7160: resolved by FIELD, not by file path — `ProcessStatus` moved out
	// of `control.rs` when that file crossed the modularity floor.
	rustKey := rustProcessStatusRename(t, rustField)

	field, ok := reflect.TypeOf(ProcessStatus{}).FieldByName(goField)
	if !ok {
		t.Fatalf("ProcessStatus has no field %s — the guard cannot run", goField)
	}
	goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if goKey != rustKey {
		t.Fatalf("wire-key drift: Go ProcessStatus.%s emits/decodes %q, userspace-dp emits %q. "+
			"A mismatch does not fail a decode — the counter reads 0 forever, which is also "+
			"what a healthy firewall reports", goField, goKey, rustKey)
	}

	// The decode leg. Asserting the two spellings agree does not prove the Go
	// struct actually reads that key into THIS field — a tag on the wrong
	// field would still spell it correctly.
	var status ProcessStatus
	payload := []byte(`{"` + rustKey + `":7}`)
	if err := json.Unmarshal(payload, &status); err != nil {
		t.Fatalf("unmarshal %s: %v", payload, err)
	}
	if status.GreDecapUnsupportedVersionRefusalsTotal != 7 {
		t.Fatalf("ProcessStatus.%s = %d after decoding %s, want 7 — the Rust key does not reach "+
			"this field", goField, status.GreDecapUnsupportedVersionRefusalsTotal, payload)
	}

	// The byte-level leg. The Rust decoder is regression-tested against
	// tests/fixtures/protocol_wire_v1.json (wire_invariant_default_specimens
	// regenerates it), so finding the key in those literal bytes closes the
	// loop Go tag -> Rust rename -> the bytes Rust actually writes. The
	// counter has no `skip_serializing_if` on the Rust side, so it is present
	// in a default specimen (as 0) by design.
	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}
	if !strings.Contains(string(raw), `"`+rustKey+`"`) {
		t.Errorf("%s does not contain the key %q that ProcessStatus decodes. The fixture is the "+
			"byte-level record of this wire; a status specimen missing the key means the "+
			"specimen predates the counter or the key moved on one plane only", fixture, rustKey)
	}
}

// TestGreDecapPtNibbleMismatchRefusalsWireKeyLockstepWithRust pins the
// #10865 ProcessStatus key to userspace-dp's serialized field.
func TestGreDecapPtNibbleMismatchRefusalsWireKeyLockstepWithRust(t *testing.T) {
	const rustField = "gre_decap_pt_nibble_mismatch_refusals_total"
	const goField = "GreDecapPtNibbleMismatchRefusalsTotal"

	rustKey := rustProcessStatusRename(t, rustField)
	field, ok := reflect.TypeOf(ProcessStatus{}).FieldByName(goField)
	if !ok {
		t.Fatalf("ProcessStatus has no field %s", goField)
	}
	goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if goKey != rustKey {
		t.Fatalf("wire-key drift: Go ProcessStatus.%s emits/decodes %q, userspace-dp emits %q",
			goField, goKey, rustKey)
	}

	var status ProcessStatus
	payload := []byte(`{"` + rustKey + `":13}`)
	if err := json.Unmarshal(payload, &status); err != nil {
		t.Fatalf("unmarshal %s: %v", payload, err)
	}
	if status.GreDecapPtNibbleMismatchRefusalsTotal != 13 {
		t.Fatalf("ProcessStatus.%s = %d after decoding %s, want 13",
			goField, status.GreDecapPtNibbleMismatchRefusalsTotal, payload)
	}

	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}
	if !strings.Contains(string(raw), `"`+rustKey+`"`) {
		t.Errorf("%s does not contain the ProcessStatus wire key %q", fixture, rustKey)
	}
}
