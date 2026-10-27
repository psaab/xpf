package userspace

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// session_delta_transport_parity_7194_test.go — #7194 item 1.
//
// xpf has two HA session-open transports and, until this file, nothing that
// made them equivalent — only the discipline of remembering to edit both.
//
// The evidence #5865 collected is the whole argument for this test. Five fields
// existed on the binary open frame and the Go consumer but not on the Rust JSON
// producer, so the JSON leg installed zeros. Worse, the Go struct's own doc
// comment asserted those fields were "mirrored on the JSON RPC-fallback delta",
// and that sentence was FALSE from the day it was written — nothing detected it,
// because nothing compared the two transports. #6312 is the recurrence: a field
// added to the binary leg in #5212 reached the JSON leg one issue later.
//
// The parity itself is currently CORRECT — #6949 closed the five-field gap, and
// both sides carry 41 fields as of this commit. That is what this test is for.
// It is a REGRESSION GUARD, not a fix: it exists so the next field added to one
// leg reds the suite instead of shipping, which is precisely what did not happen
// the last two times.
//
// WHY IT COMPARES WIRE NAMES AND NOT FIELD NAMES.
//
// The Rust struct carries 35 `#[serde(rename = "...")]` attributes and the Go
// struct carries json tags. Today every rename is an identity rename, so a
// field-name comparison would also pass — and would keep passing through a
// future rename that broke the wire while leaving both field names alone. The
// contract between these two programs is the JSON on the wire, so that is what
// is compared. Pinning the field names instead would encode the wrong SSOT.

// The wire name of a Go field: the json tag before any option, falling back to
// the field name. `json:"-"` means the field is not on the wire at all.
func goWireNames7194(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	typ := reflect.TypeOf(SessionDeltaInfo{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Name
	}
	return out
}

// #17142: rustWireNames7194 used to be its own brace-counted extractor —
// the best of the seven divergent copies (it fixed fixed-range truncation
// and SessionDeltaInfoV2 prefix-matching in its own copy, and those fixes
// never propagated to the #6949/#7037 copies). It is now the shared
// struct-scoped parser in rustwire_test.go; the name is kept only as this
// thin adapter so the #7194/#8043 cells below read unchanged.
func rustWireNames7194(t *testing.T) map[string]bool {
	t.Helper()
	return rustWireKeysInStruct(t,
		filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs"),
		"SessionDeltaInfo")
}

// Neither transport may carry a session-open field the other does not.
func TestSessionDeltaTransportsCarryTheSameFields7194(t *testing.T) {
	goNames := goWireNames7194(t)
	rustNames := rustWireNames7194(t)

	// ANTI-VACUITY FLOOR. Both extractions are text- or reflection-driven and
	// both can silently come back short — a moved file, a renamed struct, a
	// regex that stops matching after a syntax change. Every comparison below
	// would then pass over a near-empty set and certify a parity nobody
	// measured. 35 is comfortably under the current 41 and comfortably over
	// anything a broken extractor would produce.
	const floor = 35
	if len(goNames) < floor {
		t.Fatalf("the Go struct reflected only %d wire fields (floor %d); the "+
			"extraction is broken, so a clean result here would certify nothing",
			len(goNames), floor)
	}
	if len(rustNames) < floor {
		t.Fatalf("the Rust struct parsed to only %d wire fields (floor %d); the "+
			"extraction is broken, so a clean result here would certify nothing",
			len(rustNames), floor)
	}

	for wire, goField := range goNames {
		if !rustNames[wire] {
			t.Errorf("the Go consumer expects session-open field %q (%s) that the "+
				"Rust JSON producer does not emit. The JSON leg will decode it as a "+
				"ZERO, and a zero is indistinguishable from a legitimately-absent "+
				"value at the consumer — which is exactly how #5865's five-field gap "+
				"survived for months (#7194)", wire, goField)
		}
	}
	for wire := range rustNames {
		if _, ok := goNames[wire]; !ok {
			t.Errorf("the Rust JSON producer emits session-open field %q that the Go "+
				"consumer does not read. Adding a field to one transport and not the "+
				"other is the #6312 recurrence this test exists to catch (#7194)", wire)
		}
	}
}

// The Rust extractor must survive its own failure modes visibly.
//
// Without this, a regex that matched nothing would make the test above fail on
// the floor with a message about parity rather than about parsing — and the
// next reader would go looking for a missing field instead of a broken test.
func TestRustSessionDeltaExtractorFindsKnownFields7194(t *testing.T) {
	rustNames := rustWireNames7194(t)
	// Three shapes deliberately: a plain field, one whose Go spelling differs
	// sharply from the wire name, and one of the five #5865 added late. If the
	// parser regressed to matching only the simplest shape, the first would
	// still be found and the others would not.
	for _, want := range []string{"timestamp", "rt_flow_session_id", "nat64_snat_v4"} {
		if !rustNames[want] {
			t.Errorf("the Rust extractor did not find field %q. Either the struct "+
				"changed shape or the parser regressed; until that is resolved the "+
				"parity assertion above is not measuring what it claims", want)
		}
	}
}
