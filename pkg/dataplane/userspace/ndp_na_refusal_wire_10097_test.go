package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #10097: the #9893 refusal counters (`NDP_NA_FRAG_REFUSED` /
// `NDP_NA_BAD_SOURCE_REFUSED`) are process-global parser atomics carried to
// Prometheus as `xpf_userspace_ndp_na_frag_refused_total` /
// `xpf_userspace_ndp_na_bad_source_refused_total`.
//
// This file pins the WIRE for that counter pair, in the same shape as the
// #6842 / #6929 / #9169 guards: neither side is pinned to a literal. The Rust
// key is read out of the `#[serde(rename = ...)]` attribute, the Go key out of
// the struct tag by reflection, and the test asserts they AGREE. A literal
// would encode which of the two spellings is trusted, and the failure being
// guarded is that one plane moved and the other did not.
//
// WHY THIS PAIR NEEDS THE GUARD. Both fields are additive: `default` on the
// Rust side, `omitempty` on the Go side. A key mismatch therefore never fails
// a decode — the counter reads 0 forever. And 0 is not a suspicious reading
// here, it is the reading a healthy system shows when no NA-shaped frame has
// been refused yet. The instrument would look present and say nothing, which
// is worse than its absence: a refused-learn flood (fragmented or
// spoofed-source NAs, the #9893 fail-closed audit signal) would pass with both
// series flat at zero and every suite green.
func TestNdpNaRefusalWireKeysLockstepWithRust10097(t *testing.T) {
	for _, tc := range []struct {
		rustField string
		goField   string
		probe     uint64
		read      func(ProcessStatus) uint64
		other     func(ProcessStatus) uint64
		otherName string
	}{
		{
			rustField: "ndp_na_frag_refused_total",
			goField:   "NDPNAFragRefusedTotal",
			probe:     10097,
			read:      func(s ProcessStatus) uint64 { return s.NDPNAFragRefusedTotal },
			other:     func(s ProcessStatus) uint64 { return s.NDPNABadSourceRefusedTotal },
			otherName: "NDPNABadSourceRefusedTotal",
		},
		{
			rustField: "ndp_na_bad_source_refused_total",
			goField:   "NDPNABadSourceRefusedTotal",
			probe:     97,
			read:      func(s ProcessStatus) uint64 { return s.NDPNABadSourceRefusedTotal },
			other:     func(s ProcessStatus) uint64 { return s.NDPNAFragRefusedTotal },
			otherName: "NDPNAFragRefusedTotal",
		},
	} {
		// #7160: resolved by FIELD, not by file path — `ProcessStatus` moved out
		// of `control.rs` when that file crossed the modularity floor.
		rustKey := rustProcessStatusRename(t, tc.rustField)

		field, ok := reflect.TypeOf(ProcessStatus{}).FieldByName(tc.goField)
		if !ok {
			t.Fatalf("ProcessStatus has no field %s — the guard cannot run", tc.goField)
		}
		goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if goKey != rustKey {
			t.Fatalf("wire-key drift: Go ProcessStatus.%s decodes %q, userspace-dp emits %q. "+
				"A mismatch does not fail a decode — the counter reads 0 forever, which is "+
				"the healthy reading for a refusal series, so a refused-learn flood would "+
				"pass with both #10097 series flat at zero (#10097)", tc.goField, goKey, rustKey)
		}

		// The decode leg. Agreement between the two spellings does not prove the
		// Go struct reads that key into THIS field — a correctly spelled tag on
		// the wrong field would still pass the comparison above.
		var status ProcessStatus
		payload := []byte(`{"` + rustKey + `":` + itoa10097(tc.probe) + `}`)
		if err := json.Unmarshal(payload, &status); err != nil {
			t.Fatalf("unmarshal %s: %v", payload, err)
		}
		if got := tc.read(status); got != tc.probe {
			t.Fatalf("ProcessStatus.%s = %d after decoding %s, want %d — the Rust key does "+
				"not reach this field", tc.goField, got, payload, tc.probe)
		}
		// The SIBLING must not move. The pair is read as two independent
		// refusal series (fragment vs bad-source, first-defect attribution in
		// the parser), so a tag that aliased one onto the other would double-
		// count one defect class and starve the other while satisfying every
		// assertion above.
		if got := tc.other(status); got != 0 {
			t.Fatalf("decoding %s also set %s to %d — the two halves of the #10097 pair are "+
				"aliased onto one field, and the fail-closed audit cannot tell a fragmented "+
				"NA from a spoofed-source NA",
				payload, tc.otherName, got)
		}

		// The byte-level leg: the committed wire fixture is the record of what
		// Rust actually writes, closing the loop Go tag -> Rust rename -> bytes.
		// Neither field has `skip_serializing_if`, so both are present (as 0) in
		// a default specimen by design.
		fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read %s: %v", fixture, err)
		}
		if !strings.Contains(string(raw), `"`+rustKey+`"`) {
			t.Errorf("%s does not contain the key %q that ProcessStatus decodes. The fixture "+
				"is the byte-level record of this wire; a status specimen missing the key "+
				"means the specimen predates the counter or the key moved on one plane only",
				fixture, rustKey)
		}
	}
}

func itoa10097(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
