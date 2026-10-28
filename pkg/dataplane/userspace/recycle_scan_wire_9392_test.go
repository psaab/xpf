package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #9392: `recycle_scan_pops` was a Rust `#[cfg(test)]` seam, so the
// non-amortizing recycled phase #9327 measured had no operator-visible signal at
// all. Promoting it means a new wire pair on `SourceNATPoolStatus`, and this
// pins that wire.
//
// NEITHER SIDE IS PINNED TO A LITERAL, following #6842/#6929: the Rust key is
// read out of the `#[serde(rename = ...)]` attribute in `protocol/nat.rs`, the
// Go key out of the struct tag by reflection, and the test asserts they AGREE. A
// literal would encode which of the two spellings is trusted, and the failure
// being guarded is exactly that one plane moved and the other did not.
//
// WHY THIS PAIR. Both fields are additive — `default` on the Rust side,
// `omitempty` on the Go side — so a key mismatch never fails a decode. It reads
// 0 forever, and 0 is the reading that means "no claim entered the recycled
// phase", i.e. indistinguishable from a healthy pool. The instrument would look
// present and say nothing, which is the state #9392 exists to leave behind.
//
// ADD, NEVER REDEFINE: the helper and the daemon roll independently, so this
// also asserts that the two NEW keys are new — an existing key repurposed to
// carry a pop count would be decoded by an old daemon as whatever it used to
// mean.
func TestRecycleScanWireKeysLockstepWithRust9392(t *testing.T) {
	for _, tc := range []struct {
		rustField string
		goField   string
		probe     uint64
		read      func(SourceNATPoolStatus) uint64
		other     func(SourceNATPoolStatus) uint64
		otherName string
	}{
		{
			rustField: "recycle_scan_pops_total",
			goField:   "RecycleScanPopsTotal",
			probe:     9392,
			read:      func(s SourceNATPoolStatus) uint64 { return s.RecycleScanPopsTotal },
			other:     func(s SourceNATPoolStatus) uint64 { return s.RecycleScanWalksTotal },
			otherName: "RecycleScanWalksTotal",
		},
		{
			rustField: "recycle_scan_walks_total",
			goField:   "RecycleScanWalksTotal",
			probe:     587,
			read:      func(s SourceNATPoolStatus) uint64 { return s.RecycleScanWalksTotal },
			other:     func(s SourceNATPoolStatus) uint64 { return s.RecycleScanPopsTotal },
			otherName: "RecycleScanPopsTotal",
		},
	} {
		rustKey := rustSourceNATPoolRename9392(t, tc.rustField)

		field, ok := reflect.TypeOf(SourceNATPoolStatus{}).FieldByName(tc.goField)
		if !ok {
			t.Fatalf("SourceNATPoolStatus has no field %s — the guard cannot run", tc.goField)
		}
		goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if goKey != rustKey {
			t.Fatalf("wire-key drift: Go SourceNATPoolStatus.%s decodes %q, userspace-dp "+
				"emits %q. A mismatch does not fail a decode — the counter reads 0 "+
				"forever, and 0 is also what a healthy pool reports, so the signal "+
				"#9392 added would be silently absent (#9392)", tc.goField, goKey, rustKey)
		}

		// The decode leg: the key must reach THIS field. A correctly spelled tag
		// on the wrong field passes the comparison above.
		var pool SourceNATPoolStatus
		payload := []byte(`{"` + rustKey + `":` + itoa9392(tc.probe) + `}`)
		if err := json.Unmarshal(payload, &pool); err != nil {
			t.Fatalf("unmarshal %s: %v", payload, err)
		}
		if got := tc.read(pool); got != tc.probe {
			t.Fatalf("SourceNATPoolStatus.%s = %d after decoding %s, want %d — the Rust "+
				"key does not reach this field", tc.goField, got, payload, tc.probe)
		}
		// The SIBLING must not move. The pair is read as pops/walks, so a tag
		// that aliased one onto the other would report a permanent 1.00 ratio —
		// the healthy reading — for every pool including the pathological ones.
		if got := tc.other(pool); got != 0 {
			t.Fatalf("decoding %s also set %s to %d — the two halves of the pair are "+
				"aliased onto one field, and the render divides one by the other",
				payload, tc.otherName, got)
		}

		// The byte-level leg: the committed wire fixture is the record of what
		// Rust actually writes. Neither field has `skip_serializing_if`, so both
		// are present (as 0) in a default specimen by design.
		fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read %s: %v", fixture, err)
		}
		if !strings.Contains(string(raw), `"`+rustKey+`"`) {
			t.Errorf("%s does not contain the key %q. The fixture is the byte-level "+
				"record of this wire; a source_nat_pool_status specimen missing the key "+
				"means the specimen predates the counter or the key moved on one plane "+
				"only", fixture, rustKey)
		}
	}

	// ADD-NOT-REDEFINE, asserted rather than asserted-in-prose: neither new key
	// may collide with a key some OTHER field of the same struct already
	// decodes. A repurposed key is the rolling-upgrade break #9392's acceptance
	// names explicitly, and it is invisible to every assertion above — those
	// only check that the key reaches the field they expect.
	seen := map[string]string{}
	rt := reflect.TypeOf(SourceNATPoolStatus{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if key == "" || key == "-" {
			continue
		}
		if prev, dup := seen[key]; dup {
			t.Errorf("SourceNATPoolStatus keys %s and %s both decode %q — one of them "+
				"redefines a field an older peer already gives a different meaning "+
				"(#9392)", prev, f.Name, key)
		}
		seen[key] = f.Name
	}
}

// #17142: rustSourceNATPoolRename9392 was the seventh divergent copy
// (directory field search, file-wide first rename match once the field
// was located). It is now the shared struct-scoped parser
// (rustwire_test.go) over SourceNatPoolStatus; name kept as an adapter.
func rustSourceNATPoolRename9392(t *testing.T, rustField string) string {
	t.Helper()
	return rustWireKeyInProtocolStruct(t, "SourceNatPoolStatus", rustField, false)
}

func itoa9392(v uint64) string {
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
