package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func userspaceLeaseScope(v uint32) *uint32 {
	return &v
}

// #8121: the Go and Rust spellings of the idle-lease wire must AGREE.
//
// `IdleLeaseWire` exists twice — here (protocol.go) and in the helper
// (userspace-dp/src/protocol/control.rs). They meet over the control socket in
// `export_idle_leases` / `import_idle_leases`, and until now NOTHING asserted
// they agree.
//
// The tree's wire-invariant fixture would normally cover this, and could not:
// it dumps `::default()` specimens, and `idle_leases` carries
// `skip_serializing_if = "Vec::is_empty"`, so an empty vec is omitted and the
// payload's field names never appeared. Four of the type's own fields are
// `skip_serializing_if` too, so even a non-empty vec of defaults would have
// hidden them. The Rust side now contributes a POPULATED specimen; this cell
// asserts the Go side matches it.
//
// ASSERT THE AGREEMENT, never pin one side to a literal. A literal here would
// encode which side is trusted — and the failure mode being guarded is
// precisely that the two sides disagree, at which point a lease pushed by one
// node silently decodes to zero values on the other. On a rolling upgrade that
// is a persistent-NAT binding that survives on one node and not the other.

func TestIdleLeaseWireAgreesWithTheHelperSpelling8121(t *testing.T) {
	path := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures",
		"protocol_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("wire fixture not readable from here (%v); the Rust side pins its "+
			"own spelling either way", err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	specimen, ok := fixture["idle_lease_wire"]
	if !ok {
		t.Fatalf("the wire fixture has no `idle_lease_wire` specimen. Without one " +
			"the helper's field spellings are unpinned and this cell asserts " +
			"nothing — see protocol/tests.rs.")
	}
	var helperFields map[string]any
	if err := json.Unmarshal(specimen, &helperFields); err != nil {
		t.Fatalf("parse specimen: %v", err)
	}

	// The Go side, serialized with every field populated so nothing is elided
	// by omitempty — the same reason the Rust specimen is populated.
	goJSON, err := json.Marshal(IdleLeaseWire{
		Pool: "p1", Protocol: 6,
		SrcIP: "10.0.61.102", SrcPort: 40000,
		RoutingScope: userspaceLeaseScope(7),
		RemoteIP: "8.8.8.8", RemotePort: 443,
		TranslatedIP: "172.16.80.7", TranslatedPort: 51400,
		AddressOnly: true, RemainingNs: 123, TimeoutNs: 300_000_000_000,
	})
	if err != nil {
		t.Fatalf("marshal Go IdleLeaseWire: %v", err)
	}
	var goFields map[string]any
	if err := json.Unmarshal(goJSON, &goFields); err != nil {
		t.Fatalf("parse Go JSON: %v", err)
	}

	names := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	gotGo, gotHelper := names(goFields), names(helperFields)

	// POSITIVE CONTROL: a spelling set this small would be suspicious, and an
	// empty one would make the comparison below vacuous.
	if len(gotGo) < 8 {
		t.Fatalf("the Go side serialized only %d fields (%v) — too few for this "+
			"type, so the comparison would prove little", len(gotGo), gotGo)
	}

	if !reflect.DeepEqual(gotGo, gotHelper) {
		t.Errorf("the Go and helper spellings of IdleLeaseWire DISAGREE.\n"+
			"  go:     %v\n  helper: %v\n\n"+
			"These meet over the control socket in export_idle_leases / "+
			"import_idle_leases. A field named differently on one side decodes to "+
			"its zero value on the other — for this payload that is a "+
			"persistent-NAT binding that survives on one node and not the other, "+
			"which is exactly what #8121 exists to prevent.", gotGo, gotHelper)
	}
}
