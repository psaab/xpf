package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// #8615: the Go and Rust spellings of the DISPLAY-lease wire must AGREE, and
// the SYNC record must never grow the field that distinguishes them.
//
// Sibling of idle_lease_wire_agreement_8121_test.go, for the same reason and
// with the same discipline: assert the AGREEMENT, never pin one side to a
// literal, because a literal encodes which side is trusted and the failure
// being guarded is precisely that the two disagree.

func specimenFields(t *testing.T, name string) map[string]any {
	t.Helper()
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
	specimen, ok := fixture[name]
	if !ok {
		t.Fatalf("the wire fixture has no `%s` specimen. Without one the helper's "+
			"field spellings are unpinned and this cell asserts nothing — see "+
			"protocol/tests.rs.", name)
	}
	var out map[string]any
	if err := json.Unmarshal(specimen, &out); err != nil {
		t.Fatalf("parse %s specimen: %v", name, err)
	}
	return out
}

func fieldNames(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDisplayLeaseWireAgreesWithTheHelperSpelling8615(t *testing.T) {
	helperFields := specimenFields(t, "display_lease_wire")

	// Every field populated so nothing is elided by omitempty — the same reason
	// the Rust specimen is populated rather than a ::default().
	goJSON, err := json.Marshal(DisplayLeaseWire{
		Pool: "p1", Protocol: 6,
		SrcIP: "10.0.61.102", SrcPort: 40000,
		RoutingScope: userspaceLeaseScope(7),
		RemoteIP: "8.8.8.8", RemotePort: 443,
		TranslatedIP: "172.16.80.7", TranslatedPort: 51400,
		AddressOnly: true, RemainingNs: 123, TimeoutNs: 300_000_000_000,
		ActiveFlows: 4,
	})
	if err != nil {
		t.Fatalf("marshal Go DisplayLeaseWire: %v", err)
	}
	var goFields map[string]any
	if err := json.Unmarshal(goJSON, &goFields); err != nil {
		t.Fatalf("parse Go JSON: %v", err)
	}
	gotGo, gotHelper := fieldNames(goFields), fieldNames(helperFields)

	// POSITIVE CONTROL: an empty or tiny spelling set would make the comparison
	// below vacuous.
	if len(gotGo) < 9 {
		t.Fatalf("the Go side serialized only %d fields (%v) — too few for this "+
			"type, so the comparison would prove little", len(gotGo), gotGo)
	}
	if !reflect.DeepEqual(gotGo, gotHelper) {
		t.Errorf("the Go and helper spellings of DisplayLeaseWire DISAGREE.\n"+
			"  go:     %v\n  helper: %v\n\n"+
			"These meet over the control socket in "+
			"export_persistent_lease_display. A field named differently on one "+
			"side decodes to its zero value on the other; for active_flows that "+
			"silently turns every live binding into an idle one and reinstates "+
			"the #8615 defect while the table looks populated.", gotGo, gotHelper)
	}
}

// THE STRUCTURAL GUARD, and the reason the display record is a separate type.
//
// nat/idle_lease_sync_8121.rs's first design rule is "Never carry
// active_flows", because the standby installs a strict SUBSET of what the
// active sends: a carried count credits a lease for sessions that node does not
// hold, so it never reaches zero, never enters lease_expirations, and no GC
// path can reclaim it — a permanent leak of a translated identity.
//
// #8615 needs that count for DISPLAY. The rule is kept true by keeping the two
// records distinct, which is a structural claim and therefore testable: the
// record a peer can IMPORT must have no such field, on either side of the
// socket. If a later change "simplifies" the two types into one, this reds.
//
// Asserted behaviourally, on the serialized form, rather than by scanning the
// struct definition: the wire is what the import handler actually decodes, and
// a field renamed into the payload would defeat a source scan.
func TestTheSyncLeaseRecordStillCarriesNoFlowCount8615(t *testing.T) {
	goJSON, err := json.Marshal(IdleLeaseWire{
		RoutingScope: userspaceLeaseScope(7),
		Pool: "p1", Protocol: 6,
		SrcIP: "10.0.61.102", SrcPort: 40000,
		RemoteIP: "8.8.8.8", RemotePort: 443,
		TranslatedIP: "172.16.80.7", TranslatedPort: 51400,
		AddressOnly: true, RemainingNs: 123, TimeoutNs: 300_000_000_000,
	})
	if err != nil {
		t.Fatalf("marshal IdleLeaseWire: %v", err)
	}
	var idle map[string]any
	if err := json.Unmarshal(goJSON, &idle); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// POSITIVE CONTROL. An absence claim needs proof the probe can see a
	// present field: the DISPLAY record does carry active_flows, through the
	// identical marshal-and-look path. If this control ever stops finding it,
	// the absence assertion below is measuring a broken probe, not a property.
	display := specimenFields(t, "display_lease_wire")
	if _, ok := display["active_flows"]; !ok {
		t.Fatalf("CONTROL FAILED: the display specimen has no `active_flows` key, " +
			"so the absence check below proves nothing about IdleLeaseWire")
	}

	for _, banned := range []string{"active_flows", "activeFlows", "flows", "flow_count"} {
		if _, ok := idle[banned]; ok {
			t.Errorf("the SYNC lease record now carries %q. That is the one field "+
				"nat/idle_lease_sync_8121.rs's first design rule forbids: the "+
				"standby installs a strict subset, so a carried count credits the "+
				"lease for sessions this node does not hold, it never reaches "+
				"zero, never enters lease_expirations, and no GC path can reclaim "+
				"it. #8615 needed this count for DISPLAY and got a SEPARATE record "+
				"(DisplayLeaseWire) precisely so this one would keep not having "+
				"it.", banned)
		}
	}

	// And the helper's spelling of the same record, so the guard covers the
	// side that actually deserialises an import.
	helperIdle := specimenFields(t, "idle_lease_wire")
	if _, ok := helperIdle["active_flows"]; ok {
		t.Error("the HELPER's idle_lease_wire specimen now carries `active_flows` — " +
			"the import path can receive a flow count. See above.")
	}
}
