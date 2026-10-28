package cluster

import (
	"reflect"
	"strings"
	"testing"
)

// #17107 acceptance: TestSyncStatsSnapshotComplete uses reflection to
// assert that every SyncStats field appears in SyncStatsSnapshot and
// that every snapshot field is either rendered by status.go or listed in
// a notRendered allowlist with a reason, so adding an atomic without a
// decision fails.
//
// #18141 fold legs: (1) the RenderNever set is pinned to the hardcoded
// 11-field derived set in the test — a SyncStats-derived counter flipped
// to RenderNever (even with an allowlist reason) fails; (2) descriptor
// get / loadSyncStat / setSyncStatUint are cross-checked against a
// fully-populated SyncStats with DISTINCT values per field, asserting
// snapshot field equality — a swapped mirror target fails; (3) the
// render leg exercises the real surface renderSyncStatRows17107 via the
// Manager renders (the production-dead renderSyncStats/fenceTimeStr
// renderers are deleted).
//
// FAIL-ON-REVERT: deleting the MalformedRecordsDropped snapshot field (or
// its syncStatFields descriptor) fails the SyncStats->snapshot leg;
// deleting its RenderNonzero decision fails the render leg; restoring
// FormatStats does not satisfy either leg.
func TestSyncStatsSnapshotComplete(t *testing.T) {
	statsType := reflect.TypeOf(SyncStats{})
	snapType := reflect.TypeOf(SyncStatsSnapshot{})

	snapFields := map[string]bool{}
	for i := range snapType.NumField() {
		snapFields[snapType.Field(i).Name] = true
	}
	descByName := map[string]syncStatField{}
	for _, f := range syncStatFields {
		if _, dup := descByName[f.name]; dup {
			t.Fatalf("duplicate syncStatFields descriptor for %q", f.name)
		}
		if f.get == nil {
			t.Fatalf("syncStatFields descriptor %q has nil get", f.name)
		}
		descByName[f.name] = f
	}

	// Every SyncStats atomic must appear in the snapshot AND have a
	// descriptor (the descriptor is what Stats() loads through).
	for i := range statsType.NumField() {
		name := statsType.Field(i).Name
		if !snapFields[name] {
			t.Errorf("SyncStats.%s has no SyncStatsSnapshot field — counted but unreachable (the #17107 MalformedRecordsDropped defect)", name)
		}
		if _, ok := descByName[name]; !ok {
			t.Errorf("SyncStats.%s has no syncStatFields descriptor — Stats() cannot load it and no render decision exists", name)
		}
	}

	// Every snapshot field must have exactly one decision: a descriptor,
	// and iff RenderNever an allowlist reason (non-empty, and no stale
	// allowlist entries).
	for i := range snapType.NumField() {
		name := snapType.Field(i).Name
		f, ok := descByName[name]
		if !ok {
			t.Errorf("SyncStatsSnapshot.%s has no syncStatFields descriptor — no render decision", name)
			continue
		}
		reason, listed := syncStatNotRendered[name]
		switch f.mode {
		case RenderNever:
			if !listed || strings.TrimSpace(reason) == "" {
				t.Errorf("SyncStatsSnapshot.%s is RenderNever but syncStatNotRendered has no reason for it", name)
			}
			if f.label != "" {
				t.Errorf("SyncStatsSnapshot.%s is RenderNever but carries label %q", name, f.label)
			}
		case RenderAlways, RenderNonzero:
			if listed {
				t.Errorf("SyncStatsSnapshot.%s is rendered (mode %v) but also listed in syncStatNotRendered", name, f.mode)
			}
			if strings.TrimSpace(f.label) == "" {
				t.Errorf("SyncStatsSnapshot.%s is rendered (mode %v) but has no label", name, f.mode)
			}
		default:
			t.Errorf("SyncStatsSnapshot.%s has unknown render mode %v", name, f.mode)
		}
	}
	for name, reason := range syncStatNotRendered {
		if !snapFields[name] {
			t.Errorf("syncStatNotRendered[%q] names no snapshot field (stale allowlist entry)", name)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("syncStatNotRendered[%q] has an empty reason", name)
		}
		if f, ok := descByName[name]; ok && f.mode != RenderNever {
			t.Errorf("syncStatNotRendered[%q] listed but descriptor mode is %v, not RenderNever", name, f.mode)
		}
	}
	// No descriptor may name a non-snapshot field.
	for name := range descByName {
		if !snapFields[name] {
			t.Errorf("syncStatFields descriptor %q names no SyncStatsSnapshot field", name)
		}
	}
	// (1) Allowlist-gaming guard (#18141 review): the RenderNever set must
	// be EXACTLY the 11 snapshot-only derived fields below. Any
	// SyncStats-DERIVED counter descriptor (its name names a SyncStats
	// field) flipped to RenderNever — with or without a matching
	// syncStatNotRendered reason — fails here, because the derived set is
	// hardcoded in this test rather than read back from the descriptors
	// or the allowlist it is auditing. Snapshot-only fields are the three
	// with no SyncStats source (PeerBootIncarnation, GenGuardSessionCap,
	// ActiveFabric); the other eight are SyncStats fields whose snapshot
	// type is not a counter (string/bool/int/int64 state, timestamps and
	// fence/bulk scalars rendered by their own status.go blocks).
	derivedNever17107 := map[string]bool{
		"PeerBootIncarnation": true, "GenGuardSessionCap": true,
		"Connected": true, "ActiveFabric": true,
		"BulkSyncStartTime": true, "BulkSyncEndTime": true,
		"BulkSyncSessions": true, "LastConfigSyncTime": true,
		"LastConfigSyncSize": true, "LastFenceSeq": true,
		"LastFenceAckAt": true,
	}
	if len(derivedNever17107) != 11 {
		t.Fatalf("derivedNever17107 has %d entries, want the hardcoded 11", len(derivedNever17107))
	}
	statsFieldNames := map[string]bool{}
	for i := range statsType.NumField() {
		statsFieldNames[statsType.Field(i).Name] = true
	}
	for _, f := range syncStatFields {
		if derivedNever17107[f.name] {
			if f.mode != RenderNever {
				t.Errorf("derived snapshot field %s is %v, want RenderNever (hardcoded derived set)", f.name, f.mode)
			}
			continue
		}
		if f.mode == RenderNever {
			t.Errorf("SyncStats-derived counter %s is RenderNever — only the 11 hardcoded derived fields may be RenderNever", f.name)
		}
		if f.mode != RenderAlways && f.mode != RenderNonzero {
			t.Errorf("SyncStats-derived counter %s has mode %v, want RenderAlways or RenderNonzero", f.name, f.mode)
		}
	}
	for name := range derivedNever17107 {
		if _, ok := descByName[name]; !ok {
			t.Errorf("hardcoded derived field %s has no syncStatFields descriptor", name)
		}
		if _, listed := syncStatNotRendered[name]; !listed {
			t.Errorf("hardcoded derived field %s missing from syncStatNotRendered", name)
		}
	}
	for name := range syncStatNotRendered {
		if !derivedNever17107[name] {
			t.Errorf("syncStatNotRendered[%q] is not in the hardcoded 11-field derived set — a counter must not be allowlist-gamed off the statistics render", name)
		}
	}
	// The derived set is exactly the snapshot-only fields plus the
	// SyncStats fields whose descriptor-get form is not the plain
	// counter: Connected (bool), the int64 timestamps, ActiveFabric
	// (int), and the three uint64 scalars rendered by their own
	// status.go blocks (BulkSyncSessions, LastConfigSyncSize,
	// LastFenceSeq) — each already pinned RenderNever above. What this
	// leg forbids is the converse: a field OUTSIDE the hardcoded set
	// claiming derived cover. That is checked by the mode loop above
	// (any non-derived RenderNever fails), so no type test is needed
	// here; the hardcoded set, not a type heuristic, is the pin.

	// (2) Hand-mirror cross-check (#18141 review): descriptor get,
	// loadSyncStat and setSyncStatUint are three unchecked mirrors keyed
	// by name. Populate EVERY SyncStats field (plus the derived-only
	// GenGuardSessionCap) with a DISTINCT value, run Stats(), and assert
	// each descriptor's get against the resulting snapshot field. A
	// swapped load or set target exchanges two fields' distinct values —
	// invisible to an all-ones snapshot — so the expected values below
	// are derived from the field NAME alone, never through a mirror.
	dss := &SessionSync{}
	wantDistinct17107 := setDistinctSyncStats17107(t, dss)
	dSnap := dss.Stats()
	dSnapVal := reflect.ValueOf(dSnap)
	for _, f := range syncStatFields {
		fv := dSnapVal.FieldByName(f.name)
		if !fv.IsValid() {
			t.Fatalf("snapshot has no field %q", f.name)
		}
		if fv.Kind() == reflect.String {
			// PeerBootIncarnation: string snapshot field, asserted
			// separately below; its descriptor get is defined as 0.
			if got := f.get(nil, &dSnap); got != 0 {
				t.Errorf("descriptor get(%s) = %d, want 0 for the string field", f.name, got)
			}
			continue
		}
		want, ok := wantDistinct17107[f.name]
		if !ok {
			t.Errorf("descriptor %s has no distinct-value expectation — extend setDistinctSyncStats17107", f.name)
			continue
		}
		// Snapshot-field equality in the field's own form: the direct
		// check on loadSyncStat + setSyncStatUint (a swapped target
		// puts another field's distinct value here).
		var snapGot uint64
		switch fv.Kind() {
		case reflect.Bool:
			if fv.Bool() {
				snapGot = 1
			}
		case reflect.Int, reflect.Int64:
			snapGot = uint64(fv.Int())
		default:
			snapGot = fv.Uint()
		}
		if f.name == "ActiveFabric" {
			// -1 (no conns) is the snapshot value; the descriptor get
			// form maps it to 0, checked just below.
			if fv.Int() != -1 {
				t.Errorf("Stats().ActiveFabric = %d, want -1 (no conns on a zero SessionSync)", fv.Int())
			}
		} else if snapGot != want {
			t.Errorf("Stats().%s = %d, want distinct %d (loadSyncStat/setSyncStatUint swapped?)", f.name, snapGot, want)
		}
		if got := f.get(nil, &dSnap); got != want {
			t.Errorf("descriptor get(%s) = %d, want distinct %d (descriptor get reads the wrong snapshot field?)", f.name, got, want)
		}
	}
	// Snapshot fields with no descriptor expectation are a completeness
	// hole in this cross-check itself.
	for i := range snapType.NumField() {
		name := snapType.Field(i).Name
		if name == "PeerBootIncarnation" {
			if dSnap.PeerBootIncarnation == "" || dSnap.PeerBootIncarnation == "none" {
				t.Errorf("Stats().PeerBootIncarnation = %q, want the distinct peer incarnation", dSnap.PeerBootIncarnation)
			}
			continue
		}
		if _, ok := wantDistinct17107[name]; !ok {
			t.Errorf("snapshot field %s has no distinct-value expectation", name)
		}
	}
	if dSnap.MalformedRecordsDropped != wantDistinct17107["MalformedRecordsDropped"] {
		t.Errorf("Stats().MalformedRecordsDropped = %d, want distinct %d", dSnap.MalformedRecordsDropped, wantDistinct17107["MalformedRecordsDropped"])
	}

	// Render leg: every RenderAlways/RenderNonzero descriptor must
	// actually render through the status.go statistics surfaces when its
	// counter is nonzero. A snapshot with every counter at 1 must render
	// every such label in both FormatStatistics and
	// FormatDataPlaneStatistics, and in FormatInformation (fabric block
	// for the nonzero set; always rows are the statistics tables' job,
	// so FormatInformation is checked only for RenderNonzero labels).
	// The real surface is renderSyncStatRows17107 (status.go), exercised
	// here through the Manager renders — never a test-only renderer.
	ss := &SessionSync{}
	setAllSyncStats17107(t, ss)
	snap := ss.Stats()
	// The snapshot must carry the values (Stats() descriptor loop).
	snapVal := reflect.ValueOf(snap)
	for _, f := range syncStatFields {
		if f.mode == RenderNever {
			continue
		}
		fv := snapVal.FieldByName(f.name)
		if !fv.IsValid() {
			t.Fatalf("snapshot has no field %q", f.name)
		}
		if fv.Kind() == reflect.Bool {
			if !fv.Bool() {
				t.Errorf("Stats().%s = false, want true (descriptor load dropped it)", f.name)
			}
		} else if fv.Uint() != 1 {
			t.Errorf("Stats().%s = %d, want 1 (descriptor load dropped it)", f.name, fv.Uint())
		}
	}
	// MalformedRecordsDropped is the regression cell: it must reach the
	// snapshot (pre-fix it had no snapshot field at all).
	if snap.MalformedRecordsDropped != 1 {
		t.Errorf("Stats().MalformedRecordsDropped = %d, want 1", snap.MalformedRecordsDropped)
	}

	m := NewManager(0, 1)
	m.SetSyncStats(ss)
	statistics := m.FormatStatistics()
	dataPlane := m.FormatDataPlaneStatistics()
	information := m.FormatInformation()
	// RenderAlways fields render as the Sent/Received service rows of the
	// statistics tables, not as literal descriptor labels; map each to
	// its table row so the leg still proves status.go renders it.
	alwaysTableRow := map[string]string{
		"SessionsSent": "Session create", "SessionsReceived": "Session create",
		"SweepSessionsSent": "of which mirror sweep",
		"SessionsInstalled": "Sessions installed",
		"DeletesSent":       "Session close", "DeletesReceived": "Session close",
		"BulkSyncs":   "Bulk syncs (sent)",
		"ConfigsSent": "Config", "ConfigsReceived": "Config",
		"IPsecSASent": "IPsec SA", "IPsecSAReceived": "IPsec SA",
		"DHCPLeasesSent": "DHCP leases", "DHCPLeasesReceived": "DHCP leases",
		"Errors": "Errors",
	}
	for _, f := range syncStatFields {
		if f.mode == RenderNever {
			continue
		}
		if f.mode == RenderAlways {
			row, ok := alwaysTableRow[f.name]
			if !ok {
				t.Errorf("RenderAlways field %s has no alwaysTableRow mapping in this test", f.name)
				continue
			}
			if !strings.Contains(statistics, row) {
				t.Errorf("FormatStatistics does not render %s (table row %q):\n%s", f.name, row, statistics)
			}
			if !strings.Contains(dataPlane, row) {
				t.Errorf("FormatDataPlaneStatistics does not render %s (table row %q):\n%s", f.name, row, dataPlane)
			}
			continue
		}
		if !strings.Contains(statistics, f.label) {
			t.Errorf("FormatStatistics does not render %q (%s):\n%s", f.label, f.name, statistics)
		}
		if !strings.Contains(dataPlane, f.label) {
			t.Errorf("FormatDataPlaneStatistics does not render %q (%s):\n%s", f.label, f.name, dataPlane)
		}
		if !strings.Contains(information, f.label+": 1") {
			t.Errorf("FormatInformation does not render %q (%s):\n%s", f.label, f.name, information)
		}
	}
	if !strings.Contains(statistics, "Malformed records dropped") {
		t.Errorf("'Malformed records dropped' must render on show chassis cluster statistics when nonzero:\n%s", statistics)
	}
}

// setAllSyncStats17107 sets every SyncStats counter to 1 (bools to true)
// via reflection so a newly added atomic is exercised without editing
// this helper — and fails the completeness legs above until it has a
// snapshot field and a descriptor.
func setAllSyncStats17107(t *testing.T, ss *SessionSync) {
	t.Helper()
	v := reflect.ValueOf(&ss.stats).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		// atomic.Uint64 / atomic.Int64 / atomic.Bool: set via their
		// Store methods through the addressable field.
		if m := f.Addr().MethodByName("Store"); m.IsValid() {
			typ := v.Type().Field(i).Type.String()
			switch {
			case strings.HasSuffix(typ, "atomic.Bool"):
				m.Call([]reflect.Value{reflect.ValueOf(true)})
			case strings.HasSuffix(typ, "atomic.Int64"):
				m.Call([]reflect.Value{reflect.ValueOf(int64(1))})
			default:
				m.Call([]reflect.Value{reflect.ValueOf(uint64(1))})
			}
			continue
		}
		t.Fatalf("SyncStats field %s is not an atomic with Store — extend setAllSyncStats17107", v.Type().Field(i).Name)
	}
	// Derived snapshot inputs that do not live in SyncStats.
	ss.SetGenGuardSessionCap(1)
}

// distinctPeerBoot17107 is the peer incarnation installed by
// setDistinctSyncStats17107; nonzero so PeerBootIncarnation renders as
// its hex string, not "none".
var distinctPeerBoot17107 = bootIncarnation{0x17, 0x10, 0x70}

// setDistinctSyncStats17107 stores a DISTINCT value in every SyncStats
// field (1000+fieldIndex in SyncStats declaration order, so the value
// identifies its field) plus the derived inputs (GenGuardSessionCap,
// peer boot incarnation), and returns the uint64 each snapshot field
// must then carry in descriptor-get form: bools as 1, ActiveFabric as 0
// (no conns on a zero SessionSync), int64 timestamps as stored. A newly
// added SyncStats field is covered automatically; a swapped mirror
// target is not — it fails the caller's equality.
func setDistinctSyncStats17107(t *testing.T, ss *SessionSync) map[string]uint64 {
	t.Helper()
	want := map[string]uint64{}
	v := reflect.ValueOf(&ss.stats).Elem()
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		f := v.Field(i)
		m := f.Addr().MethodByName("Store")
		if !m.IsValid() {
			t.Fatalf("SyncStats field %s is not an atomic with Store — extend setDistinctSyncStats17107", name)
		}
		typ := v.Type().Field(i).Type.String()
		switch {
		case strings.HasSuffix(typ, "atomic.Bool"):
			m.Call([]reflect.Value{reflect.ValueOf(true)})
			want[name] = 1
		case strings.HasSuffix(typ, "atomic.Int64"):
			val := int64(3000 + i)
			m.Call([]reflect.Value{reflect.ValueOf(val)})
			want[name] = uint64(val)
		default:
			val := uint64(1000 + i)
			m.Call([]reflect.Value{reflect.ValueOf(val)})
			want[name] = val
		}
	}
	ss.SetGenGuardSessionCap(777)
	want["GenGuardSessionCap"] = 777
	// ActiveFabric has no SyncStats source: a zero SessionSync has no
	// conns, so preferredFabricLocked reports -1 and the descriptor
	// getter maps that to 0.
	want["ActiveFabric"] = 0
	ss.mu.Lock()
	ss.peerBootIncarnation = distinctPeerBoot17107
	ss.mu.Unlock()
	return want
}
