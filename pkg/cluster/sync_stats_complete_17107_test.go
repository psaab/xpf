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

	// Render leg: every RenderAlways/RenderNonzero descriptor must
	// actually render through the status.go statistics surfaces when its
	// counter is nonzero. A snapshot with every counter at 1 must render
	// every such label in both FormatStatistics and
	// FormatDataPlaneStatistics, and in FormatInformation (fabric block
	// for the nonzero set; always rows are the statistics tables' job,
	// so FormatInformation is checked only for RenderNonzero labels).
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
