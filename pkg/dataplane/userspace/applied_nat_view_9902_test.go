package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// poisonedRow9902 is a #9874-poisoned rule's status row: the rule keeps its
// pool_mode but builds no allocator, so the row reports MaxTrackedFlows == 0
// (the signal is the zero CAP — a default allocator still mints a nonzero
// allocator_id, so "zeros" would be the wrong word for the row).
func poisonedRow9902(rule string) SourceNATPoolStatus {
	return SourceNATPoolStatus{RuleName: rule, PoolName: "p1"}
}

// constructedRow9902 is a live allocator's row. allocations is a parameter
// (not always >0) because an HA import reserves bitmap + live records WITHOUT
// bumping allocations_total — an import-only allocator ties a poisoned
// default at 0, which is why selection keys off MaxTrackedFlows instead.
func constructedRow9902(rule string, allocations uint64) SourceNATPoolStatus {
	return SourceNATPoolStatus{
		RuleName: "r-" + rule, PoolName: "p1",
		AddressCount: 1, PortLow: 1, PortHigh: 100,
		UsedPorts: 50, MaxTrackedFlows: 90,
		LiveFlows: 43, PersistentLeases: 13,
		AllocationsTotal: allocations,
		ExhaustionTotal:  3, AllocatorID: 9,
	}
}

func viewFor9902(t *testing.T, rows []SourceNATPoolStatus) AppliedNATView {
	t.Helper()
	m := New()
	m.proc = selfProc(t)
	cfg := &config.Config{}
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 3}
	m.markAppliedSnapshotLocked()
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 3, SourceNATPools: rows}
	return m.AppliedNATView()
}

// The constructed row must win over a poisoned default in BOTH orders —
// first-wins takes the poisoned row whenever it sorts first (C4), zeroing
// UsedPorts AND ExhaustionTotal for a live pool.
func TestAppliedNATViewSelectsConstructed9902(t *testing.T) {
	healthy := constructedRow9902("good", 5)
	poisoned := poisonedRow9902("bad")
	for _, tc := range []struct {
		name string
		rows []SourceNATPoolStatus
	}{
		{"poisoned-first", []SourceNATPoolStatus{poisoned, healthy}},
		{"healthy-first", []SourceNATPoolStatus{healthy, poisoned}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := viewFor9902(t, tc.rows)
			if len(v.Pools) != 1 {
				t.Fatalf("expected 1 deduped pool, got %d", len(v.Pools))
			}
			p := v.Pools["p1"]
			if p.UsedPorts != 50 || p.ExhaustionTotal != 3 || p.AllocatorID != 9 {
				t.Fatalf("constructed row must win, got %+v", p)
			}
			if p.LiveFlows != 43 || p.MaxTrackedFlows != 90 || p.PersistentLeases != 13 {
				t.Fatalf("constructed row's flow leg must project, got %+v", p)
			}
		})
	}
}

// The import-only allocator (MaxTrackedFlows>0, AllocationsTotal==0) must
// STILL beat a poisoned default in both orders. max-AllocationsTotal
// selection ties them at 0 and can take the poisoned row — this cell is
// what kills that selector.
func TestAppliedNATViewImportOnlyBeatsPoisoned9902(t *testing.T) {
	imported := constructedRow9902("imported", 0)
	poisoned := poisonedRow9902("bad")
	for _, tc := range []struct {
		name string
		rows []SourceNATPoolStatus
	}{
		{"poisoned-first", []SourceNATPoolStatus{poisoned, imported}},
		{"healthy-first", []SourceNATPoolStatus{imported, poisoned}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := viewFor9902(t, tc.rows)
			p := v.Pools["p1"]
			if p.UsedPorts != 50 || p.ExhaustionTotal != 3 || p.AllocatorID != 9 {
				t.Fatalf("import-only row must win, got %+v", p)
			}
			if p.LiveFlows != 43 || p.MaxTrackedFlows != 90 || p.PersistentLeases != 13 {
				t.Fatalf("import-only row's flow leg must project, got %+v", p)
			}
		})
	}
}

// Identical constructed rows dedup to one entry with intact counters (never
// summed: two rows of 50 must read 50, not 100).
func TestAppliedNATViewIdenticalRowsDedup9902(t *testing.T) {
	a := constructedRow9902("a", 5)
	b := constructedRow9902("b", 5)
	v := viewFor9902(t, []SourceNATPoolStatus{a, b})
	if len(v.Pools) != 1 {
		t.Fatalf("expected 1 deduped pool, got %d", len(v.Pools))
	}
	if p := v.Pools["p1"]; p.UsedPorts != 50 || p.ExhaustionTotal != 3 {
		t.Fatalf("deduped row must keep one value, got %+v", p)
	} else if p.LiveFlows != 43 || p.MaxTrackedFlows != 90 || p.PersistentLeases != 13 {
		t.Fatalf("deduped row's flow leg must keep one value, got %+v", p)
	}
}

// The view carries the exhaustion identity end to end: the SELECTED row's
// ExhaustionTotal+AllocatorID (poisoned-first ordering, so a first-wins
// projection would read zeros) plus the manager's freshness tokens.
func TestAppliedNATViewCarriesExhaustionIdentity9902(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	cfg := &config.Config{}
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 3}
	m.markAppliedSnapshotLocked()
	m.procGen = 41
	m.setLastStatusLocked(ProcessStatus{
		LastSnapshotGeneration: 3,
		SourceNATPools: []SourceNATPoolStatus{
			poisonedRow9902("bad"),
			constructedRow9902("good", 5),
		},
	})
	v := m.AppliedNATView()
	if v.StatusSequence != 1 {
		t.Fatalf("StatusSequence = %d, want 1 (one publication)", v.StatusSequence)
	}
	if v.ProcGen != 41 {
		t.Fatalf("ProcGen = %d, want 41", v.ProcGen)
	}
	p := v.Pools["p1"]
	if p.ExhaustionTotal != 3 || p.AllocatorID != 9 {
		t.Fatalf("selected row's identity must project, got %+v", p)
	}
	if p.LiveFlows != 43 || p.MaxTrackedFlows != 90 || p.PersistentLeases != 13 {
		t.Fatalf("selected row's flow leg must project, got %+v", p)
	}
}

// Go/Rust wire-key lockstep for allocator_id, following the #9392 pattern:
// the Rust key is read out of the serde rename, the Go key out of the struct
// tag, and the test asserts they agree AND that the key reaches the field.
// A mismatch reads 0 forever — and 0 is also "legacy helper", so the signal
// would be silently absent.
func TestAllocatorIDWireKeysLockstepWithRust9902(t *testing.T) {
	rustKey := rustSourceNATPoolRename9392(t, "allocator_id")
	field, ok := reflect.TypeOf(SourceNATPoolStatus{}).FieldByName("AllocatorID")
	if !ok {
		t.Fatal("SourceNATPoolStatus has no field AllocatorID — the guard cannot run")
	}
	goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if goKey != rustKey {
		t.Fatalf("wire-key drift: Go decodes %q, Rust emits %q (#9902 F-026)", goKey, rustKey)
	}

	var pool SourceNATPoolStatus
	payload := []byte(`{"` + rustKey + `":99,"exhaustion_total":7}`)
	if err := json.Unmarshal(payload, &pool); err != nil {
		t.Fatalf("unmarshal %s: %v", payload, err)
	}
	if pool.AllocatorID != 99 {
		t.Fatalf("AllocatorID = %d after decoding %s, want 99", pool.AllocatorID, payload)
	}
	if pool.ExhaustionTotal != 7 {
		t.Fatalf("ExhaustionTotal = %d after decoding %s, want 7", pool.ExhaustionTotal, payload)
	}

	// Byte-level leg: allocator_id has no skip_serializing_if, so the
	// committed default specimen carries the key.
	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}
	if !strings.Contains(string(raw), `"`+rustKey+`"`) {
		t.Fatalf("%s does not contain the key %q — regenerate the fixture", fixture, rustKey)
	}
}

// Go/Rust wire-key lockstep for the #9896 flow-cap pair, extending the
// allocator_id lockstep above to live_flows/max_tracked_flows
// (protocol/nat.rs:428-435 <-> protocol_counters.go:17,20). Same failure
// being guarded: both fields are additive (`default` on the Rust side,
// `omitempty` on the Go side), so a key mismatch never fails a decode — it
// reads 0 forever. A drifted max reads as "helper predating the counters"
// and silently kills the flow leg; a drifted live reads as an idle pool and
// holds every flow alarm at 0%.
func TestFlowCapWireKeysLockstepWithRust9896(t *testing.T) {
	for _, tc := range []struct {
		rustField string
		goField   string
		want      uint64
	}{
		{"live_flows", "LiveFlows", 43},
		{"max_tracked_flows", "MaxTrackedFlows", 90},
	} {
		rustKey := rustSourceNATPoolRename9392(t, tc.rustField)
		field, ok := reflect.TypeOf(SourceNATPoolStatus{}).FieldByName(tc.goField)
		if !ok {
			t.Fatalf("SourceNATPoolStatus has no field %s — the guard cannot run", tc.goField)
		}
		goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if goKey != rustKey {
			t.Fatalf("wire-key drift: Go decodes %q, Rust emits %q (#9896 %s)", goKey, rustKey, tc.goField)
		}

		var pool SourceNATPoolStatus
		payload := []byte(`{"` + rustKey + `":` + itoa9392(tc.want) + `}`)
		if err := json.Unmarshal(payload, &pool); err != nil {
			t.Fatalf("unmarshal %s: %v", payload, err)
		}
		got := reflect.ValueOf(pool).FieldByName(tc.goField).Uint()
		if got != tc.want {
			t.Fatalf("%s = %d after decoding %s, want %d", tc.goField, got, payload, tc.want)
		}

		// Byte-level leg: neither key has skip_serializing_if, so the
		// committed default specimen carries both.
		fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read %s: %v", fixture, err)
		}
		if !strings.Contains(string(raw), `"`+rustKey+`"`) {
			t.Fatalf("%s does not contain the key %q — regenerate the fixture", fixture, rustKey)
		}
	}
}

// A successful status publication replaces the cache AND bumps the sequence,
// once per publication.
func TestLastStatusSeqBumpsOnPublish9902(t *testing.T) {
	m, _ := seamedManager(t)
	st := readyHelperStatus()
	st.LastSnapshotGeneration = 11
	if err := m.applyHelperStatusLocked(st); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if m.lastStatusSeq != 1 {
		t.Fatalf("lastStatusSeq = %d after one publish, want 1", m.lastStatusSeq)
	}
	if m.lastStatus.LastSnapshotGeneration != 11 {
		t.Fatalf("cache not replaced: %+v", m.lastStatus)
	}
	if err := m.applyHelperStatusLocked(st); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if m.lastStatusSeq != 2 {
		t.Fatalf("lastStatusSeq = %d after two publishes, want 2", m.lastStatusSeq)
	}
}

// A FAILED apply (map-free manager: transport ok, maps absent) leaves the
// cache AND the sequence untouched — the monitor must keep evaluating the
// previous sample, not re-read it as fresh.
func TestLastStatusSeqFrozenOnFailedApply9902(t *testing.T) {
	m := New() // no map hooks: helperStatusMapsLocked finds nothing
	st := readyHelperStatus()
	st.LastSnapshotGeneration = 11
	if err := m.applyHelperStatusLocked(st); err == nil {
		t.Fatal("map-free apply must fail (fixture cannot reach the cell otherwise)")
	}
	if m.lastStatusSeq != 0 {
		t.Fatalf("failed apply bumped lastStatusSeq to %d", m.lastStatusSeq)
	}
	if m.lastStatus.LastSnapshotGeneration != 0 {
		t.Fatalf("failed apply replaced the cache: %+v", m.lastStatus)
	}
}

// Clears need no bump: gen-0 ⇒ incoherent ⇒ the monitor HOLDs anyway.
func TestLastStatusSeqUntouchedByClear9902(t *testing.T) {
	m := New()
	m.setLastStatusLocked(ProcessStatus{LastSnapshotGeneration: 11})
	if m.lastStatusSeq != 1 {
		t.Fatalf("lastStatusSeq = %d, want 1", m.lastStatusSeq)
	}
	m.clearLastStatusLocked()
	if m.lastStatusSeq != 1 {
		t.Fatalf("clear changed lastStatusSeq to %d", m.lastStatusSeq)
	}
}
