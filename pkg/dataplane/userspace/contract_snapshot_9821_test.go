package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// contractFixture9821 is the issue probe as set lines: a declared dotted
// interface with an untagged unit-0 (collapsing onto the base device — the
// same-ifindex pair) and a vlan child, used verbatim as an RI member, plus
// an undotted control interface. The zone members the dotted unit (lenient:
// DEFINED first-dots) and the undotted control (strict-clean).
func contractFixture9821() []string {
	return []string{
		"set interfaces ge-0/0/5.0 vlan-tagging",
		"set interfaces ge-0/0/5.0 unit 0 family inet address 10.55.0.1/24",
		// NOTE: `vlan-id` and the address live on SEPARATE set lines — the
		// combined single-line form silently drops the address at parse
		// level even undotted (observed, pre-existing, out of cohort scope;
		// the 6722 fixtures use combined lines but never assert addresses).
		"set interfaces ge-0/0/5.0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/5.0 unit 100 family inet address 10.55.100.1/24",
		"set interfaces ge-0/0/6 unit 0 family inet address 10.56.0.1/24",
		"set routing-instances RA interface ge-0/0/5.0",
		"set routing-instances RA interface ge-0/0/6.0",
		"set security zones security-zone trust interfaces ge-0/0/5.0.0",
		"set security zones security-zone trust interfaces ge-0/0/6.0",
	}
}

// buildContractSnapshot9821 compiles the fixture with stubbed links and
// builds the publishable snapshot, normalizing the volatile fields
// (build time) so the golden is byte-stable. Capabilities/pins/IDs are
// config-derived and stable; SecureTunnel is false throughout (no xfrm
// links can alias these fixture devices).
func buildContractSnapshot9821(t *testing.T) *ConfigSnapshot {
	t.Helper()
	cfg := compileWithStubbedLinks6722(t, contractFixture9821(), map[string]int{
		"ge-0-0-5.0":     90,
		"ge-0-0-5.0.100": 91,
		"ge-0-0-6":       92,
	}, map[string]string{
		"ge-0-0-5.0":     "02:00:00:00:00:90",
		"ge-0-0-5.0.100": "02:00:00:00:00:91",
		"ge-0-0-6":       "02:00:00:00:00:92",
	}, true)
	ucfg := deriveUserspaceConfig(cfg)
	snap, err := buildSnapshot(cfg, ucfg, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	snap.GeneratedAt = time.Unix(0, 0).UTC()
	return snap
}

// TestContractSnapshotGolden9821 is the cell-13 Go producer half: the
// contract fixture builds, marshals, and byte-matches the golden the Rust
// consumer half reads. Regen with UPDATE_GOLDEN=1 — and REVIEW the diff:
// every row must match the #9821 spec (declared-first attribution,
// structural identity, pair-atomic merge inputs), never just "what the
// builder emits today".
func TestContractSnapshotGolden9821(t *testing.T) {
	snap := buildContractSnapshot9821(t)
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "contract-9821-declared-snapshot.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("regenerated %s (%d bytes) — REVIEW the diff", path, len(raw))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regen once with UPDATE_GOLDEN=1, then review)", path, err)
	}
	if string(raw) != string(want) {
		t.Fatalf("contract snapshot drifted from the golden (%d vs %d bytes). "+
			"Diff testdata/contract-9821-declared-snapshot.json against actual output: "+
			"an intended wire change re-regens with UPDATE_GOLDEN=1 (Rust consumer must "+
			"still pass); anything else is a regression in declared-first attribution, "+
			"structural identity, or merge inputs.", len(raw), len(want))
	}
}

// TestRowIdentityWireKeyLockstepWithRust9821 asserts the Go emitter and the
// Rust consumer AGREE on the wire spelling of the #22 is_unit field —
// mirroring the 7037 egress-zone guard (same helpers, same rationale: serde
// `default` makes a skew silent, so reflection on both sides binds it).
func TestRowIdentityWireKeyLockstepWithRust9821(t *testing.T) {
	goKey := jsonKeyOf(t, reflect.TypeOf(InterfaceSnapshot{}), "IsUnit")

	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the is_unit wire-key lockstep guard cannot run)", path, err)
	}
	body := rustStructBody(t, string(src), "InterfaceSnapshot")
	rustKey := rustSerdeRenameOf(t, body, "is_unit")

	if goKey != rustKey {
		t.Fatalf("is_unit wire key skew: Go emits %q, Rust reads %q. Rename BOTH sides or neither.", goKey, rustKey)
	}
}

// TestFabricBondWireKeyLockstep9925 pins the additive field's Go/Rust wire
// spelling. A serde default keeps old snapshots readable, so a key mismatch
// would otherwise silently turn the admission bit off on one side.
func TestFabricBondWireKeyLockstep9925(t *testing.T) {
	goKey := jsonKeyOf(t, reflect.TypeOf(InterfaceSnapshot{}), "FabricBond")
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the fabric-bond wire-key guard cannot run)", path, err)
	}
	rustKey := rustSerdeRenameOf(t, rustStructBody(t, string(src), "InterfaceSnapshot"), "fabric_bond")
	if goKey != rustKey {
		t.Fatalf("fabric_bond wire key skew: Go emits %q, Rust reads %q", goKey, rustKey)
	}
}

// TestContractSnapshotGoldenPins9821 asserts the load-bearing rows of the
// golden INDEPENDENTLY of the byte-compare, so a blind regen cannot launder
// a regression: the same-ifindex pair carries the instance on the
// address-carrying unit row with structural identity, and the control is
// unchanged.
func TestContractSnapshotGoldenPins9821(t *testing.T) {
	snap := buildContractSnapshot9821(t)
	byName := map[string]InterfaceSnapshot{}
	for _, r := range snap.Interfaces {
		byName[r.Name] = r
	}
	// The same-ifindex pair: base + collapsed unit-0 share device 90.
	base, ok := byName["ge-0/0/5.0"]
	if !ok {
		t.Fatal("golden lacks the ge-0/0/5.0 base row")
	}
	unit0, ok := byName["ge-0/0/5.0.0"]
	if !ok {
		t.Fatal("golden lacks the ge-0/0/5.0.0 unit row")
	}
	if base.Ifindex != 90 || unit0.Ifindex != 90 {
		t.Fatalf("pair ifindexes = (%d,%d), want both 90 (unit-0 collapse)", base.Ifindex, unit0.Ifindex)
	}
	if base.RoutingInstance != "RA" || base.RoutingDomain != unit0.RoutingDomain {
		t.Errorf("base row instance = (%q,%d), unit row = (%q,%d) — one consistent instance across the pair",
			base.RoutingInstance, base.RoutingDomain, unit0.RoutingInstance, unit0.RoutingDomain)
	}
	if unit0.RoutingInstance != "RA" || unit0.RoutingDomain == 0 {
		t.Errorf("unit row instance = (%q,%d) — want the address-carrying row attributed to RA",
			unit0.RoutingInstance, unit0.RoutingDomain)
	}
	if base.IsUnit || !unit0.IsUnit {
		t.Errorf("structural identity = (base %v, unit %v) — want (false, true)", base.IsUnit, unit0.IsUnit)
	}
	vlan, ok := byName["ge-0/0/5.0.100"]
	if !ok {
		t.Fatal("golden lacks the ge-0/0/5.0.100 vlan row")
	}
	if vlan.Ifindex != 91 || !vlan.IsUnit || vlan.RoutingInstance != "RA" {
		t.Errorf("vlan row = (ifindex %d, isUnit %v, ri %q) — want (91, true, RA)",
			vlan.Ifindex, vlan.IsUnit, vlan.RoutingInstance)
	}
	// Undotted control: unchanged shape.
	cbase, ok := byName["ge-0/0/6"]
	if !ok || cbase.IsUnit || cbase.Ifindex != 92 {
		t.Errorf("control base row = %+v — want IsUnit=false on ifindex 92", cbase)
	}
	cunit, ok := byName["ge-0/0/6.0"]
	if !ok || !cunit.IsUnit || cunit.Ifindex != 92 || cunit.RoutingInstance != "RA" {
		t.Errorf("control unit row = %+v — want IsUnit=true on ifindex 92 in RA", cunit)
	}
}
