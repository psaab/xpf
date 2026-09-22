package config

import (
	"strings"
	"testing"
)

func contestedCfg7509(t *testing.T, zones map[string][]string) *Config {
	t.Helper()
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{}
	for name, ifaces := range zones {
		cfg.Security.Zones[name] = &ZoneConfig{Interfaces: ifaces}
	}
	return cfg
}

func warningsMentioning(cfg *Config, sub string) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			out = append(out, w)
		}
	}
	return out
}

// TestContestedTrunkZoneAdvisoryFires7509 is the fail-on-revert cell: a base
// whose units span two zones must be reported AT COMMIT, naming the interface,
// both zones, and the consequence.
//
// The dataplane change makes this failure safe and explicit: transit is denied
// as unattributed before the implicit default policy (#6682), while host-bound
// traffic is denied by the contested-parent host-inbound sentinel (#10503).
func TestContestedTrunkZoneAdvisoryFires7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100"},
		"wan": {"ge-0/0/0.200"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{})

	got := warningsMentioning(cfg, "ge-0/0/0")
	if len(got) != 1 {
		t.Fatalf("expected exactly one advisory naming the contested base; got %d: %v",
			len(got), cfg.Warnings)
	}
	// The operator has to be able to act on it: which interface, which zones,
	// and what actually changes. A warning that says only "contested" sends
	// them back to source, which is the gap this exists to close.
	for _, want := range []string{
		"ge-0/0/0", "lan", "wan", "UNTAGGED", "unattributed", "DENIED",
		"host-inbound", "#6682", "#10503",
	} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("advisory must name %q so it is actionable; got: %s", want, got[0])
		}
	}
	if strings.Contains(got[0], "falls to the default policy") {
		t.Fatalf("advisory must not claim traffic falls to default policy; got: %s", got[0])
	}
}

// The control, and the one that decides whether the advisory is AIMED right: a
// trunk whose units are all in ONE zone is an ordinary, correct config and must
// stay silent. An advisory that fires on every trunk is noise, and noise is what
// makes an operator skip the one that matters.
func TestSingleZoneTrunkIsSilent7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100", "ge-0/0/0.200", "ge-0/0/0.300"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("a trunk whose units share one zone must produce NO advisory; got %v",
			cfg.Warnings)
	}
}

// Two DIFFERENT bases each in their own zone is not a contest either — the
// grouping must be per base, not global. Without this cell a bug that ignored
// the base key entirely would pass the two cells above.
func TestDistinctBasesAreNotAContest7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100"},
		"wan": {"ge-0/0/1.100"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("units on DIFFERENT bases are not a contest; got %v", cfg.Warnings)
	}
}

// The tolerant paths (Store.Load, Store.SyncApply) must stay silent, or the
// advisory fires on every boot and every peer sync of a config committed long
// ago — and an advisory seen on every boot is one an operator learns to skip.
func TestContestedTrunkZoneAdvisorySuppressedOnTolerantPath7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100"},
		"wan": {"ge-0/0/0.200"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{suppressContestedTrunkZoneAdvisory: true})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("the tolerant path must emit no advisory; got %v", cfg.Warnings)
	}
}

// #5878 canonicalisation, both directions.
//
// `ge-0/0/0.01` and `ge-0/0/0.1` are ONE unit, so naming that single unit in two
// zones is a DUPLICATE ZONE BINDING, not a trunk contest — there is only one
// unit on the base and it resolves to one zone. Reporting it here would send an
// operator to "split your units" for a problem that is nothing of the sort.
//
// But two DIFFERENT units must still be seen as different when their spellings
// differ, or the advisory misses a real contest whenever one side writes `.02`.
// Both halves are asserted, because a canonicaliser that collapsed too much
// would pass the first and fail the second, and one that collapsed too little
// would do the reverse.
func TestCanonicalUnitRefsAreOneUnit7509(t *testing.T) {
	same := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.1"},
		"wan": {"ge-0/0/0.01"},
	})
	appendContestedTrunkZoneAdvisoryLocked(same, compileOpts{})
	if len(same.Warnings) != 0 {
		t.Fatalf("one canonical unit named in two zones is a duplicate binding, not a "+
			"trunk contest; got %v", same.Warnings)
	}

	differ := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.1"},
		"wan": {"ge-0/0/0.02"},
	})
	appendContestedTrunkZoneAdvisoryLocked(differ, compileOpts{})
	if len(warningsMentioning(differ, "ge-0/0/0")) != 1 {
		t.Fatalf("units .1 and .02 are DIFFERENT units on one base in different zones — "+
			"a real contest the advisory must not miss because the spellings differ; got %v",
			differ.Warnings)
	}
}

// sharedDeviceCfg7509 builds a config with real interface UNITS (the contested
// helper above needs only zone refs; this half's predicate reads the units'
// vlan-id and the interface's tunnel stanza, so those have to exist).
func sharedDeviceCfg7509(t *testing.T, name string, tunnel bool, units map[int]int, zones map[string][]string) *Config {
	t.Helper()
	cfg := contestedCfg7509(t, zones)
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{}
	ifc := &InterfaceConfig{Name: name, Units: map[int]*InterfaceUnit{}}
	if tunnel {
		ifc.Tunnel = &TunnelConfig{}
	}
	for num, vlan := range units {
		ifc.Units[num] = &InterfaceUnit{Number: num, VlanID: vlan}
	}
	cfg.Interfaces.Interfaces[name] = ifc
	return cfg
}

// TestSharedDeviceUnzonedUnitAdvisoryFires7509 is the fail-on-revert cell for
// the zoned-vs-UNZONED half: unit 0 shares the trunk's kernel device and is in
// no zone while the tagged unit is zoned, so untagged traffic stops being
// adjudicated under the tagged unit's zone. The operator must learn that at
// commit, not from traffic dying.
func TestSharedDeviceUnzonedUnitAdvisoryFires7509(t *testing.T) {
	cfg := sharedDeviceCfg7509(t, "ge-0/0/0", false,
		map[int]int{0: 0, 100: 100},
		map[string][]string{"lan": {"ge-0/0/0.100"}})
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, compileOpts{})

	got := warningsMentioning(cfg, "ge-0/0/0.0")
	if len(got) != 1 {
		t.Fatalf("expected exactly one advisory naming the unzoned device-sharing "+
			"unit; got %d: %v", len(got), cfg.Warnings)
	}
	for _, want := range []string{
		"ge-0/0/0", "ge-0/0/0.0", "UNZONED", "unattributed", "DENIED",
		"host-inbound", "#6682", "#10503",
	} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("advisory must name %q so it is actionable; got: %s", want, got[0])
		}
	}
	if strings.Contains(got[0], "falls to the default policy") {
		t.Fatalf("advisory must not claim traffic falls to default policy; got: %s", got[0])
	}
}

// The reported #7509 shape itself: an interface-level tunnel whose unit 0 is
// unzoned and whose unit 1 is zoned. EVERY unit of such a tunnel collapses onto
// the tunnel device, so unit 0 is a device-sharing unit even though the
// non-VLAN-unit-0 rule is not what admits it here.
func TestSharedDeviceUnzonedTunnelUnitAdvisoryFires7509(t *testing.T) {
	cfg := sharedDeviceCfg7509(t, "gr-0/0/0", true,
		map[int]int{0: 0, 1: 0},
		map[string][]string{"vpnb": {"gr-0/0/0.1"}})
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, compileOpts{})

	if got := warningsMentioning(cfg, "gr-0/0/0.0"); len(got) != 1 {
		t.Fatalf("expected one advisory for the unzoned tunnel unit; got %d: %v",
			len(got), cfg.Warnings)
	}
}

// THE CONTROL THAT AIMS IT. A TAGGED unzoned unit has its OWN kernel device, is
// adjudicated per unit, and is completely unaffected by the #7509 refusal.
// Warning about it would describe a consequence that does not happen — and an
// advisory that fires on configs nothing happened to is the noise that makes an
// operator skip the one that matters.
func TestTaggedUnzonedUnitIsSilent7509(t *testing.T) {
	cfg := sharedDeviceCfg7509(t, "ge-0/0/0", false,
		map[int]int{0: 0, 100: 100, 200: 200},
		map[string][]string{"lan": {"ge-0/0/0.0", "ge-0/0/0.100"}})
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, compileOpts{})

	if len(cfg.Warnings) != 0 {
		t.Fatalf("unit 200 is TAGGED, so it has its own device and #7509 never "+
			"touches it: expected silence, got %v", cfg.Warnings)
	}
}

// The other control: every unit zoned is an ordinary config and must be silent.
// Paired with the fires-cell above, this is what shows the predicate keys on the
// UNZONED unit rather than on "the interface has more than one unit".
func TestFullyZonedInterfaceIsSilent7509(t *testing.T) {
	cfg := sharedDeviceCfg7509(t, "ge-0/0/0", false,
		map[int]int{0: 0, 100: 100},
		map[string][]string{"lan": {"ge-0/0/0"}}) // BARE ref fans DOWN to both units
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, compileOpts{})

	if len(cfg.Warnings) != 0 {
		t.Fatalf("a bare zone reference zones every unit, so nothing is refused: "+
			"expected silence, got %v", cfg.Warnings)
	}
}

// And the case with NO zoned unit at all: it remains outside every zone and
// therefore has no contested-parent advisory; its transit is handled by the
// unzoned-ingress path (#6682), and host-bound admission is not changed by
// #10503's contested-parent sentinel. It must stay silent too.
func TestWhollyUnzonedInterfaceIsSilent7509(t *testing.T) {
	cfg := sharedDeviceCfg7509(t, "ge-0/0/0", false,
		map[int]int{0: 0, 100: 100},
		map[string][]string{"lan": {"ge-0/0/1.0"}})
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, compileOpts{})

	if len(cfg.Warnings) != 0 {
		t.Fatalf("nothing on ge-0/0/0 is zoned, so #7509 changes nothing for it: "+
			"expected silence, got %v", cfg.Warnings)
	}
}

// Suppressed on the TOLERANT paths for the same reason as its sibling: Store.Load
// (persisted-config boot) and Store.SyncApply (HA peer sync) would otherwise
// replay it on every boot and every sync of a decision already made.
func TestSharedDeviceUnzonedUnitAdvisorySuppressedOnTolerantPath7509(t *testing.T) {
	cfg := sharedDeviceCfg7509(t, "ge-0/0/0", false,
		map[int]int{0: 0, 100: 100},
		map[string][]string{"lan": {"ge-0/0/0.100"}})
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, compileOpts{suppressContestedTrunkZoneAdvisory: true})

	if len(cfg.Warnings) != 0 {
		t.Fatalf("tolerant path must be silent; got %v", cfg.Warnings)
	}
}

// TestBothZoneAdvisoriesReachTheRealCompiler7509 binds the WIRING, not the
// functions the cells above call directly.
//
// Every other cell in this file invokes `append*AdvisoryLocked` itself, so all
// of them stay green if the call in `compiler.go` is deleted — and both
// advisories are reached from TWO sites there (CompileConfig and its sibling).
// This drives the real `CompileConfig` from real `set` lines and asserts the
// warning arrives in `cfg.Warnings`, which is the surface the gRPC commit
// response and the local CLI both read.
//
// MEASURED LIMITATION, recorded here because the cell would otherwise read as
// proof of something it does not show: on the loss userspace cluster the remote
// `cli` renders NEITHER advisory on `commit` or on `commit check`, and the
// already-merged #8402 advisory behaves identically — measured as a control on
// the same box, same session. So the gap is in the commit RESPONSE path, not in
// this wiring, and it is filed as #8484. The advisory that demonstrably
// reaches an operator today is the userspace-dp runtime warning
// (`forwarding_build/interfaces.rs`), which was observed in the journal on that
// same box for this same config.
func TestBothZoneAdvisoriesReachTheRealCompiler7509(t *testing.T) {
	compile := func(t *testing.T, lines []string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range lines {
			p, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}

	// #7509 half: an interface-level tunnel whose unit 1 is in no zone while
	// unit 0 is. Mirrors the config committed on the cluster during the smoke.
	shared := compile(t, []string{
		"set interfaces gr-0/0/0 tunnel source 10.1.1.1",
		"set interfaces gr-0/0/0 tunnel destination 10.1.1.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.255.193.42/30",
		"set security zones security-zone sfmix interfaces gr-0/0/0.0",
	})
	if got := warningsMentioning(shared, "gr-0/0/0.1"); len(got) != 1 {
		t.Fatalf("the #7509 advisory must survive the REAL compiler; got %d of %d "+
			"warnings: %v", len(got), len(shared.Warnings), shared.Warnings)
	}

	// #8402 half, in the same cell so one deleted call site cannot hide behind
	// the other: a trunk whose units span two zones.
	contested := compile(t, []string{
		"set interfaces ge-0/0/9 vlan-tagging",
		"set interfaces ge-0/0/9 unit 100 vlan-id 100 family inet address 10.100.9.1/24",
		"set interfaces ge-0/0/9 unit 200 vlan-id 200 family inet address 10.200.9.1/24",
		"set security zones security-zone lan interfaces ge-0/0/9.100",
		"set security zones security-zone dmz interfaces ge-0/0/9.200",
	})
	if got := warningsMentioning(contested, "more than one security zone"); len(got) != 1 {
		t.Fatalf("the #8402 advisory must survive the REAL compiler; got %d of %d "+
			"warnings: %v", len(got), len(contested.Warnings), contested.Warnings)
	}
}
