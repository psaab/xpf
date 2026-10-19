package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6751 §5.7 (PR 3a): interface-mode SNAT egress addresses are an occupancy
// domain, and a DISJOINT one from the source-pool / NAT64 allocators. A pool
// containing an egress interface address lets two independently-keyed
// allocators mint the same translated (address, port) tuple, which the reverse
// NAT index cannot disambiguate — the same reply-misdelivery #5144 rejects for
// pool-vs-pool, on the arm #5144 never covered.
//
// These cells cover the CONFIG-time half. The runtime half (addresses resolved
// from the kernel, DHCP) is PR 3b and needs the DRAIN discipline behind it.

// ifaceEgressCfg builds a config with one interface-mode SNAT rule-set at the
// given to-side scope, one interface in zone `wan` carrying addr, and a source
// pool holding poolAddr.
func ifaceEgressCfg(toZone, toIface, toRI, addr, poolAddr string) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/3": {Units: map[int]*InterfaceUnit{
			50: {Addresses: []string{addr}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/3.50"}},
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "vrf-a", Interfaces: []string{"ge-0/0/3.50"}},
	}
	cfg.Security.NAT.SourcePools = map[string]*NATPool{
		"p": {Name: "p", Address: poolAddr},
	}
	cfg.Security.NAT.Source = []*NATRuleSet{
		{
			Name: "iface-rs", FromZone: "trust",
			ToZone: toZone, ToInterface: toIface, ToRoutingInstance: toRI,
			Rules: []*NATRule{{Name: "r", Then: NATThen{Interface: true}}},
		},
		// A pool-mode rule-set so the pool is a live allocator owner; without a
		// referencing rule the pool mints nothing and is not an owner at all,
		// which would make every cell below vacuous.
		{
			Name: "pool-rs", FromZone: "trust", ToZone: "wan",
			Rules: []*NATRule{{Name: "r", Then: NATThen{PoolName: "p"}}},
		},
	}
	return cfg
}

func overlapsIfaceEgress(t *testing.T, cfg *Config) bool {
	t.Helper()
	_, err := validateNATPoolExternalTupleOverlapStrict(cfg, false)
	return err != nil && strings.Contains(err.Error(), "interface-mode source-NAT")
}

// TestInterfaceEgressJoinsStrictOwnerSet_6751 is the core cell for every scope
// shape in the derivation matrix.
//
// The unscoped row is the one that matters most and the one the previous Go
// precedent got wrong: `maps_sync.go` collected only non-empty `ToZone` and
// returned NOTHING for an unscoped rule-set. An unscoped interface-mode rule
// matches every egress, so returning the empty set understates the candidate
// set exactly where it is widest — failing OPEN on the broadest input.
//
// FAIL-ON-REVERT: delete the interface-egress owner append in
// validateNATPoolExternalTupleOverlapStrict and every row REDS.
func TestInterfaceEgressJoinsStrictOwnerSet_6751(t *testing.T) {
	const ifAddr = "172.16.50.5/24"
	const collide = "172.16.50.5/32"
	const disjoint = "172.16.60.5/32"

	for _, tc := range []struct {
		name                  string
		toZone, toIface, toRI string
		pool                  string
		wantOverlap           bool
	}{
		{"to-zone matches", "wan", "", "", collide, true},
		{"to-interface matches", "", "ge-0/0/3.50", "", collide, true},
		{"to-routing-instance matches", "", "", "vrf-a", collide, true},
		{"unscoped is a WILDCARD, not empty", "", "", "", collide, true},

		// Negative rows: a scope that does NOT select the interface must not
		// contribute its address. Without these, "every interface is always a
		// candidate" passes all four positive rows while false-rejecting
		// correct configs.
		{"to-zone elsewhere", "dmz", "", "", collide, false},
		{"to-interface elsewhere", "", "ge-0/0/9.0", "", collide, false},
		{"to-routing-instance elsewhere", "", "", "vrf-z", collide, false},

		// Control: the right scope but a pool that does not overlap must stay
		// clean, or the cell is just asserting "interface-mode rejects".
		{"matching scope, disjoint pool", "wan", "", "", disjoint, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ifaceEgressCfg(tc.toZone, tc.toIface, tc.toRI, ifAddr, tc.pool)
			got := overlapsIfaceEgress(t, cfg)
			if got != tc.wantOverlap {
				t.Fatalf("overlap reported = %v, want %v. Scope(zone=%q iface=%q ri=%q) "+
					"pool=%s vs interface address %s (#6751 §5.7)",
					got, tc.wantOverlap, tc.toZone, tc.toIface, tc.toRI, tc.pool, ifAddr)
			}
		})
	}
}

// TestInterfaceEgressOwnersDedupeByAddress_6751 pins the dedup that keeps the
// gate from false-rejecting a correct multi-rule config.
//
// Several interface-mode rule-sets all egressing one WAN interface name the
// SAME address. One owner per RULE would make those rule-sets overlap each
// OTHER — every real multi-zone config would stop committing. The occupancy is
// a property of the ADDRESS, so the address is the owner identity.
//
// FAIL-ON-REVERT: key the interface owners per rule-set instead of per address
// and this REDS with the rule-sets colliding with one another.
func TestInterfaceEgressOwnersDedupeByAddress_6751(t *testing.T) {
	cfg := ifaceEgressCfg("wan", "", "", "172.16.50.5/24", "172.16.60.5/32")
	// Three more interface-mode rule-sets, all egressing the same interface.
	for _, name := range []string{"iface-rs-b", "iface-rs-c", "iface-rs-d"} {
		cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &NATRuleSet{
			Name: name, FromZone: "trust", ToZone: "wan",
			Rules: []*NATRule{{Name: "r", Then: NATThen{Interface: true}}},
		})
	}
	if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, false); err != nil {
		t.Fatalf("four interface-mode rule-sets sharing one egress address were reported "+
			"as overlapping: %v. They occupy ONE address, not four — owners must dedupe "+
			"by address or every real multi-zone config stops committing (#6751 §5.7)", err)
	}
}

// TestDisabledInterfaceRuleIsNotAnEgressOwner_6751: `then source-nat off` mints
// no translation, so it must contribute no occupancy. Otherwise a disabled rule
// would quarantine an address the dataplane never translates onto.
func TestDisabledInterfaceRuleIsNotAnEgressOwner_6751(t *testing.T) {
	cfg := ifaceEgressCfg("wan", "", "", "172.16.50.5/24", "172.16.50.5/32")
	cfg.Security.NAT.Source[0].Rules[0].Then = NATThen{Interface: true, Off: true}
	if overlapsIfaceEgress(t, cfg) {
		t.Fatal("a DISABLED interface-mode rule contributed an egress owner; it mints no " +
			"translation, so it occupies nothing (#6751 §5.7)")
	}
}

// shippedNATConfigs are repository config files that carry BOTH a source-NAT
// stanza and are deployed or presented as reference wiring.
//
// docs/ha-cluster-userspace.conf is the loss-cluster smoke substrate;
// test/incus/xpf-cluster-fw{0,1}.conf drive the legacy regression cluster;
// xpf-test.conf is the standalone test VM's config.
var shippedNATConfigs = []string{
	"../../docs/ha-cluster.conf",
	"../../docs/ha-cluster-loss.conf",
	"../../docs/ha-cluster-userspace.conf",
	"../../test/incus/xpf-cluster-fw0.conf",
	"../../test/incus/xpf-cluster-fw1.conf",
	"../../test/incus/xpf-test.conf",
	"../../test/incus/xpf-vlan-test.conf",
	"../../test/incus/xpf-internet-test.conf",
}

// TestShippedConfigsHaveNoCrossDomainNATOverlap_6751 points the gate at the
// configs we actually ship.
//
// This cell exists because of what happened while building the gate: it caught
// `xpf-cluster-fw0.conf` immediately (nat64-pool sitting on reth0.50's own
// address) — but `xpf-test.conf` carried the IDENTICAL defect one address over
// and was NOT caught, purely because no test in this package ever compiled that
// file. `go test ./pkg/config/` was green while a shipped config violated the
// rule the package had just added.
//
// That is the failure mode where a check reports a value indistinguishable from
// healthy: the gate existed, the suite passed, and nothing pointed one at the
// other. A validator's reach is not what it can detect, it is what it is
// actually run against.
//
// FAIL-ON-REVERT: move either nat64-pool back onto its interface's own address
// and this REDS naming that file.
func TestShippedConfigsHaveNoCrossDomainNATOverlap_6751(t *testing.T) {
	checked := 0
	for _, rel := range shippedNATConfigs {
		raw, err := os.ReadFile(rel)
		if err != nil {
			// A config that has been renamed away is not a silent pass: name it.
			t.Errorf("read %s: %v (if this file moved, update shippedNATConfigs — a "+
				"config that drops off this list stops being gated)", rel, err)
			continue
		}
		t.Run(filepath.Base(rel), func(t *testing.T) {
			cfg, err := CompileConfigForNode(hierTree(t, string(raw)), 0)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if _, verr := validateNATPoolExternalTupleOverlapStrict(cfg, false); verr != nil {
				t.Fatalf("shipped config has a cross-domain NAT overlap: %v", verr)
			}
		})
		checked++
	}
	// Guard the guard: an empty or silently-shrunk list would pass this test
	// while gating nothing at all.
	//
	// This overlaps the read-error branch above -- that branch `continue`s
	// before `checked++`, so a missing file already reds twice. Kept anyway:
	// the two say different things (this one catches a list that shrank between
	// the range and here), and a redundant guard costs nothing where a missing
	// one costs a silently ungated config.
	if checked != len(shippedNATConfigs) {
		t.Fatalf("only %d of %d shipped configs were checked", checked, len(shippedNATConfigs))
	}
	assertShippedNATConfigListIsComplete_6751(t)
}

// assertShippedNATConfigListIsComplete_6751 turns the list above from a FLOOR
// into a census.
//
// The list handles a config being renamed AWAY -- the read error names it. It
// cannot see one being ADDED, which is the direction that matters: a ninth
// `.conf` landing in docs/ or test/incus/ with a source-NAT stanza is gated by
// nothing, `go test ./pkg/config/` stays green, and the list looks complete
// because it is a list. That is the same failure this test's own doc comment is
// about -- a validator's reach is not what it can detect, it is what it is
// actually pointed at -- so leaving the additive direction open would repeat it.
//
// The population is DERIVED and compared against the explicit list rather than
// replacing it. The list stays the readable statement of intent that a reviewer
// can eyeball; the comparison makes a divergence in either direction fail.
func assertShippedNATConfigListIsComplete_6751(t *testing.T) {
	t.Helper()

	var globbed []string
	for _, dir := range []string{"../../docs", "../../test/incus"} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.conf"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		globbed = append(globbed, matches...)
	}

	// ANTI-VACUITY. These paths are relative to the test's working directory,
	// so a glob that silently matches nothing -- a moved package, a changed
	// layout -- would make both sets empty, the comparison hold, and this pass
	// having checked nothing. That failure mode is live precisely because the
	// paths are relative.
	if len(globbed) < len(shippedNATConfigs) {
		t.Fatalf("the glob found %d .conf files, fewer than the %d already listed. "+
			"The relative paths are not resolving from the test's working directory, "+
			"so this comparison would hold vacuously.", len(globbed), len(shippedNATConfigs))
	}

	// Only files that actually carry a source-NAT stanza are in scope; a config
	// with no NAT at all has nothing for this gate to say.
	//
	// DELIBERATE LOOSENESS, named here rather than left for a reviewer to find:
	// this is a text match, so a config mentioning "source-nat" only in a
	// COMMENT is pulled into the census and must be listed. That is a false
	// positive in the direction of MORE gating, which is the correct way to be
	// wrong here -- the cost is one line in the list, where the opposite error
	// costs a silently ungated config. But it means the list can grow for a
	// reason that is not a real NAT stanza, and someone hitting that will think
	// the census is broken. It is not; add the file.
	//
	// Compiling each candidate to decide would be exact, and is not worth it:
	// the gate below already compiles every LISTED config, so an exact selector
	// would double the work to avoid an over-inclusion that costs nothing.
	withNAT := map[string]bool{}
	for _, rel := range globbed {
		raw, err := os.ReadFile(rel)
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		if strings.Contains(string(raw), "source-nat") {
			withNAT[filepath.Clean(rel)] = true
		}
	}
	listed := map[string]bool{}
	for _, rel := range shippedNATConfigs {
		listed[filepath.Clean(rel)] = true
	}

	for rel := range withNAT {
		if !listed[rel] {
			t.Errorf("%s carries a source-NAT stanza and is NOT in shippedNATConfigs, so "+
				"nothing gates it. Add it — a config that is never compiled by this "+
				"package is exactly how xpf-test.conf shipped the defect this test was "+
				"written for.", rel)
		}
	}
	for rel := range listed {
		if !withNAT[rel] {
			t.Errorf("shippedNATConfigs lists %s, but it no longer carries a source-NAT "+
				"stanza (or has moved). Update the list rather than leaving a name that "+
				"gates nothing.", rel)
		}
	}
}

// staticIfaceCfg builds a whole-address static mapping whose external address is
// (or is not) an interface-mode SNAT egress address.
func staticIfaceCfg(externalAddr string, matchPort, mappedPort int) *Config {
	cfg := ifaceEgressCfg("wan", "", "", "172.16.50.5/24", "172.16.60.5/32")
	cfg.Security.NAT.Static = []*StaticNATRuleSet{
		{Name: "s-rs", Rules: []*StaticNATRule{{
			Name: "s", Match: externalAddr, Then: "10.0.0.7",
			MatchDestinationPort: matchPort, MappedPort: mappedPort,
		}}},
	}
	return cfg
}

// TestWholeAddressStaticOnInterfaceEgressIsReported_6751 pins the narrowed
// suppression — the arm both pre-#6751 gates left open.
//
// The #5837 inert advisory SUPPRESSES itself when interface SNAT owns the
// address, correctly (the translation is not inert). That left the genuinely
// unsafe case with NO diagnostic at all: a whole-address static and interface
// SNAT on one address emit the same external tuple, and the reverse index
// cannot disambiguate.
//
// Both halves are asserted: STRICT rejects, tolerant WARNS (#1960 no-brick — a
// peer-sync or boot load must not be bricked by a config already on disk).
//
// FAIL-ON-REVERT: restore the bare `continue` in the warn path and the warn row
// REDS; drop the strict hook and the reject row REDS.
func TestWholeAddressStaticOnInterfaceEgressIsReported_6751(t *testing.T) {
	cfg := staticIfaceCfg("172.16.50.5/32", 0, 0)

	if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, false); err == nil {
		t.Error("STRICT commit ACCEPTED a whole-address static mapping on an " +
			"interface-mode SNAT egress address. Both emit the same external " +
			"(address, port) tuple and the reverse index cannot tell them apart, so " +
			"replies cross the boundary (#6751 §5.7)")
	}
	warns := validateNATInterfaceAddressCollisionWarnings(cfg)
	found := false
	for _, w := range warns {
		if strings.Contains(w, "interface-mode source-NAT egress address") {
			found = true
		}
	}
	if !found {
		t.Errorf("tolerant load emitted NO collision warning; the #5837 suppression is "+
			"still hiding the unsafe case. warnings=%v", warns)
	}
}

// TestStaticOnInterfaceEgressToleratesLoad_6751 is the #1960 half: the tolerant
// path must WARN, never reject. A boot load or peer-sync of a config already on
// disk must not be bricked by a gate added after it was written.
func TestStaticOnInterfaceEgressToleratesLoad_6751(t *testing.T) {
	cfg := staticIfaceCfg("172.16.50.5/32", 0, 0)
	if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, true); err != nil {
		t.Fatalf("LENIENT validation rejected the config: %v. A tolerant load / peer-sync "+
			"must warn, not brick (#1960)", err)
	}
}

// TestMappedPortStaticOnInterfaceEgressIsNotReported_6751 is the control that
// keeps the finding from degenerating into "any static on an interface address".
//
// A mapped-port static emits a DISTINCT external port, so it does not produce
// the ambiguous identity — reserving its emitted port is the runtime half's job
// (PR 3b/3c), not a config-time rejection. Without this row, a detector that
// flagged every static would pass the cell above while false-rejecting the
// shipped `8080 -> 80` port-forward shape.
func TestMappedPortStaticOnInterfaceEgressIsNotReported_6751(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		matchPort, mappedPort int
	}{
		{"match-destination-port set", 8080, 0},
		{"mapped-port set", 0, 80},
		{"both set (8080 -> 80)", 8080, 80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := staticIfaceCfg("172.16.50.5/32", tc.matchPort, tc.mappedPort)
			if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, false); err != nil {
				t.Fatalf("a MAPPED-PORT static on an interface egress was rejected: %v. It "+
					"emits a distinct external port, so it is not the whole-address "+
					"ambiguity (#6751 §5.7)", err)
			}
		})
	}
}

// TestStaticOffInterfaceEgressIsNotReported_6751 is the other control: a
// whole-address static on an address that is NOT an interface-SNAT egress is
// ordinary and must stay clean.
func TestStaticOffInterfaceEgressIsNotReported_6751(t *testing.T) {
	cfg := staticIfaceCfg("203.0.113.10/32", 0, 0)
	if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, false); err != nil {
		t.Fatalf("a whole-address static on a NON-interface address was rejected: %v", err)
	}
}

// #15258 (A89-05): the verdict for a port-mapped static on an
// interface-SNAT egress address must not depend on whether an unrelated
// source pool exists. natPoolOverlapOwners early-returned nil when
// len(pools)==0, so the interface-egress owners (and therefore the
// #14368 static pairing, which includes port-mapped statics against
// minting allocators) vanished on pool-less configs: the same config
// was accepted without pools and rejected once any pool was added.
// The contract: interface-egress owners are built regardless of pools,
// so both shapes give the SAME verdict. Whole-address statics are
// already rejected in both shapes by the #6751 §5.7 gate; the
// port-mapped shape must now agree too (interface SNAT can mint the
// mapped external port, #14368).
func staticIfaceCfg15258(withPool bool, matchPort, mappedPort int) *Config {
	cfg := staticIfaceCfg("172.16.50.5/32", matchPort, mappedPort)
	if !withPool {
		cfg.Security.NAT.SourcePools = nil
		// Drop the pool-mode rule-set too: no source pool exists at all.
		cfg.Security.NAT.Source = cfg.Security.NAT.Source[:1]
	}
	return cfg
}

func TestPortMappedStaticOnIfaceEgressSameVerdictWithAndWithoutPool_15258(t *testing.T) {
	for _, withPool := range []bool{false, true} {
		cfg := staticIfaceCfg15258(withPool, 8080, 80)
		if _, err := validateStaticNATPoolOverlapStrict(cfg, false); err == nil {
			t.Fatalf("withPool=%v: port-mapped static on interface egress must reject via #14368 pairing (#15258)", withPool)
		} else if !strings.Contains(err.Error(), "#14368") {
			t.Fatalf("withPool=%v: error must cite #14368, got: %v", withPool, err)
		}
		if _, err := validateStaticNATPoolOverlapStrict(cfg, true); err != nil {
			t.Fatalf("withPool=%v: lenient must warn not reject (#1960): %v", withPool, err)
		}
	}
	// Whole-address control: already consistent (rejected in both
	// shapes by #6751); must stay rejected, not become pool-dependent.
	for _, withPool := range []bool{false, true} {
		cfg := staticIfaceCfg15258(withPool, 0, 0)
		if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, false); err == nil {
			t.Fatalf("withPool=%v: whole-address static on interface egress must stay rejected (#6751)", withPool)
		}
	}
}
