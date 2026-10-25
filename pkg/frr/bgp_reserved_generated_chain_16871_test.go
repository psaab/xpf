package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16871 (R3-B08-03): legal policy names `xpf` + `default-export` chained in
// that order compose into the reserved generated default-export map
// `xpf-default-export-xpf-chain`. Before the fix no belt checked that pair:
// bgpComposedChainCollision special-cased only the emptied-chain deny, and
// bgpDefaultExportCollision15157 only checked an operator policy-statement
// NAMED the reserved name. FRR merges the composed map with the generated
// default-export map, corrupting both filters with a clean commit/apply.
//
// These tests FAIL pre-fix (the forge returns nil) and pass post-fix.

// TestReservedGeneratedTableCoversFixedNames16871 pins the registry: it is
// derived from config.ReservedGeneratedRouteMaps16871, currently covers both
// fixed generated names, and each is derivable by a chain of legally named
// policies (the forgery the registry exists to catch). If a name
// construction changes, this fails instead of silently making the belt
// unreachable.
func TestReservedGeneratedTableCoversFixedNames16871(t *testing.T) {
	want := map[string][]string{
		emptiedChainDenyName:      {"xpf", "emptied", "chain"},
		bgpDefaultExportName15157: {"xpf", "default-export"},
	}
	if got, want := len(reservedGeneratedRouteMaps16871), len(config.ReservedGeneratedRouteMaps16871); got != want {
		t.Fatalf("derived registry has %d entries, config enumeration has %d (%v) — derivation broken",
			got, want, config.ReservedGeneratedRouteMaps16871)
	}
	if len(reservedGeneratedRouteMaps16871) != len(want) {
		t.Fatalf("reservedGeneratedRouteMaps16871 has %d entries, want %d (%v)",
			len(reservedGeneratedRouteMaps16871), len(want), want)
	}
	for _, r := range reservedGeneratedRouteMaps16871 {
		chain, ok := want[r.name]
		if !ok {
			t.Fatalf("table registers unexpected reserved name %q", r.name)
		}
		if forged := composedChainName(chain); forged != r.name {
			t.Fatalf("reserved name %q is no longer derivable: composedChainName(%v) = %q; "+
				"re-derive whether the belt is still reachable", r.name, chain, forged)
		}
		if !strings.HasSuffix(r.name, ReservedChainSuffix) {
			t.Errorf("reserved name %q must end in ReservedChainSuffix so the strict suffix gate covers the direct spelling", r.name)
		}
	}
}

// TestReservedGeneratedTableMatchesConfig16871 pins the derivation: the
// render-side registry must equal config.ReservedGeneratedRouteMaps16871
// as a SET, in config order, and every frr name constant must be the config
// constant (they are aliases, so inequality means someone re-declared a
// literal — drift). An entry added to the config enumeration is picked up
// structurally; this reds if the derivation or an alias breaks.
func TestReservedGeneratedTableMatchesConfig16871(t *testing.T) {
	// Order + size pin: the derived registry preserves config order exactly.
	if len(reservedGeneratedRouteMaps16871) != len(config.ReservedGeneratedRouteMaps16871) {
		t.Fatalf("derived registry (%d entries) and config enumeration (%d entries %v) disagree in size — derivation broken",
			len(reservedGeneratedRouteMaps16871),
			len(config.ReservedGeneratedRouteMaps16871), config.ReservedGeneratedRouteMaps16871)
	}
	for i, name := range config.ReservedGeneratedRouteMaps16871 {
		if reservedGeneratedRouteMaps16871[i].name != name {
			t.Errorf("derived registry[%d] = %q, want config order %q", i, reservedGeneratedRouteMaps16871[i].name, name)
		}
	}
	want := map[string]bool{}
	for _, name := range config.ReservedGeneratedRouteMaps16871 {
		if want[name] {
			t.Fatalf("config.ReservedGeneratedRouteMaps16871 lists %q twice", name)
		}
		want[name] = true
	}
	for _, r := range reservedGeneratedRouteMaps16871 {
		if !want[r.name] {
			t.Errorf("frr reserved table names %q, absent from config.ReservedGeneratedRouteMaps16871 %v", r.name, config.ReservedGeneratedRouteMaps16871)
		}
		delete(want, r.name)
	}
	for name := range want {
		t.Errorf("config.ReservedGeneratedRouteMaps16871 names %q, absent from the frr reserved table", name)
	}
	if config.EmptiedChainDenyName != emptiedChainDenyName {
		t.Errorf("config.EmptiedChainDenyName %q != frr emptiedChainDenyName %q (must alias, not copy)", config.EmptiedChainDenyName, emptiedChainDenyName)
	}
	if config.BGPDefaultExportName != bgpDefaultExportName15157 {
		t.Errorf("config.BGPDefaultExportName %q != frr bgpDefaultExportName15157 %q (must alias, not copy)", config.BGPDefaultExportName, bgpDefaultExportName15157)
	}
	// The alias targets themselves must be exactly the two known literals.
	if emptiedChainDenyName != "xpf-emptied-chain"+ReservedChainSuffix ||
		bgpDefaultExportName15157 != "xpf-default-export"+ReservedChainSuffix {
		t.Errorf("reserved literals changed: emptied=%q default-export=%q", emptiedChainDenyName, bgpDefaultExportName15157)
	}
}

func reservedChainFC16871(chain []string) *FullConfig {
	mk := func(n string) *config.PolicyStatement {
		return &config.PolicyStatement{Name: n, DefaultAction: "accept",
			Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}}
	}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{},
	}
	for _, n := range chain {
		po.PolicyStatements[n] = mk(n)
	}
	// Control members for the negative control below.
	po.PolicyStatements["LOCAL"] = mk("LOCAL")
	po.PolicyStatements["TRANSIT"] = mk("TRANSIT")
	return &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true, Export: chain},
			},
		},
	}
}

// TestForgedDefaultExportFixtureReferencesGeneratedMap16871 proves the
// fixture genuinely collides. The defect witness must be the GENERATED
// definition itself (permit match source-protocol bgp, then deny 20), NOT
// any `route-map <name>` occurrence: the forged composed map [xpf
// default-export] renders under the same name and would satisfy a bare
// occurrence count by itself. We therefore build, WITHOUT any forged chain,
// a section whose only route-map of that name is the generated one, and
// assert its generated sequences; then assert the belt fails the forged
// chain (not a coincidence of names in the render).
func TestForgedDefaultExportFixtureReferencesGeneratedMap16871(t *testing.T) {
	// (a) Independent generated-map witness: the #15157 fixture has
	// origination (EXP from protocol static) and no-export neighbours, and
	// contains NO policy named xpf/default-export, so the forged composed
	// map cannot exist here. The definition block must carry exactly the
	// generated permit-bgp/deny pair.
	section := New().buildManagedSection(leakFC15157())
	def := routeMapBlock15157(section, bgpDefaultExportName15157)
	if !strings.Contains(def, "route-map "+bgpDefaultExportName15157+" permit 10\n match source-protocol bgp\n") ||
		!strings.Contains(def, "route-map "+bgpDefaultExportName15157+" deny 20\n") {
		t.Fatalf("generated default-export definition not found independently of any forged chain:\n%s", section)
	}
	if strings.Contains(def, "match ip address") {
		t.Fatalf("definition carries a composed/forged term, not the generated pair:\n%s", def)
	}
	// (b) The forged chain collides with that generated map: belt refuses.
	fc := reservedChainFC16871([]string{"xpf", "default-export"})
	if err := bgpComposedChainCollision(fc); err == nil {
		t.Fatal("expected collision error on the forged default-export chain")
	} else if !strings.Contains(err.Error(), bgpDefaultExportName15157) {
		t.Fatalf("collision error must name the generated map: %v", err)
	}
}

// TestForgedChainApplyFullRefusesBeforeWrite16871 is the one-fixture
// end-to-end witness: ONE FullConfig carries BOTH the exporting neighbour
// that originates routes (so the generated default-export map is genuinely
// used) AND the forged chain [xpf default-export] on another neighbour, plus
// the no-export neighbour that attaches the generated map. ApplyFull must
// refuse naming the reserved map, and must refuse BEFORE any write: the
// on-disk frr.conf keeps its exact prior bytes and the executor sees no
// reload. (buildManagedSection is intentionally not used here — ApplyFull
// never reaches it on this path.)
func TestForgedChainApplyFullRefusesBeforeWrite16871(t *testing.T) {
	fc := leakFC15157() // A exports EXP (originates static); C/C6 no-export.
	// Forge: policies xpf + default-export, chained on a new neighbour.
	mk := func(n string) *config.PolicyStatement {
		return &config.PolicyStatement{Name: n, DefaultAction: "accept",
			Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}}
	}
	fc.PolicyOptions.PolicyStatements["xpf"] = mk("xpf")
	fc.PolicyOptions.PolicyStatements["default-export"] = mk("default-export")
	fc.BGP.Neighbors = append(fc.BGP.Neighbors,
		&config.BGPNeighbor{Address: "192.0.2.9", PeerAS: 65009, FamilyInet: true, Export: []string{"xpf", "default-export"}})

	// Sanity on the SAME fixture: the generated map is genuinely referenced
	// (no-export C attaches it) and the belt fires on this exact config.
	if !bgpUsesDefaultExport15157(fc.BGP, fc.PolicyOptions) {
		t.Fatal("fixture must genuinely use the generated default-export map")
	}
	if err := bgpComposedChainCollision(fc); err == nil || !strings.Contains(err.Error(), bgpDefaultExportName15157) {
		t.Fatalf("belt must refuse this fixture naming the reserved map, got %v", err)
	}

	confPath := filepath.Join(t.TempDir(), "frr.conf")
	const prior = "log syslog informational\n! prior operator bytes\n"
	if err := os.WriteFile(confPath, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeExecutor{}
	m := &Manager{frrConf: confPath, exec: fake}
	err := m.ApplyFull(fc)
	if err == nil || !strings.Contains(err.Error(), bgpDefaultExportName15157) {
		t.Fatalf("ApplyFull must refuse the forged fixture naming %s, got %v", bgpDefaultExportName15157, err)
	}
	after, rerr := os.ReadFile(confPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(after) != prior {
		t.Errorf("ApplyFull wrote before refusing: frr.conf changed to %q", after)
	}
	if n := fake.reloadPyCalls(); n != 0 {
		t.Errorf("ApplyFull must refuse before any reload, saw %d reload call(s)", n)
	}
}

// TestForgedEmptiedChainStillFailsClosed16871 is the positive control from
// the issue: the pre-existing emptied-deny forge keeps failing closed
// through the new table (same error class, still naming the reserved map).
func TestForgedEmptiedChainStillFailsClosed16871(t *testing.T) {
	fc := reservedChainFC16871([]string{"xpf", "emptied", "chain"})
	err := bgpComposedChainCollision(fc)
	if err == nil {
		t.Fatal("chain [xpf emptied chain] must still fail the apply closed")
	}
	if !strings.Contains(err.Error(), emptiedChainDenyName) {
		t.Errorf("collision error does not name the emptied deny: %v", err)
	}
}

// TestOrdinaryChainNoReservedCollision16871 is the negative control from the
// issue probe: [LOCAL TRANSIT] derives an ordinary composed name and must
// not be refused.
func TestOrdinaryChainNoReservedCollision16871(t *testing.T) {
	fc := reservedChainFC16871([]string{"LOCAL", "TRANSIT"})
	if err := bgpComposedChainCollision(fc); err != nil {
		t.Errorf("ordinary chain [LOCAL TRANSIT] must not be refused: %v", err)
	}
}
