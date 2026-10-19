package frr

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7625: `filterDefinedPolicies` returns the SURVIVING SUBSET of an authored
// policy chain, silently discarding any member that names a policy-statement
// which is not defined. That produces two materially different outcomes:
//
//	authored chain        after the drop   outcome
//	[undefined]           []               no attachment emitted -> PERMIT-ALL
//	[defined, undefined]  [defined]        attachment still emitted -> SILENT NARROWING
//
// The second is the more insidious, precisely because it is invisible: the
// neighbour still carries A filter, the session works, and `show route-map`
// shows a real, well-formed policy — it is simply not the policy the operator
// wrote. Nothing anywhere reports that a member of the authored chain was
// discarded.
//
// WHY THE EXISTING #6807 HELPER CANNOT SEE IT. `danglingRouteMapRefs6807`
// compares references emitted in the rendered section against definitions
// emitted in that same section. A NARROWED chain still references a route-map
// that really is defined, so the rendered section is perfectly self-consistent
// and the helper — correctly, for its own question — reports nothing. Detecting
// narrowing needs the AUTHORED chain, which the rendered text does not contain.
// `TestDanglingHelperIsBlindToNarrowing7625` proves that rather than asserting
// it.
//
// This detector is deliberately DECISION-INDEPENDENT. #7625 has an open
// behaviour choice (keep dropping / emit a bounded deny / split by direction),
// and its own text says whichever option is taken must cover BOTH shapes. This
// helper is what lets any of them be asserted; it changes no behaviour.

// chainDrop7625 records one attachment site where the resolved chain differs
// from the authored one.
type chainDrop7625 struct {
	Where    string
	Authored []string
	Kept     []string
	Dropped  []string
}

// Emptied reports the PERMIT-ALL shape: every authored member was discarded, so
// no attachment is emitted at all and FRR applies no filter in that direction.
// False means the SILENT-NARROWING shape — an attachment is still emitted, and
// it is not the one the operator wrote.
func (d chainDrop7625) Emptied() bool { return len(d.Kept) == 0 }

func (d chainDrop7625) String() string {
	shape := "narrowed"
	if d.Emptied() {
		shape = "emptied->permit-all"
	}
	return fmt.Sprintf("%s: authored=%v kept=%v dropped=%v (%s)",
		d.Where, d.Authored, d.Kept, d.Dropped, shape)
}

// droppedFrom7625 returns the authored names that filterDefinedPolicies would
// discard. It re-derives the drop rather than reaching into the production
// helper, so a change to that helper's contract shows up here as a difference
// rather than being mirrored silently.
func droppedFrom7625(authored []string, po *config.PolicyOptionsConfig) (kept, dropped []string) {
	for _, n := range authored {
		if n == "" {
			continue
		}
		if isDefinedPolicyStatement(n, po) {
			kept = append(kept, n)
		} else {
			dropped = append(dropped, n)
		}
	}
	return kept, dropped
}

// narrowedPolicyChains7625 walks every BGP policy-chain attachment site in the
// config and reports each one whose resolved chain differs from the authored
// chain. Sites with no authored chain, or whose chain survives intact, are not
// reported.
//
// Neighbour sites mirror bgpNeighborImportChain/bgpNeighborExportChain: a
// neighbour with ANY own entry suppresses the global default for that peer
// (#5277), so only its own list is examined; a neighbour with none inherits the
// global chain and is not a distinct site.
func narrowedPolicyChains7625(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []chainDrop7625 {
	var out []chainDrop7625
	add := func(where string, authored []string) {
		if len(authored) == 0 {
			return
		}
		kept, dropped := droppedFrom7625(authored, po)
		if len(dropped) == 0 {
			return
		}
		out = append(out, chainDrop7625{
			Where: where, Authored: authored, Kept: kept, Dropped: dropped,
		})
	}
	if bgp == nil {
		return nil
	}
	add("protocols bgp import", bgp.Import)
	add("protocols bgp export", bgp.Export)
	for _, n := range bgp.Neighbors {
		if n == nil {
			continue
		}
		if hasNonEmptyPolicy(n.Import) {
			add(fmt.Sprintf("neighbor %s import", n.Address), n.Import)
		}
		if hasNonEmptyPolicy(n.Export) {
			add(fmt.Sprintf("neighbor %s export", n.Address), n.Export)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Where < out[j].Where })
	return out
}

func definedPolicy7625(name string) *config.PolicyStatement {
	return &config.PolicyStatement{
		Name:  name,
		Terms: []*config.PolicyTerm{{Name: "t1", PrefixList: []string{"PL"}}},
	}
}

func policyOptions7625(defined ...string) *config.PolicyOptionsConfig {
	ps := map[string]*config.PolicyStatement{}
	for _, n := range defined {
		ps[n] = definedPolicy7625(n)
	}
	return &config.PolicyOptionsConfig{
		PolicyStatements: ps,
		PrefixLists:      map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}}},
		Communities:      map[string]*config.CommunityDef{},
		ASPaths:          map[string]*config.ASPathDef{},
	}
}

// NEGATIVE CONTROL. A detector that reports nothing must mean the chains are
// intact, not that the walk found no sites — so this fixture has real chains
// and the assertion below requires the walk to have visited them.
func TestNarrowingDetectorIsSilentOnAnIntactConfig7625(t *testing.T) {
	po := policyOptions7625("A", "B")
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Import: []string{"A"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"A", "B"}, Export: []string{"B"}},
		},
	}
	if got := narrowedPolicyChains7625(bgp, po); len(got) != 0 {
		t.Fatalf("reported drops on an intact config: %v", got)
	}
	// Anti-vacuity: the walk must actually resolve those chains, or "no drops"
	// is the answer for a detector that looked at nothing.
	if kept, dropped := droppedFrom7625([]string{"A", "B"}, po); len(kept) != 2 || len(dropped) != 0 {
		t.Fatalf("the resolver did not see the defined chain: kept=%v dropped=%v", kept, dropped)
	}
}

// The two shapes, side by side. A single-shape test cannot show that they are
// DIFFERENT outcomes, which is the whole point of #7625's correction.
func TestNarrowingDetectorSeparatesEmptiedFromNarrowed7625(t *testing.T) {
	po := policyOptions7625("REAL")
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			// Shape 1: the only member is undefined -> chain empties -> permit-all.
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"GHOST"}},
			// Shape 2: one member survives -> attachment still emitted, but it is
			// not the authored policy. This is the shape nothing could see before.
			{Address: "10.0.2.2", PeerAS: 65003, FamilyInet: true, Import: []string{"REAL", "GHOST"}},
		},
	}
	got := narrowedPolicyChains7625(bgp, po)
	if len(got) != 2 {
		t.Fatalf("want 2 findings (one per shape), got %d: %v", len(got), got)
	}
	byWhere := map[string]chainDrop7625{}
	for _, d := range got {
		byWhere[d.Where] = d
	}

	emptied, ok := byWhere["neighbor 10.0.2.1 import"]
	if !ok {
		t.Fatalf("no finding for the emptied chain; got %v", got)
	}
	if !emptied.Emptied() {
		t.Errorf("a chain whose only member was dropped must report Emptied(): %v", emptied)
	}

	narrowed, ok := byWhere["neighbor 10.0.2.2 import"]
	if !ok {
		t.Fatalf("no finding for the narrowed chain; got %v", got)
	}
	if narrowed.Emptied() {
		t.Errorf("a chain that still emits an attachment must NOT report Emptied(): %v", narrowed)
	}
	if len(narrowed.Kept) != 1 || narrowed.Kept[0] != "REAL" {
		t.Errorf("narrowed chain kept %v, want [REAL]", narrowed.Kept)
	}
	if len(narrowed.Dropped) != 1 || narrowed.Dropped[0] != "GHOST" {
		t.Errorf("narrowed chain dropped %v, want [GHOST]", narrowed.Dropped)
	}
}

// The justification for this detector existing, PROVEN rather than asserted:
// the #6807 helper is blind to narrowing, because a narrowed chain leaves a
// rendered section that is internally consistent.
func TestDanglingHelperIsBlindToNarrowing7625(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.2", PeerAS: 65003, FamilyInet: true, Import: []string{"REAL", "GHOST"}},
			},
		},
	}
	section := New().buildManagedSection(fc)

	// The rendered section is self-consistent: no reference dangles.
	if dangling := danglingRouteMapRefs6807(section); len(dangling) != 0 {
		t.Fatalf("precondition failed — the narrowed render is supposed to be "+
			"internally consistent, but #6807's helper found %v. If this fires, "+
			"the renderer changed and this test's premise no longer holds", dangling)
	}
	// ...and yet an authored member was silently discarded.
	drops := narrowedPolicyChains7625(fc.BGP, po)
	if len(drops) != 1 || drops[0].Emptied() {
		t.Fatalf("the narrowing detector must report exactly one non-emptied "+
			"finding here; got %v", drops)
	}
	if !strings.Contains(drops[0].String(), "GHOST") {
		t.Errorf("the finding does not name the discarded policy: %v", drops[0])
	}
	t.Logf("#6807 helper: clean. #7625 detector: %v", drops[0])
}

// ---------------------------------------------------------------------------
// #7625 EMPTIED-CHAIN FIX. The decision on #7625 splits the two shapes: the
// EMPTIED chain gets a bounded explicit deny (this section), the NARROWED chain
// keeps today's behaviour pending a measurement of FRR chain evaluation.
//
// Why the emptied case is a HOLE and not a degradation: the operator wrote a
// filter on that direction, every member of it failed to resolve, and the
// renderer's response was to emit NO attachment at all. Per the FRR semantics
// established in #6807, an ABSENT attachment is the one and only shape that
// PERMITS. So the config that asked for the most filtering got the least.

// neighborRouteMapRefs7625 returns the route-map names attached to addr in the
// given direction ("in"/"out"), in render order.
func neighborRouteMapRefs7625(section, addr, dir string) []string {
	var out []string
	re := regexp.MustCompile(`(?m)^\s*neighbor ` + regexp.QuoteMeta(addr) +
		` route-map (\S+) ` + dir + `\s*$`)
	for _, m := range re.FindAllStringSubmatch(section, -1) {
		out = append(out, m[1])
	}
	return out
}

// routeMapIsDeny7625 reports whether name is defined in the section and every
// sequence it defines is a deny. A single permit sequence anywhere under the
// name is enough to let routes through, so this asks for ALL, not ANY.
func routeMapIsDeny7625(section, name string) (defined bool, allDeny bool) {
	re := regexp.MustCompile(`(?m)^route-map ` + regexp.QuoteMeta(name) + ` (permit|deny) \d+\s*$`)
	ms := re.FindAllStringSubmatch(section, -1)
	if len(ms) == 0 {
		return false, false
	}
	for _, m := range ms {
		if m[1] != "deny" {
			return true, false
		}
	}
	return true, true
}

// THE FIX. An import chain whose every member is undefined must deny, not
// permit. Before the fix this fails at the FIRST assertion: no attachment is
// emitted at all.
func TestEmptiedImportChainDeniesRatherThanPermits7625(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"GHOST"}},
			},
		},
	}
	section := New().buildManagedSection(fc)

	refs := neighborRouteMapRefs7625(section, "10.0.2.1", "in")
	if len(refs) != 1 {
		t.Fatalf("an emptied import chain emitted %d inbound route-map attachments, want 1 "+
			"(no attachment is the PERMIT-ALL shape #7625 is about):\n%s", len(refs), section)
	}
	defined, allDeny := routeMapIsDeny7625(section, refs[0])
	if !defined {
		t.Fatalf("attachment references %q but the managed section never defines it", refs[0])
	}
	if !allDeny {
		t.Errorf("route-map %q must be an unconditional deny; it carries a permit sequence:\n%s",
			refs[0], section)
	}
	// The #6807 property must hold BY CONSTRUCTION, not because the reference
	// was dropped.
	if d := danglingRouteMapRefs6807(section); len(d) != 0 {
		t.Errorf("emptied-chain fix left dangling route-map refs %v", d)
	}
}

// THE TRAP, as a negative control. The GLOBAL `protocols bgp export` list may
// name bare PROTOCOL tokens (`static`, `direct`), which are not
// policy-statements and are excluded from the policy chain on purpose: they
// render as `redistribute <proto>` on a separate router-global path. Such a
// list also filters to EMPTY, but it is not an emptied FILTER — the operator
// asked to advertise those routes, not to drop everything. Attaching a deny
// here would withdraw every route to the peer. A NEIGHBOUR's own export list
// has no redistribute rendering, so the same token there is a ghost and DOES
// deny (#15159, policy_chain_neighbor_protocol_token_15159_test.go).
//
// This cell fails if the fix keys on "the filtered chain is empty" instead of
// "every authored member is a genuine ghost at this scope".
func TestEmptiedExportChainOfBareProtocolTokensGetsNoDeny7625(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Export: []string{"static"},
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.3", PeerAS: 65004, FamilyInet: true},
			},
		},
	}
	section := New().buildManagedSection(fc)

	// Anti-vacuity: "static" really is a bare protocol token, so this fixture
	// really does exercise the empty-after-filter path.
	if !knownRedistProtocol("static") {
		t.Fatalf("fixture premise broken: \"static\" is not a known redistribute protocol")
	}
	if kept := bgpNeighborExportChain(fc.BGP.Neighbors[0], nil, po); len(kept) != 0 {
		t.Fatalf("fixture premise broken: the export chain did not filter to empty, got %v", kept)
	}
	if refs := neighborRouteMapRefs7625(section, "10.0.2.3", "out"); len(refs) != 0 {
		t.Errorf("a global bare-protocol export list must not attach a deny (it would withdraw "+
			"every route to the peer); got %v:\n%s", refs, section)
	}
}

// NEGATIVE CONTROL. An intact chain must be untouched by the fix — same
// attachment, referencing the operator's own policy, no deny anywhere.
func TestIntactChainIsUnaffectedByTheEmptiedFix7625(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.4", PeerAS: 65005, FamilyInet: true, Import: []string{"REAL"}},
			},
		},
	}
	section := New().buildManagedSection(fc)
	refs := neighborRouteMapRefs7625(section, "10.0.2.4", "in")
	if len(refs) != 1 || refs[0] != "REAL" {
		t.Fatalf("intact chain must reference the operator policy, got %v", refs)
	}
}

// THE DIRECTION ASYMMETRY. A bare protocol token means REDISTRIBUTE on export,
// but nothing at all on import — inbound has no redistribute construct, so the
// token renders as a route-map name and resolves to nothing. The strict commit
// path rejects it for exactly that reason
// (config.TestBGPNeighborImportProtocolTokenRejected), so it reaches the
// renderer only on the lenient load / peer-sync path — and there it is a ghost
// like any other and must DENY.
//
// This cell fails if the protocol-token exclusion is applied to both directions
// instead of just export. It is the counterpart of the export cell above: the
// two together pin the asymmetry, which neither can do alone.
func TestEmptiedImportChainOfBareProtocolTokensStillDenies7625(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.5", PeerAS: 65006, FamilyInet: true, Import: []string{"static"}},
			},
		},
	}
	section := New().buildManagedSection(fc)
	refs := neighborRouteMapRefs7625(section, "10.0.2.5", "in")
	if len(refs) != 1 || refs[0] != emptiedChainDenyName {
		t.Fatalf("an inbound bare protocol token resolves to nothing and must deny; "+
			"got refs %v:\n%s", refs, section)
	}
	if _, allDeny := routeMapIsDeny7625(section, refs[0]); !allDeny {
		t.Errorf("route-map %q must be an unconditional deny", refs[0])
	}
}

// The reserved name must not be forgeable. FRR merges same-named route-maps, so
// an operator policy-statement of this exact name would fuse its sequences into
// the deny. The strict path forbids the reserved namespace; this is the
// render-side belt for the lenient path, and it fails the apply CLOSED.
func TestEmptiedChainDenyCollisionFailsClosed7625(t *testing.T) {
	po := policyOptions7625("REAL", emptiedChainDenyName)
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.6", PeerAS: 65007, FamilyInet: true, Import: []string{"GHOST"}},
			},
		},
	}
	err := emptiedChainDenyCollision(fc)
	if err == nil {
		t.Fatal("a colliding operator policy-statement of the reserved deny name must fail the apply closed")
	}
	if !strings.Contains(err.Error(), emptiedChainDenyName) {
		t.Errorf("collision error does not name the route-map: %v", err)
	}
	// NEGATIVE CONTROL: the same colliding name is harmless when no attachment
	// resolves to the deny, so the guard must not fire on every config that
	// happens to define that name.
	clean := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.7", PeerAS: 65008, FamilyInet: true, Import: []string{"REAL"}},
			},
		},
	}
	if err := emptiedChainDenyCollision(clean); err != nil {
		t.Errorf("guard fired on a config that never references the deny: %v", err)
	}
}

// The withdrawal must be ALERTABLE, not just logged. An emptied chain denies
// every route in that direction, which is the same operator-visible consequence
// the #6807 oversized cases carry, so it belongs in the same quarantine gauge —
// and the set is rebuilt per render, so a config that no longer empties must
// stop reporting rather than stay latched.
func TestEmptiedChainDenyIsQuarantineCounted7625(t *testing.T) {
	po := policyOptions7625("REAL")
	m := New()

	emptied := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.8", PeerAS: 65009, FamilyInet: true, Import: []string{"GHOST"}},
			},
		},
	}
	m.buildManagedSection(emptied)
	found := false
	for _, n := range m.QuarantinedRouteMaps() {
		if n == emptiedChainDenyName {
			found = true
		}
	}
	if !found {
		t.Fatalf("emptied-chain deny is not quarantine-counted; got %v", m.QuarantinedRouteMaps())
	}

	// Re-rendering a config with nothing emptied must CLEAR it: an alert that
	// keeps firing after the operator restores the policy is how the next real
	// one gets missed.
	fixed := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.8", PeerAS: 65009, FamilyInet: true, Import: []string{"REAL"}},
			},
		},
	}
	m.buildManagedSection(fixed)
	for _, n := range m.QuarantinedRouteMaps() {
		if n == emptiedChainDenyName {
			t.Errorf("quarantine stayed latched after the config stopped emptying: %v",
				m.QuarantinedRouteMaps())
		}
	}
}

// AGREEMENT. bgpNeighborAuthoredExport/Import re-state the most-specific-wins
// resolution that bgpNeighborExportChain/ImportChain apply (a neighbor with ANY
// own entry suppresses the global default; otherwise it inherits). Two copies of
// one rule drift, and the drift would be silent and dangerous in BOTH
// directions: an authored list read from the wrong source could deny a neighbor
// that inherits a perfectly good global chain, or miss an emptied one.
//
// So this pins the AGREEMENT rather than either copy: filtering the authored
// chain must reproduce the resolver's chain exactly, for every shape. A change
// to either function alone fails here.
func TestAuthoredChainAgreesWithResolvedChain7625(t *testing.T) {
	po := policyOptions7625("REAL", "ALSO")
	cases := []struct {
		name string
		bgp  *config.BGPConfig
		n    *config.BGPNeighbor
	}{
		{"neighbor own list overrides global",
			&config.BGPConfig{Import: []string{"REAL"}, Export: []string{"REAL"}},
			&config.BGPNeighbor{Import: []string{"ALSO"}, Export: []string{"ALSO"}}},
		{"neighbor empty inherits global",
			&config.BGPConfig{Import: []string{"REAL", "ALSO"}, Export: []string{"REAL"}},
			&config.BGPNeighbor{}},
		{"both empty",
			&config.BGPConfig{},
			&config.BGPNeighbor{}},
		{"neighbor ghost-only still overrides global",
			&config.BGPConfig{Import: []string{"REAL"}, Export: []string{"REAL"}},
			&config.BGPNeighbor{Import: []string{"GHOST"}, Export: []string{"GHOST"}}},
		{"global ghost-only, neighbor inherits it",
			&config.BGPConfig{Import: []string{"GHOST"}, Export: []string{"GHOST"}},
			&config.BGPNeighbor{}},
		{"neighbor mixed, one survives",
			&config.BGPConfig{},
			&config.BGPNeighbor{Import: []string{"REAL", "GHOST"}, Export: []string{"GHOST", "ALSO"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gi := bgpGlobalImportChain(tc.bgp, po)
			ge := bgpGlobalExportChain(tc.bgp, po)

			wantIn := bgpNeighborImportChain(tc.n, gi, po)
			gotIn := filterDefinedPolicies(bgpNeighborAuthoredImport(tc.n, tc.bgp), po)
			if !equalStringSlice(gotIn, wantIn) {
				t.Errorf("import: authored%v filters to %v, resolver says %v",
					bgpNeighborAuthoredImport(tc.n, tc.bgp), gotIn, wantIn)
			}

			wantOut := bgpNeighborExportChain(tc.n, ge, po)
			gotOut := filterDefinedPolicies(bgpNeighborAuthoredExport(tc.n, tc.bgp), po)
			if !equalStringSlice(gotOut, wantOut) {
				t.Errorf("export: authored%v filters to %v, resolver says %v",
					bgpNeighborAuthoredExport(tc.n, tc.bgp), gotOut, wantOut)
			}
		})
	}
}

// The reserved deny name is FORGEABLE by a composed chain, which the original
// #7625 comment denied. ReservedChainSuffix stops a policy-statement from being
// NAMED that; it does not stop several legally named policies from JOINING into
// it. composedChainName(["xpf","emptied","chain"]) is byte-identical to
// emptiedChainDenyName, and FRR merges same-named route-maps — so without a
// guard the composed chain's permits fuse into the deny and reopen the very hole
// #7625 closed, while the chain's own filter is corrupted by the deny's sequence.
//
// This is the derivation, asserted directly rather than assumed, so a future
// change to either name construction fails here instead of silently making the
// guard unreachable.
func TestComposedChainCanForgeTheReservedDenyName7625(t *testing.T) {
	forged := composedChainName([]string{"xpf", "emptied", "chain"})
	if forged != emptiedChainDenyName {
		t.Fatalf("the collision this guard exists for is no longer derivable: "+
			"composedChainName gives %q, reserved name is %q. If a name construction "+
			"changed, re-derive whether the guard below is still reachable — an "+
			"unreachable guard passes its test and protects nothing",
			forged, emptiedChainDenyName)
	}
}

// FAIL CLOSED. A config carrying both a chain that derives the reserved name and
// an emptied chain that references it must be refused, not rendered.
func TestForgedDenyNameFailsTheApplyClosed7625(t *testing.T) {
	mk := func(n string) *config.PolicyStatement {
		return &config.PolicyStatement{Name: n, DefaultAction: "accept",
			Terms: []*config.PolicyTerm{{Name: "t1", PrefixList: []string{"PL"}}}}
	}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"xpf": mk("xpf"), "emptied": mk("emptied"), "chain": mk("chain"),
		},
		PrefixLists: map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}}},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true,
					Import: []string{"xpf", "emptied", "chain"}},
			},
		},
	}
	err := bgpComposedChainCollision(fc)
	if err == nil {
		t.Fatal("a composed chain deriving the reserved emptied-chain deny name must " +
			"fail the apply closed; FRR would merge it with the deny")
	}
	if !strings.Contains(err.Error(), emptiedChainDenyName) {
		t.Errorf("the error does not name the collision: %v", err)
	}

	// NEGATIVE CONTROL: an ordinary composed chain must still render. A guard
	// that refuses every composed chain would pass the assertion above and be
	// indistinguishable from a correct one.
	po.PolicyStatements["A"] = mk("A")
	po.PolicyStatements["B"] = mk("B")
	fc.BGP.Neighbors[0].Import = []string{"A", "B"}
	if err := bgpComposedChainCollision(fc); err != nil {
		t.Errorf("guard fired on an ordinary composed chain: %v", err)
	}
}
