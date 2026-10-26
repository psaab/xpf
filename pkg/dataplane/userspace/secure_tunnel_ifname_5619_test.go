package userspace

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// secureTunnelIfNameCases is the classification table for the `st<N>` range
// rule (#5619).
//
// It is NOT half of a two-plane mirror any more, whatever an earlier revision
// of this comment said: it cited a Rust test `secure_tunnel_ifname_matches_go`
// that does not exist. #6691 round 5 deleted `is_secure_tunnel_ifname` from
// userspace-dp because the dataplane's question is OWNERSHIP, which only the
// control plane can answer — that plane now reads the snapshot's
// `secure_tunnel` flag. So this table pins one implementation, and its job is
// to hold IsSecureTunnelIfName to the same bounds as the XFRMIfNameAndID
// constructor it shares secureTunnelIndex with.
var secureTunnelIfNameCases = []struct {
	base string
	want bool
}{
	{"st0", true},
	{"st1", true},
	{"st9", true},
	{"st10", true},
	{"st0000", true},
	// Atoi accepts a leading sign, so `st+5` parses to index 5 and DOES yield
	// an xfrmi — both planes must classify it as a tunnel. (An earlier comment
	// here claimed XFRMIfNameAndID refuses this spelling; it does not.)
	{"st+5", true},
	// #6691 range boundary. The if_id is `stIndex<<16 | unit+1`, so an index
	// >= 0x10000 has no room and XFRMIfNameAndID builds nothing; a negative
	// index likewise. The classifier must agree, or a wildcard-authored
	// ordinary interface named `st65536` is stripped of adjudication and of
	// its AF_XDP binding — a traffic outage on a valid interface.
	{"st65535", true},
	{"st65536", false},
	{"st99999", false},
	{"st-1", false},
	{"st-3", false},
	// Not secure tunnels.
	{"st", false},
	{"stx", false},
	{"st0x", false},
	{"start0", false},
	{"", false},
	{"ge-0-0-0", false},
	{"lo0", false},
	{"fxp0", false},
	{"em0", false},
	{"fab0", false},
	{"reth0", false},
	{"gr-0-0-0", false},
}

// secureTunnelSpellings is the EDGE set for every behavioural test below.
//
// A mutation applied inside the region a guard already covers says nothing
// about that guard's BOUNDARY, and the boundary is where #5619 was wrong twice:
// first by collapsing `st0.0` onto `st0`, then — in the first cut of the fix —
// by synthesizing `st0.0` for a BARE `bind-interface st0`. Both directions of
// one defect, and a suite that only ever exercised `st0.0` could not see
// either.
//
// Every case authors a DIFFERENT bind-interface string, and the expected netdev
// is DERIVED from that string via XFRMIfNameAndID rather than hardcoded — so a
// reconstruction bug in the implementation cannot be mirrored by the same bug
// in the test.
//
// The bare/dotted pair is the load-bearing one: both derive if_id 1, yet the
// reconciler creates DIFFERENT device names for them (pkg/routing/xfrm.go).
var secureTunnelSpellings = []struct {
	name      string
	bindIface string // what the operator authors — this decides the device name
	ifName    string // the `set interfaces` stanza name
	unit      int
}{
	{name: "bare_st0", bindIface: "st0", ifName: "st0", unit: 0},
	{name: "dotted_st0_0", bindIface: "st0.0", ifName: "st0", unit: 0},
	{name: "multidigit_st10_5", bindIface: "st10.5", ifName: "st10", unit: 5},
	{name: "nonzero_unit_st0_7", bindIface: "st0.7", ifName: "st0", unit: 7},
}

// spellingConfig builds a config authoring bindIface with a matching interface
// unit, plus an ordinary LAN interface for contrast. It returns the config, the
// unit ref, and the netdev the reconciler will create — derived, never
// hardcoded.
func spellingConfig(t *testing.T, bindIface, ifName string, unit int) (*config.Config, string, string) {
	t.Helper()
	unitRef := fmt.Sprintf("%s.%d", ifName, unit)
	cfg := compileForTest5619(t,
		fmt.Sprintf("set security ipsec vpn v bind-interface %s", bindIface),
		fmt.Sprintf("set interfaces %s unit %d family inet address 10.5.5.1/30", ifName, unit),
		fmt.Sprintf("set security zones security-zone vpn interfaces %s", unitRef),
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	wantDev, ifID := config.XFRMIfNameAndID(bindIface)
	if ifID == 0 || wantDev == "" {
		t.Fatalf("premise broken: bind-interface %q resolves to no xfrm device", bindIface)
	}
	return cfg, unitRef, wantDev
}

// TestSecureTunnelIfNameClassification pins the Go half of the mirror.
func TestSecureTunnelIfNameClassification(t *testing.T) {
	for _, tc := range secureTunnelIfNameCases {
		if got := config.IsSecureTunnelIfName(tc.base); got != tc.want {
			t.Errorf("IsSecureTunnelIfName(%q) = %v, want %v", tc.base, got, tc.want)
		}
	}
}

// TestSecureTunnelClassifierAgreesWithConstructor is the #6691 SSOT guard, and
// the reason the range now lives in one place.
//
// The classifier (IsSecureTunnelIfName) and the constructor (XFRMIfNameAndID)
// answer the same question and MUST NOT disagree on any name. They did: the
// classifier ran a bare Atoi, so `st-3` and `st65536` classified as secure
// tunnels while the constructor builds an xfrmi for neither. Nothing reserves
// the `st` prefix — `set interfaces st65536 ...` is an ordinary wildcard-
// authorable data interface — so the disagreement removed a live interface from
// the ingress map, the AF_XDP binding plan and the RSS allowlist.
//
// This is asserted as an EQUIVALENCE over a corpus rather than as a table of
// expected verdicts, so it cannot be satisfied by editing an expectation: the
// oracle is the constructor's own behaviour. The corpus sweeps the decade
// boundaries around 0x10000 (where the if_id's 16-bit index field runs out),
// both sign forms, and the non-numeric shapes.
func TestSecureTunnelClassifierAgreesWithConstructor(t *testing.T) {
	corpus := []string{
		"st", "st0", "st1", "st9", "st10", "st0000", "st007",
		"st+0", "st+5", "st+65535", "st+65536",
		"st-0", "st-1", "st-3", "st-65535",
		"st65534", "st65535", "st65536", "st65537", "st99999", "st1000000",
		"st9223372036854775808", // overflows int64: Atoi errors
		"stx", "st0x", "st 5", "st5 ", "start0",
		"", "s", "ge-0-0-0", "reth0", "lo0", "fxp0", "em0", "fab0", "gr-0-0-0",
	}
	var tunnels, ordinary int
	for _, base := range corpus {
		// The constructor's own verdict for this BASE name: a non-zero if_id
		// means it builds an xfrmi, which is exactly what "is a secure tunnel"
		// means.
		_, ifID := config.XFRMIfNameAndID(base)
		want := ifID != 0
		if got := config.IsSecureTunnelIfName(base); got != want {
			t.Errorf("IsSecureTunnelIfName(%q) = %v but XFRMIfNameAndID(%q) yields "+
				"if_id %d (builds a device = %v) — a classifier that disagrees with the "+
				"constructor either strips a real interface out of the dataplane or "+
				"admits a name no xfrmi exists for", base, got, base, ifID, want)
		}
		if want {
			tunnels++
		} else {
			ordinary++
		}
	}
	// A corpus that landed entirely on one side would make the equivalence
	// vacuous (both functions returning a constant would pass).
	if tunnels < 5 || ordinary < 5 {
		t.Fatalf("corpus is degenerate: %d tunnels / %d ordinary — the equivalence "+
			"proves nothing unless both verdicts are well represented", tunnels, ordinary)
	}

	// The corpus above is dot-free on purpose: the equivalence holds over the
	// classifier's DOMAIN, which is base names. A dotted string is a unit REF —
	// XFRMIfNameAndID accepts one (it splits the unit off itself) while the
	// classifier must reject it, so the two legitimately disagree there. Callers
	// split first and pass the base (SecureTunnelUnitNetdev, and the `base` local
	// in userspaceSkipsIngressInterface), so pin that a ref never sneaks through
	// as a base.
	for _, ref := range []string{"st0.0", "st0.1", "st10.5", "st.0"} {
		if config.IsSecureTunnelIfName(ref) {
			t.Errorf("IsSecureTunnelIfName(%q) = true, but it takes BASE names — a ref "+
				"reaching it unsplit means a caller skipped the split and would resolve "+
				"the unit suffix twice", ref)
		}
	}
}

// TestSecureTunnelRangeBoundsWhatCanBeOwned is the #6691 behavioural
// consequence at the EDGE of the `st<N>` range, restated for round 5's
// ownership keying.
//
// The range no longer decides what is EXCLUDED — ownership does. What the
// range still decides is what can be OWNED AT ALL: `XFRMIfNameAndID` builds an
// if_id only for an index in [0, 65536), so an out-of-range name resolves to
// if_id 0 and `SecureTunnelNetdevForRef` refuses it even when an operator
// authors it verbatim as a `bind-interface`. That is the coherent version of
// the old rationale, which justified the 0x10000 bound with "names are
// wildcard-authorable and nothing reserves `st`" — an argument equally true of
// `st5`, and therefore an argument against keying on the name at all.
//
// The 2x2 that matters:
//
//	in range  + a VPN binds it   -> a real tunnel, excluded
//	in range  + no VPN           -> an ordinary NIC, adjudicated  <- the r5 blocker
//	out range + a VPN "binds" it -> NOT AUTHORABLE: #5297 rejects the
//	                                bind-interface at commit, so the state
//	                                cannot exist to be misclassified
//	out range + no VPN           -> an ordinary NIC, adjudicated
//
// The third row is asserted as a commit REJECTION rather than as a snapshot
// verdict, which is a stronger statement than the old test made: an
// out-of-range name cannot be owned because it cannot be authored as a
// bind-interface at all.
func TestSecureTunnelRangeBoundsWhatCanBeOwned(t *testing.T) {
	for _, base := range []string{"st65535", "st65536", "st-3", "st+5"} {
		for _, bound := range []bool{true, false} {
			label := base + "/unbound"
			if bound {
				label = base + "/bound"
			}
			t.Run(label, func(t *testing.T) {
				_, ifID := config.XFRMIfNameAndID(base)
				inRange := ifID != 0
				lines := []string{
					fmt.Sprintf("set interfaces %s unit 0 family inet address 192.0.2.1/24", base),
					fmt.Sprintf("set security zones security-zone trust interfaces %s.0", base),
				}
				if bound {
					lines = append([]string{
						fmt.Sprintf("set security ipsec vpn v bind-interface %s", base),
					}, lines...)
				}

				if bound && !inRange {
					// The state is not authorable: #5297 refuses an
					// out-of-range bind-interface at commit. Assert THAT,
					// rather than compiling a config the product rejects.
					if _, err := compileMayFail5619(lines...); err == nil {
						t.Fatalf("commit ACCEPTED bind-interface %q, which resolves to no "+
							"XFRM interface — the route-based VPN would commit and carry "+
							"no traffic", base)
					}
					return
				}
				cfg := compileForTest5619(t, lines...)

				// Ownership is only POSSIBLE in range; that is the whole role
				// the range now plays.
				_, canBeOwned := cfg.SecureTunnelNetdevForRef(base + ".0")
				if canBeOwned != (bound && inRange) {
					t.Fatalf("premise broken: ownership=%v for bound=%v inRange=%v",
						canBeOwned, bound, inRange)
				}

				var row InterfaceSnapshot
				var found bool
				for _, r := range buildInterfaceSnapshots(cfg) {
					if r.Name == base+".0" {
						row, found = r, true
					}
				}
				if !found {
					t.Fatalf("premise broken: no %s.0 row in the snapshot", base)
				}

				wantSkip := canBeOwned
				if got := userspaceSkipsIngressInterface(row); got != wantSkip {
					t.Errorf("userspaceSkipsIngressInterface(%s.0) = %v, want %v — the "+
						"exclusion follows OWNERSHIP; the range only bounds which names "+
						"an if_id can exist for", base, got, wantSkip)
				}
			})
		}
	}
}

// TestSecureTunnelAddsNothingToTheAdjudicatedSets proves the claim this change
// actually supports: adding a route-based IPsec tunnel does not change which
// interfaces the dataplane ADJUDICATES.
//
// A DIFFERENTIAL: the same config is compiled twice, with and without the VPN
// and its zoned tunnel, and the ingress-adjudication set must be identical.
//
// SCOPE, deliberately narrow. This is NOT a claim that every snapshot-derived
// set is byte-identical to the pre-#5619 world — it is not, and the PR body
// says so. The RSS allowlist correctly LOSES a bogus `st0` entry that the name
// bug had put there (it is keyed by name with no ifindex guard, so the
// "excluded by accident via ifindex 0" story never applied to it), and several
// ungated consumers now see the tunnel's real ifindex/MTU/addresses. Those are
// assessed separately in the PR. What this pins is the adjudication boundary.
func TestSecureTunnelAddsNothingToTheAdjudicatedSets(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, unitRef, wantDev := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)
			restore := stubLinkSnapshot5619(t, map[string]int{wantDev: 42, "ge-0-0-0": 11})
			defer restore()

			lanOnly := compileForTest5619(t,
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			)

			snaps := buildInterfaceSnapshots(cfg)
			var resolved bool
			for _, s := range snaps {
				if s.Name == unitRef && s.LinuxName == wantDev && s.Ifindex == 42 {
					resolved = true
				}
			}
			if !resolved {
				t.Fatalf("premise broken: %q did not resolve to %q/42; the differential "+
					"would then match for the pre-fix reason", unitRef, wantDev)
			}

			got := buildUserspaceIngressIfindexes(&ConfigSnapshot{Interfaces: snaps})
			want := buildUserspaceIngressIfindexes(&ConfigSnapshot{
				Interfaces: buildInterfaceSnapshots(lanOnly),
			})
			if !slices.Equal(got, want) {
				t.Errorf("adding a route-based IPsec tunnel CHANGED the ingress-adjudication "+
					"set: with tunnel %v, without %v", got, want)
			}
			if !slices.Equal(got, []uint32{11}) {
				t.Errorf("ingress set = %v, want [11] (the LAN netdev alone)", got)
			}
		})
	}
}

// TestSecureTunnelNonTunnelStNamesStayAdjudicated is the counterpart scope
// check: names that merely START with "st" are NOT secure tunnels and must keep
// being adjudicated. Without this, "scope the claim" could be satisfied by an
// over-broad prefix match that silently drops a real data interface out of the
// dataplane — a far worse failure than the gap being fixed.
func TestSecureTunnelNonTunnelStNamesStayAdjudicated(t *testing.T) {
	for _, name := range []string{"stx", "start0"} {
		t.Run(name, func(t *testing.T) {
			snap := InterfaceSnapshot{
				Name: name + ".0", LinuxName: name, Zone: "trust", Ifindex: 11,
			}
			if userspaceSkipsIngressInterface(snap) {
				t.Errorf("%q was excluded from the dataplane; only st<N> with a numeric N "+
					"is a secure tunnel, and over-matching silently drops a real data "+
					"interface out of adjudication", snap.Name)
			}
		})
	}
}

// TestSecureTunnelUnitReportsMTUAndAddresses covers the user-visible half of
// this change, which otherwise would ride along unasserted.
//
// Because the unit resolved to a netdev that does not exist, buildLinkSnapshot
// missed and the secure-tunnel unit reported MTU 0 and no live addresses in
// every snapshot consumer (status output, the CLI, the host-inbound view).
// Asserted across every spelling, so it binds the real device rather than
// merely "the name changed".
func TestSecureTunnelUnitReportsMTUAndAddresses(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, unitRef, wantDev := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)

			prev := buildLinkSnapshot
			defer func() { buildLinkSnapshot = prev }()
			// #6691 r6: the LIVE address must differ from the CONFIGURED one.
			// This stub used to return 10.5.5.1/30 — the same value
			// spellingConfig authors — and production merges the configured
			// address into the row, so the assertion below held whether or not
			// the live lookup resolved. A fixture true by construction cannot
			// detect the defect it was written for. 10.5.5.2/30 can only reach
			// the row through buildLinkSnapshot.
			buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
				if name == wantDev {
					return 42, 1400, "", []InterfaceAddressSnapshot{
						{Family: "inet", Address: "10.5.5.2/30"},
					}
				}
				return 0, 0, "", nil
			}

			var found bool
			for _, s := range buildInterfaceSnapshots(cfg) {
				if s.Name != unitRef {
					continue
				}
				found = true
				if s.MTU != 1400 {
					t.Errorf("%s MTU = %d, want 1400 — the unit reported MTU 0 because it "+
						"resolved to a netdev that does not exist", unitRef, s.MTU)
				}
				var live bool
				for _, addr := range s.Addresses {
					if addr.Address == "10.5.5.2/30" {
						live = true
					}
				}
				if !live {
					t.Errorf("%s addresses = %v, want the LIVE 10.5.5.2/30 — which only "+
						"buildLinkSnapshot can supply, so its absence means the unit "+
						"resolved to a netdev the lookup missed", unitRef, s.Addresses)
				}
			}
			if !found {
				t.Fatalf("premise broken: no %q unit in the snapshot", unitRef)
			}
		})
	}
}

// connectedPrefixInputs mirrors, in Go, the gate the Rust dataplane applies to
// the interface rows this package ships: `populate_interfaces` skips a row on
// `if iface.ifindex <= 0 { continue }` and pushes ONE connected route per
// address of every row that survives
// (userspace-dp/src/afxdp/forwarding_build/interfaces.rs). The returned set is
// therefore the exact input from which the FIB derives `connected_v4` — and
// `infer_connected_route_target_v4` resolves a static route's gateway against
// nothing else.
//
// Returned as a SET rather than a list because a base row and its unit-0 row
// legitimately carry the same (ifindex, address) pair under some spellings and
// collapse to one connected prefix downstream.
func connectedPrefixInputs(snaps []InterfaceSnapshot) map[string]bool {
	out := map[string]bool{}
	for _, s := range snaps {
		if s.Ifindex <= 0 {
			continue
		}
		for _, a := range s.Addresses {
			out[fmt.Sprintf("%d|%s", s.Ifindex, a.Address)] = true
		}
	}
	return out
}

// TestSecureTunnelSpellingsAgreeOnForwardingInputs is the guard for the
// FORWARDING half of #5619 — the half the name fix moves and the earlier
// analysis of this change got wrong.
//
// Every spelling below describes ONE tunnel: `bind-interface st0` and
// `bind-interface st0.0` derive the same XFRM if_id and the same unit ref
// `st0.0`. They must therefore hand the dataplane the same forwarding inputs.
// Before the fix they did not, and the consequence was a DISPOSITION SPLIT
// measured end to end (real Go wire snapshot -> real Rust FIB) for a LAN->tunnel
// flow via a gateway inside the tunnel subnet:
//
//	bind-interface st0    -> MissingNeighbor
//	bind-interface st0.0  -> NoRoute
//
// `NoRoute` is slow-path eligible and reinjects unconditionally; the
// `MissingNeighbor` arm runs its OWN zone-policy evaluation and a deny exits
// before the reinject gate. So the same tunnel, spelled two ways, either
// enforced zone policy on LAN->tunnel transit or bypassed it into the kernel.
//
// What is asserted, and why each half is load-bearing:
//
//   - PER SPELLING, the unit row must clear the `ifindex > 0` gate AND carry
//     the tunnel address. Both are required for the connected prefix to exist;
//     asserting only the cross-spelling equality below would MISS the
//     round-1 reconstruction bug, because under it the BARE spelling's base
//     `st0` row still resolves to ifindex 42 with the same address and holds
//     the set equal while the UNIT row silently reads 0.
//   - ACROSS SPELLINGS, the derived connected-prefix input set must be
//     identical. This is the convergence claim itself, and it is what fails
//     under the original unit-0 collapse.
func TestSecureTunnelSpellingsAgreeOnForwardingInputs(t *testing.T) {
	var reference map[string]bool
	var referenceName string
	for _, tc := range secureTunnelSpellings {
		cfg, unitRef, wantDev := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)
		prev := buildLinkSnapshot
		buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
			switch name {
			case wantDev:
				return 42, 1400, "", []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.5.5.1/30"},
				}
			case "ge-0-0-0":
				return 11, 1500, "02:00:00:00:00:01", []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.1.1/24"},
				}
			}
			return 0, 0, "", nil
		}
		snaps := buildInterfaceSnapshots(cfg)
		buildLinkSnapshot = prev

		var unitRow *InterfaceSnapshot
		for i := range snaps {
			if snaps[i].Name == unitRef {
				unitRow = &snaps[i]
			}
		}
		if unitRow == nil {
			t.Fatalf("%s: premise broken: no %q row in the snapshot", tc.name, unitRef)
		}
		// The `ifindex > 0` gate. A unit row that fails it contributes NO
		// connected prefix, and a LAN->tunnel route via a gateway in the
		// tunnel subnet then resolves NoRoute instead of MissingNeighbor —
		// reinjected to the kernel with the zone policy unevaluated.
		if unitRow.Ifindex <= 0 {
			t.Errorf("%s (bind-interface %s): %s Ifindex = %d; the row is skipped by "+
				"populate_interfaces, so the tunnel contributes no connected prefix and "+
				"LAN->tunnel transit resolves NoRoute (kernel reinject, zone policy "+
				"bypassed) instead of MissingNeighbor",
				tc.name, tc.bindIface, unitRef, unitRow.Ifindex)
		}
		var carriesTunnelAddr bool
		for _, a := range unitRow.Addresses {
			if a.Address == "10.5.5.1/30" {
				carriesTunnelAddr = true
			}
		}
		if !carriesTunnelAddr {
			t.Errorf("%s (bind-interface %s): %s addresses = %v, want the tunnel address "+
				"10.5.5.1/30 — without it the row yields no connected prefix even at a "+
				"resolved ifindex", tc.name, tc.bindIface, unitRef, unitRow.Addresses)
		}

		got := connectedPrefixInputs(snaps)
		if reference == nil {
			reference, referenceName = got, tc.name
			continue
		}
		if !maps.Equal(got, reference) {
			t.Errorf("connected-prefix inputs differ between spellings %q and %q: %v vs %v "+
				"— these spell the SAME tunnel (same if_id, same unit ref), so a difference "+
				"here means the two take different FIB dispositions for identical config",
				referenceName, tc.name, reference, got)
		}
	}
	if reference == nil {
		t.Fatal("premise broken: no spelling was exercised")
	}
	if !reference["42|10.5.5.1/30"] {
		t.Errorf("premise broken: the tunnel prefix never entered the connected-prefix "+
			"inputs at all (%v); this test would then pass vacuously", reference)
	}
}

// TestSecureTunnelNetdevForRefFailsClosedUnderCollision pins the tolerant-load
// path to the SAME contract pkg/routing enforces.
//
// #6691: an earlier revision of this test required the opposite — it asserted
// that a colliding pair resolves to the lexicographically smallest name, "for
// determinism". That pinned a defect. Two DISTINCT bind-interface strings
// deriving one if_id (`st0` and `st0.0` both yield if_id 1) are rejected at
// commit (#2933) and refused at apply, where pkg/routing/xfrm.go deletes BOTH
// from its desired set — "refusing to create either (cross-VPN leak / EEXIST
// risk)". So on a box in that state NEITHER device exists, and a resolver that
// names one anyway is not deterministic-and-correct, it is deterministically
// WRONG: it attaches forwarding state to a device the reconciler has guaranteed
// is absent. Determinism was the wrong property; agreeing with routing is the
// right one.
//
// The tolerant-load path is exactly the path that matters, since strict commit
// never produces this config.
func TestSecureTunnelNetdevForRefFailsClosedUnderCollision(t *testing.T) {
	// PREMISE: the two spellings really do collide on one if_id. If they ever
	// stopped colliding, the fail-closed assertion below would pass vacuously.
	nameA, idA := config.XFRMIfNameAndID("st0.0")
	nameB, idB := config.XFRMIfNameAndID("st0")
	if idA == 0 || idA != idB || nameA == nameB {
		t.Fatalf("premise broken: expected distinct names sharing one if_id, got "+
			"%q/%d and %q/%d", nameA, idA, nameB, idB)
	}

	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"a": {Name: "a", BindInterface: "st0.0"},
		"b": {Name: "b", BindInterface: "st0"},
	}
	// Repeated: a map-order-dependent implementation could fail closed on one
	// iteration order and resolve on another.
	for i := 0; i < 50; i++ {
		// #6691 r6: BOTH halves of the documented contract. Checking only
		// `ok` let a hypothetical ("st0", false) return pass — the doc
		// promises the name is empty too, and a caller that reads the name
		// without checking ok would then attach forwarding state to a device
		// pkg/routing has guaranteed is absent.
		if got, ok := cfg.SecureTunnelNetdevForRef("st0.0"); ok || got != "" {
			t.Fatalf("SecureTunnelNetdevForRef = (%q, %v) under an if_id collision, want "+
				"(\"\", false); pkg/routing creates NEITHER colliding device, so no name "+
				"is correct here (iteration %d)", got, ok, i)
		}
	}

	// Two VPNs authoring the SAME string are NOT a collision — one name, one
	// device — and routing programs it. Fail-closed must not swallow this.
	same := &config.Config{}
	same.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"a": {Name: "a", BindInterface: "st0.0"},
		"b": {Name: "b", BindInterface: "st0.0"},
	}
	got, ok := same.SecureTunnelNetdevForRef("st0.0")
	if !ok || got != nameA {
		t.Errorf("SecureTunnelNetdevForRef = %q (ok=%v) for two VPNs on the SAME "+
			"bind-interface, want %q — that is one device, not a collision, and routing "+
			"programs it", got, ok, nameA)
	}
}

// TestSecureTunnelUnitNetdevFallsBackUnderCollision pins what the SHARED
// resolver returns once the lookup fails closed: the verbatim dotted ref, which
// names no device on a box where routing refused to create either colliding
// xfrmi — NOT the unit-zero collapse onto `st0`, which is precisely the name
// the other half of the colliding pair asked for.
func TestSecureTunnelUnitNetdevFallsBackUnderCollision(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"a": {Name: "a", BindInterface: "st0.0"},
		"b": {Name: "b", BindInterface: "st0"},
	}
	got, ok := cfg.SecureTunnelUnitNetdev("st0.0")
	if !ok {
		t.Fatal("SecureTunnelUnitNetdev refused a secure-tunnel unit ref outright; " +
			"ok=false means `not a secure tunnel` and would send every caller into the " +
			"unit-zero collapse this fix exists to bypass")
	}
	if got != "st0.0" {
		t.Errorf("SecureTunnelUnitNetdev(%q) = %q, want %q — under a collision routing "+
			"creates neither device, so the ref itself is the honest answer",
			"st0.0", got, "st0.0")
	}
}

// --- helpers -------------------------------------------------------------

// compileForTest5619 runs the REAL parser + compiler so these tests exercise
// the deployed config path rather than a hand-built Config literal.
// compileMayFail5619 is compileForTest5619 for cases where the REJECTION is the
// assertion: it returns the compile error instead of failing the test.
func compileMayFail5619(lines ...string) (*config.Config, error) {
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			return nil, err
		}
		if err := tree.SetPath(path); err != nil {
			return nil, err
		}
	}
	return config.CompileConfig(tree)
}

// compileForTest5619 compiles a strict fixture. Snapshot-only fixtures may
// omit IPsec authentication details; a missing PSK gets a fixture key, and a
// missing gateway gets an addressed fixture gateway so a synthetic PSK has a
// peer scope under #15989. Authored key/gateway values are retained; only
// missing fixture details are synthesized here.
func compileForTest5619(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	all := append([]string(nil), lines...)
	boundVPNs := make([]string, 0)
	bound := make(map[string]bool)
	hasKey := make(map[string]bool)
	hasGateway := make(map[string]bool)
	for _, line := range all {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "set" || fields[1] != "security" ||
			fields[2] != "ipsec" || fields[3] != "vpn" {
			continue
		}
		vpn := fields[4]
		switch fields[5] {
		case "bind-interface":
			if !bound[vpn] {
				bound[vpn] = true
				boundVPNs = append(boundVPNs, vpn)
			}
		case "pre-shared-key":
			hasKey[vpn] = true
		case "gateway":
			hasGateway[vpn] = true
		case "ike":
			if len(fields) >= 8 && fields[6] == "gateway" {
				hasGateway[vpn] = true
			}
		}
	}
	for _, vpn := range boundVPNs {
		if !hasGateway[vpn] {
			gwName := "fixture-peer-" + vpn
			all = append(all,
				"set security ike gateway "+gwName+" address 198.51.100.1",
				"set security ipsec vpn "+vpn+" ike gateway "+gwName,
			)
		}
		if !hasKey[vpn] {
			all = append(all, "set security ipsec vpn "+vpn+" pre-shared-key fixture-psk")
		}
	}
	tree := &config.ConfigTree{}
	for _, line := range all {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// stubLinkSnapshot5619 makes the named netdevs "exist" with the given
// ifindexes. Any other name resolves to ifindex 0, exactly as buildLinkSnapshot
// behaves for a device that is not on the box.
func stubLinkSnapshot5619(t *testing.T, live map[string]int) func() {
	t.Helper()
	prev := buildLinkSnapshot
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if idx, ok := live[name]; ok {
			return idx, 1500, "02:00:00:00:00:01", nil
		}
		return 0, 0, "", nil
	}
	return func() { buildLinkSnapshot = prev }
}
