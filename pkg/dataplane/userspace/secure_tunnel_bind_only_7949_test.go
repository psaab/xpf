package userspace

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7949 Shape B — a secure tunnel named ONLY through `bind-interface`.
//
// The fixtures reuse secureTunnelSpellings from secure_tunnel_ifname_5619_test.go
// on purpose: that edge set is where #5619 was wrong twice (collapsing `st0.0`
// onto `st0`, then synthesizing `st0.0` for a bare `bind-interface st0`), and a
// Shape B synthesis is the same class of name derivation one level up. Every
// expected netdev is DERIVED from the authored bind-interface string via
// config.XFRMIfNameAndID, never hardcoded, so a reconstruction bug in the
// implementation cannot be mirrored by the same bug here.

const bindOnlyTunnelIfindex7949 = 42

// shapeBConfig7949 authors bindIface with a zone reference on unitRef and NO
// `set interfaces st<N>` stanza — the shape #4515 accepts and #7949 is about.
// The LAN interface is not decoration: buildInterfaceSnapshotsFrom returns nil
// on an empty interface map for every config that has no such tunnel, and a
// fixture without it would be exercising that guard rather than the synthesis.
func shapeBConfig7949(t *testing.T, bindIface, ifName string, unit int) (*config.Config, string, string) {
	t.Helper()
	unitRef := fmt.Sprintf("%s.%d", ifName, unit)
	cfg := compileForTest5619(t,
		fmt.Sprintf("set security ipsec vpn v bind-interface %s", bindIface),
		fmt.Sprintf("set security zones security-zone vpn interfaces %s", unitRef),
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	if cfg.Interfaces.Interfaces[ifName] != nil {
		t.Fatalf("premise broken: %q has an interface stanza, so this is Shape A "+
			"and the test would pass on origin/master", ifName)
	}
	wantDev, ifID := config.XFRMIfNameAndID(bindIface)
	if ifID == 0 || wantDev == "" {
		t.Fatalf("premise broken: bind-interface %q resolves to no xfrm device", bindIface)
	}
	return cfg, unitRef, wantDev
}

// stubTunnelLink7949 makes the tunnel netdev and the LAN netdev "exist".
// Anything else resolves to ifindex 0, exactly as buildLinkSnapshot does for a
// device that is not on the box.
func stubTunnelLink7949(t *testing.T, tunnelDev string) {
	t.Helper()
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		switch name {
		case tunnelDev:
			return bindOnlyTunnelIfindex7949, 1400, "", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.5.5.1/30"},
			}
		case "ge-0-0-0":
			return 11, 1500, "02:00:00:00:00:01", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.1.1/24"},
			}
		}
		return 0, 0, "", nil
	}
}

func rowByName7949(rows []InterfaceSnapshot, name string) (InterfaceSnapshot, bool) {
	for _, r := range rows {
		if r.Name == name {
			return r, true
		}
	}
	return InterfaceSnapshot{}, false
}

// TestBindInterfaceOnlySecureTunnelReachesTheSnapshot7949 is the fail-on-revert
// cell for the defect itself.
//
// WHAT THE INSTRUMENT SAYS IF THE PROPERTY IS FALSE: on origin/master the row
// does not exist at all, so the lookup fails and the message names the ref. The
// Ifindex assertion is the one that matters for the security claim — Rust
// populate_interfaces gates on `ifindex > 0` before it populates
// name_to_ifindex / linux_to_ifindex, so a row that exists at ifindex 0 is
// invisible to resolve_ifindex and closes nothing.
//
// MUTATION: delete the appendBindInterfaceOnlySecureTunnelRows call in
// buildInterfaceSnapshotsFrom -> every spelling reds with "no row".
func TestBindInterfaceOnlySecureTunnelReachesTheSnapshot7949(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, unitRef, wantDev := shapeBConfig7949(t, tc.bindIface, tc.ifName, tc.unit)
			stubTunnelLink7949(t, wantDev)

			rows := buildInterfaceSnapshots(cfg)
			row, ok := rowByName7949(rows, unitRef)
			if !ok {
				var names []string
				for _, r := range rows {
					names = append(names, r.Name)
				}
				t.Fatalf("no snapshot row for %q (bind-interface %q, netdev %q); rows = %v.\n"+
					"A `bind-interface`-only tunnel never reaches snapshot.Interfaces, so Rust "+
					"resolve_ifindex misses on both name maps, the interface-only next hop "+
					"collapses to ifindex 0 and the flow is NoRoute -> slow-path reinject: the "+
					"kernel forwards it with no zone policy, session, NAT or screen (#7949)",
					unitRef, tc.bindIface, wantDev, names)
			}
			if row.LinuxName != wantDev {
				t.Errorf("row %q LinuxName = %q, want %q — the netdev must be read back from "+
					"the AUTHORED bind-interface string, not reconstructed from the ref",
					unitRef, row.LinuxName, wantDev)
			}
			if row.Ifindex != bindOnlyTunnelIfindex7949 {
				t.Errorf("row %q Ifindex = %d, want %d. A row at ifindex 0 is skipped by "+
					"populate_interfaces before it reaches name_to_ifindex, so it closes nothing",
					unitRef, row.Ifindex, bindOnlyTunnelIfindex7949)
			}
			if row.Zone != "vpn" {
				t.Errorf("row %q Zone = %q, want \"vpn\"", unitRef, row.Zone)
			}
			// R3: the flag that classifies this row must be DERIVED, and true.
			// A row appended outside the builder loop defaults it to false,
			// which escapes both netdevExclusionClasses entries and drags the
			// row into every set the enumeration classified as skipped.
			if !row.SecureTunnel {
				t.Errorf("row %q SecureTunnel = false — it escapes BOTH exclusion classes "+
					"(Tunnel is stanza-derived and also false), so every consumer documented "+
					"as skipping a secure tunnel admits it (#7949 R3)", unitRef)
			}
			// #6722: without an EgressZone the row cannot claim an egress zone
			// in the helper (the claim requires corroboration from a row whose
			// `zone` equals the claimed `egress_zone`), and an egress zone of 0
			// skips every policy tier — the row would exist and adjudicate
			// nothing.
			if row.EgressZone != "vpn" {
				t.Errorf("row %q EgressZone = %q, want \"vpn\" — a row with no egress zone "+
					"resolves to the 0 sentinel, which skips every rule tier including "+
					"`from-zone any to-zone any`, so the row would be adjudication-inert",
					unitRef, row.EgressZone)
			}
		})
	}
}

// TestUnzonedBindInterfaceOnlyTunnelGetsNoRow7949 pins R1 as a PROPERTY.
//
// The issue requires the zone to be authored in the same change that creates
// the row. Here that is structural: the synthesis iterates authoredZoneRefs, so
// a tunnel the operator never zoned cannot produce a row.
//
// MUTATION: drive the synthesis off cfg.Security.IPsec.VPNs instead of the
// authored zone refs — the obvious "just make every tunnel visible" design —
// and this reds.
func TestUnzonedBindInterfaceOnlyTunnelGetsNoRow7949(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	wantDev, _ := config.XFRMIfNameAndID("st0.0")
	stubTunnelLink7949(t, wantDev)

	rows := buildInterfaceSnapshots(cfg)
	// Vacuity guard: the builder must have run and produced the LAN row, or
	// "no tunnel row" would be true for the wrong reason.
	if _, ok := rowByName7949(rows, "ge-0/0/0.0"); !ok {
		t.Fatal("the LAN row is missing — the builder did not run, so the absence " +
			"asserted below proves nothing")
	}
	for _, r := range rows {
		if r.LinuxName == wantDev || strings.HasPrefix(r.Name, "st0") {
			t.Fatalf("an UNZONED bind-interface-only tunnel produced row %+v. The row must "+
				"be created only alongside an authored zone: an unzoned row adjudicates "+
				"nothing (egress zone 0 skips every rule tier and falls to the default "+
				"action, exactly where today's NoRoute path already lands) while still "+
				"moving the flow off the kernel path (#7949 R1)", r)
		}
	}
}

// TestBindOnlyTunnelRowMatchesTheStanzaSpelling7949 IS the per-consumer
// decision, expressed once.
//
// #7949 asks for a stated intent per consumer rather than a side effect. The
// intent is one sentence: the two spellings of one tunnel must behave
// identically. Shape A — the same `bind-interface` WITH a `set interfaces`
// stanza — already produces this row and has since #5619, so every consumer's
// disposition toward it is shipped, reviewed behaviour. Asserting the AGREEMENT
// rather than a table of hand-written expectations means the answer cannot
// drift away from the one that is actually in production, and no consumer can
// change behaviour "by accident" without changing Shape A too.
//
// MUTATION: change any stamped field on the synthesized row (SecureTunnel to a
// literal false, LinuxName to the ref instead of the device, Zone dropped) and
// this reds naming the field.
func TestBindOnlyTunnelRowMatchesTheStanzaSpelling7949(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfgB, unitRef, wantDev := shapeBConfig7949(t, tc.bindIface, tc.ifName, tc.unit)
			cfgA, unitRefA, wantDevA := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)
			if unitRefA != unitRef || wantDevA != wantDev {
				t.Fatalf("fixture mismatch: A(%q,%q) vs B(%q,%q) are not the same tunnel",
					unitRefA, wantDevA, unitRef, wantDev)
			}

			stubTunnelLink7949(t, wantDev)
			rowsA := buildInterfaceSnapshots(cfgA)
			rowsB := buildInterfaceSnapshots(cfgB)

			rowA, okA := rowByName7949(rowsA, unitRef)
			rowB, okB := rowByName7949(rowsB, unitRef)
			if !okA {
				t.Fatalf("Shape A has no %q row — the ORACLE is missing, so the comparison "+
					"below would be between two zero values", unitRef)
			}
			if !okB {
				t.Fatalf("Shape B has no %q row (#7949 unfixed)", unitRef)
			}
			// Vacuity guards on the oracle. A parity assertion between two rows
			// that are both inert would pass while proving nothing.
			if !rowA.SecureTunnel || rowA.Ifindex == 0 || rowA.Zone == "" || rowA.EgressZone == "" {
				t.Fatalf("Shape A's %q row is inert (%+v) — parity with it is not evidence",
					unitRef, rowA)
			}

			if !reflect.DeepEqual(rowA, rowB) {
				t.Errorf("the two spellings of ONE tunnel produce different rows.\n"+
					"  with `set interfaces` stanza: %+v\n"+
					"  bind-interface only:          %+v\n"+
					"Every consumer of snapshot.Interfaces reads these fields; a difference "+
					"here is a consumer behaving differently for two configs that describe "+
					"the same device (#7949).", rowA, rowB)
			}

			// The one DELIBERATE difference, asserted rather than left to be
			// discovered: Shape A also emits a BASE row, and Shape B does not.
			// That row is a stanza artifact — interfaces.go records that under
			// `bind-interface st0.0` the base `st0` reports SecureTunnel false
			// and "contributes its name to the name-keyed AF_XDP/RSS allowlist
			// even though no `st0` netdev exists". Not reproducing it is the
			// better half of the asymmetry, so it is stated here.
			_, baseInA := rowByName7949(rowsA, tc.ifName)
			_, baseInB := rowByName7949(rowsB, tc.ifName)
			if !baseInA && tc.bindIface != tc.ifName {
				t.Errorf("Shape A no longer emits the %q base row; this assertion's premise "+
					"has changed and the asymmetry below is no longer the one described",
					tc.ifName)
			}
			if baseInB {
				t.Errorf("Shape B emitted a %q BASE row as well as the unit row. Two rows for "+
					"one tunnel contend for one ifindex, which the helper's per-ifindex "+
					"egress-zone claim treats as a CONFLICT and resolves by unzoning the "+
					"whole ifindex", tc.ifName)
			}
		})
	}
}

func TestBindOnlyTunnelRowCarriesCoSFields11788(t *testing.T) {
	cfgB, unitRef, wantDev := shapeBConfig7949(t, "st0.0", "st0", 0)
	cfgA, unitRefA, wantDevA := spellingConfig(t, "st0.0", "st0", 0)
	if unitRefA != unitRef || wantDevA != wantDev {
		t.Fatalf("fixture mismatch: Shape A (%q, %q), Shape B (%q, %q)",
			unitRefA, wantDevA, unitRef, wantDev)
	}
	stubTunnelLink7949(t, wantDev)

	wantCoS := config.CoSInterfaceUnit{
		Unit:                              0,
		ShapingRateBytes:                  3_000_000_000,
		BurstSizeBytes:                    12_345,
		SchedulerMap:                      "vpn-egress",
		DSCPClassifier:                    "vpn-dscp",
		IEEE8021Classifier:                "vpn-dot1p",
		INetPrecedenceClassifier:          "vpn-precedence",
		DSCPRewriteRule:                   "vpn-rewrite",
		OversubscriptionPolicy:            "guarantee-rate",
		OversubscriptionGuaranteeFraction: 0.35,
		PriorityLowMinShareBytes:          456_789,
	}
	addCoS := func(cfg *config.Config) {
		unit := wantCoS
		cfg.ClassOfService = &config.ClassOfServiceConfig{
			Interfaces: map[string]*config.CoSInterface{
				"st0": {
					Name: "st0",
					Units: map[int]*config.CoSInterfaceUnit{
						0: &unit,
					},
				},
			},
		}
	}
	addCoS(cfgA)
	addCoS(cfgB)

	rowsA := buildInterfaceSnapshots(cfgA)
	rowsB := buildInterfaceSnapshots(cfgB)
	rowA, okA := rowByName7949(rowsA, unitRef)
	rowB, okB := rowByName7949(rowsB, unitRef)
	if !okA || !okB {
		t.Fatalf("missing comparison row: Shape A=%t, Shape B=%t", okA, okB)
	}
	snapshotCoS := func(row InterfaceSnapshot) config.CoSInterfaceUnit {
		return config.CoSInterfaceUnit{
			ShapingRateBytes:                  row.CoSShapingRateBytesPerSec,
			BurstSizeBytes:                    row.CoSBurstSize,
			SchedulerMap:                      row.CoSSchedulerMap,
			DSCPClassifier:                    row.CoSDSCPClassifier,
			IEEE8021Classifier:                row.CoSIEEE8021Classifier,
			INetPrecedenceClassifier:          row.CoSINetPrecedenceClassifier,
			DSCPRewriteRule:                   row.CoSDSCPRewriteRule,
			OversubscriptionPolicy:            row.CoSOversubscriptionPolicy,
			OversubscriptionGuaranteeFraction: row.CoSOversubscriptionGuaranteeFraction,
			PriorityLowMinShareBytes:          row.CoSPriorityLowMinShareBytes,
		}
	}
	for _, tc := range []struct {
		name string
		row  InterfaceSnapshot
	}{{"Shape A", rowA}, {"Shape B", rowB}} {
		if got := snapshotCoS(tc.row); !reflect.DeepEqual(got, wantCoS) {
			t.Errorf("%s CoS fields = %#v, want %#v", tc.name, got, wantCoS)
		}
	}
	if !reflect.DeepEqual(rowA, rowB) {
		t.Errorf("CoS-configured tunnel rows differ:\n  Shape A: %+v\n  Shape B: %+v", rowA, rowB)
	}
}

// TestBindOnlyTunnelConsumerDispositions7949 states the disposition of each
// production consumer of snapshot.Interfaces for the new row.
//
// The set and the split are from the merged enumeration
// (docs/research/7167-tunnel-ingress/7949-consumer-enumeration.md): every
// consumer either consults userspaceSkipsIngressInterface — in which case a row
// with SecureTunnel set is skipped — or it does not. These assertions pin which
// side each lands on, so a future change to the exclusion classes cannot move a
// consumer across the line silently.
//
// MUTATION: set SecureTunnel to a literal false on the synthesized row. The
// three "skipped" assertions all red at once, which is the enumeration's own
// finding (R3) reproduced as a failure.
func TestBindOnlyTunnelConsumerDispositions7949(t *testing.T) {
	cfg, unitRef, wantDev := shapeBConfig7949(t, "st0.0", "st0", 0)
	stubTunnelLink7949(t, wantDev)
	snap := &ConfigSnapshot{Interfaces: buildInterfaceSnapshots(cfg)}
	row, ok := rowByName7949(snap.Interfaces, unitRef)
	if !ok {
		t.Fatal("no tunnel row — every disposition below would be vacuous")
	}

	// SKIPPED — the ingress-adjudication ifindex set. An xfrmi has no path to
	// hand a frame back in for the egress direction, so it is not AF_XDP-bound.
	for _, ifx := range buildUserspaceIngressIfindexes(snap) {
		if int(ifx) == row.Ifindex {
			t.Errorf("the tunnel ifindex %d entered the ingress-adjudication set; the "+
				"AF_XDP shim would be attached to an xfrmi", row.Ifindex)
		}
	}

	// SKIPPED — the name-keyed AF_XDP/RSS allowlist.
	for _, name := range UserspaceBoundLinuxInterfaces(cfg) {
		if name == wantDev {
			t.Errorf("the tunnel netdev %q entered the AF_XDP/RSS allowlist", wantDev)
		}
	}

	// SKIPPED — the binding plan key. Adding the row must not churn the plan:
	// a full binding reconcile on a commit that changes no binding is the
	// consequence #7949's table predicted, and the Go implementation filters.
	withoutRow := &ConfigSnapshot{}
	for _, r := range snap.Interfaces {
		if r.Name != unitRef {
			withoutRow.Interfaces = append(withoutRow.Interfaces, r)
		}
	}
	if len(withoutRow.Interfaces) == len(snap.Interfaces) {
		t.Fatal("the control snapshot is identical to the subject — the row was never removed")
	}
	if got, want := snapshotBindingPlanKey(snap), snapshotBindingPlanKey(withoutRow); got != want {
		t.Errorf("the tunnel row changed the binding plan key:\n  with: %s\n  without: %s\n"+
			"Every commit would then run a full binding reconcile for a row that produces "+
			"no binding candidate", got, want)
	}

	// PARTICIPATES — local-address entries. The tunnel's own address is a
	// local address of this box, and the loop has no exclusion filter. This is
	// the disposition Shape A already has.
	var sawTunnelAddr bool
	for _, e := range buildLocalAddressEntries(snap) {
		if e.v4 && e.v4Key == 0x0a050501 { // 10.5.5.1
			sawTunnelAddr = true
		}
	}
	if !sawTunnelAddr {
		t.Errorf("the tunnel's own address 10.5.5.1 is not a local-delivery entry; " +
			"traffic addressed to the firewall's tunnel endpoint would not be classified " +
			"as local")
	}

	// DOES NOT PARTICIPATE — HA owner-RG resolution. A stanza-less tunnel
	// authors no `redundancy-group` and has no RETH parent, so its RG is 0 and
	// resolveOwnerRGFromZone's `RedundancyGroup > 0` gate skips it. Stated as a
	// DECISION: the tunnel does not own its zone's redundancy group.
	if row.RedundancyGroup != 0 {
		t.Errorf("tunnel row RedundancyGroup = %d, want 0", row.RedundancyGroup)
	}
	if rg := resolveOwnerRGFromZone(snap, "vpn"); rg != 0 {
		t.Errorf("resolveOwnerRGFromZone(vpn) = %d, want 0 — the tunnel must not win the "+
			"first-wins owner-RG race for its zone", rg)
	}
}

// TestBindOnlyTunnelIfIDCollisionGetsNoRow7949 pins the fail-closed inheritance.
//
// Two DISTINCT bind-interface spellings deriving one if_id make
// pkg/routing/xfrm.go create NEITHER device, and SecureTunnelNetdevForRef
// reports that by refusing to name a winner. Gating the row on that resolver
// means a colliding config gets no row rather than a row naming a device that
// is guaranteed absent.
//
// MUTATION: gate on SecureTunnelUnitNetdev instead, which returns the verbatim
// ref under a collision — the row then appears with a netdev on no box.
func TestBindOnlyTunnelIfIDCollisionGetsNoRow7949(t *testing.T) {
	// The TOLERANT path deliberately, not compileForTest5619: strict commit
	// hard-rejects an if_id collision (#2933) and apply refuses it (#2909), so
	// the only way a colliding config reaches the snapshot builder at all is
	// the lenient load / peer-sync path. A fixture built through the strict
	// compiler would fail on the config, never reach the builder, and prove
	// nothing about what the builder does with one.
	cfg := lenientConfig7949(t,
		"set security ipsec vpn a bind-interface st0",
		"set security ipsec vpn b bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	if _, ok := cfg.SecureTunnelNetdevForRef("st0.0"); ok {
		t.Fatal("premise broken: this config is supposed to be an if_id collision, " +
			"so the resolver must refuse to name a device")
	}
	stubTunnelLink7949(t, "st0.0")

	rows := buildInterfaceSnapshots(cfg)
	if _, ok := rowByName7949(rows, "ge-0/0/0.0"); !ok {
		t.Fatal("the LAN row is missing — the builder did not run")
	}
	for _, r := range rows {
		if strings.HasPrefix(r.Name, "st0") {
			t.Errorf("an if_id COLLISION produced row %+v. Routing creates neither device "+
				"for a collision, so the row names a netdev guaranteed absent", r)
		}
	}
}

// TestBindOnlyTunnelEmitsOneRowPerDevice7949 covers the shape where BOTH the
// base and the unit ref are zoned for one tunnel.
//
// Under `bind-interface st0` both `st0` and `st0.0` resolve to the netdev
// `st0`. Two rows on one ifindex is not a cosmetic duplicate: the helper merges
// the Go-stamped egress zone per ifindex and any disagreement is sticky, which
// unzones the egress for the whole ifindex — including, on a shared ifindex,
// for a pre-existing interface.
//
// MUTATION: drop the device dedup (haveDev) and two rows appear.
func TestBindOnlyTunnelEmitsOneRowPerDevice7949(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set security zones security-zone vpn interfaces st0",
		"set security zones security-zone vpn interfaces st0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	wantDev, _ := config.XFRMIfNameAndID("st0")
	stubTunnelLink7949(t, wantDev)

	rows := buildInterfaceSnapshots(cfg)
	var onDev []string
	for _, r := range rows {
		if r.LinuxName == wantDev {
			onDev = append(onDev, r.Name)
		}
	}
	sort.Strings(onDev)
	if len(onDev) != 1 {
		t.Fatalf("%d rows claim netdev %q (%v), want exactly 1. Rows sharing an ifindex "+
			"must carry an identical egress zone or the helper's per-ifindex claim goes "+
			"Conflicting and the ifindex loses its egress zone entirely", len(onDev), wantDev, onDev)
	}
	if _, ok := rowByName7949(rows, "ge-0/0/0.0"); !ok {
		t.Fatal("the LAN row is missing — the builder did not run")
	}
}

// TestShapeAIsUnchangedByTheShapeBSynthesis7949 is the no-regression half.
//
// The claim is NOT "one row per netdev" — Shape A legitimately puts two rows on
// one netdev, because snapshotLinuxName collapses a non-VLAN unit 0 onto its
// base device (`bind-interface st0` gives base `st0` and unit `st0.0`, both on
// netdev `st0`). The claim is that the synthesis ADDS NOTHING to a config that
// already has its stanza: every emitted row name must be derivable from
// cfg.Interfaces.Interfaces, which is exactly the set the builder loop emits.
//
// MUTATION: drop the `haveName[ref]` guard in the synthesis and Shape A gains a
// duplicate `st0.0` row, which this reds on.
func TestShapeAIsUnchangedByTheShapeBSynthesis7949(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, unitRef, wantDev := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)
			stubTunnelLink7949(t, wantDev)
			rows := buildInterfaceSnapshots(cfg)

			// The set of names the builder loop can emit, from the config map
			// alone. Derived, not listed: a hardcoded expectation would have to
			// be edited every time the fixture changes and would then stop
			// discriminating.
			fromConfig := map[string]bool{}
			for name, iface := range cfg.Interfaces.Interfaces {
				fromConfig[name] = true
				if iface == nil {
					continue
				}
				for unitNum := range iface.Units {
					fromConfig[fmt.Sprintf("%s.%d", name, unitNum)] = true
				}
			}
			if !fromConfig[unitRef] {
				t.Fatalf("fixture: %q is not derivable from the config map, so this is not "+
					"Shape A and the assertion below is vacuous", unitRef)
			}

			seen := map[string]int{}
			for _, r := range rows {
				seen[r.Name]++
				if !fromConfig[r.Name] {
					t.Errorf("Shape A emitted row %q, which no interface stanza names — the "+
						"Shape B synthesis added a row to a config that already had one",
						r.Name)
				}
			}
			for name, n := range seen {
				if n != 1 {
					t.Errorf("row %q appears %d times, want 1 — the synthesis duplicated a "+
						"row the builder loop already emitted", name, n)
				}
			}
		})
	}
}

// lenientConfig7949 compiles through the TOLERANT path, for fixtures strict
// commit rejects outright.
func lenientConfig7949(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestBindOnlyTunnelIsTheOnlyInterface7949 covers the config the fix would
// otherwise be correct everywhere EXCEPT: one whose only interface is the
// `bind-interface`-only tunnel itself.
//
// buildInterfaceSnapshotsFrom returns nil early on an empty
// cfg.Interfaces.Interfaces, and this shape has an empty one by definition, so
// without bindInterfaceOnlySecureTunnelRefs the synthesis would never run for
// the single config that consists of nothing but the shape it is about.
//
// MUTATION: restore the early return to `len(cfg.Interfaces.Interfaces) == 0`
// and this reds; the control below keeps the relaxation from widening what any
// other config returns.
func TestBindOnlyTunnelIsTheOnlyInterface7949(t *testing.T) {
	wantDev, _ := config.XFRMIfNameAndID("st0.0")
	stubTunnelLink7949(t, wantDev)

	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
	)
	if len(cfg.Interfaces.Interfaces) != 0 {
		t.Fatalf("fixture: interface map is not empty (%d entries), so the early return "+
			"under test is not the one this cell exercises", len(cfg.Interfaces.Interfaces))
	}
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0.0")
	if !ok {
		t.Fatalf("no row for a tunnel that is the config's ONLY interface; rows = %+v", rows)
	}
	if row.Ifindex != bindOnlyTunnelIfindex7949 || !row.SecureTunnel {
		t.Errorf("row = %+v, want Ifindex %d and SecureTunnel true", row, bindOnlyTunnelIfindex7949)
	}

	// CONTROL: the relaxation must not change what a config with neither
	// interface stanzas nor such a tunnel returns. Still nil, as before.
	bare := compileForTest5619(t, "set security zones security-zone trust")
	if got := buildInterfaceSnapshots(bare); got != nil {
		t.Errorf("a config with no interfaces and no bind-interface tunnel now returns %+v, "+
			"want nil — the early return was widened beyond the #7949 shape", got)
	}
}

// TestBothInterfaceSnapshotEntryPointsAgree7949 pins the agreement between the
// two doors into the builder.
//
// This is not hypothetical tidiness: the first cut of #7949 widened the early
// return inside buildInterfaceSnapshotsFrom and left the identical copy in
// buildInterfaceSnapshots untouched, so the synthesis ran through the
// buildSnapshot path and not through the wrapper. The guard is now one
// function; this asserts the two callers still reach the same verdict rather
// than pinning either side to a literal, which is what lets a future third
// caller be checked by the same cell.
//
// MUTATION: give either entry point its own `len(cfg.Interfaces.Interfaces)
// == 0` test again and the tunnel-only row disagrees.
func TestBothInterfaceSnapshotEntryPointsAgree7949(t *testing.T) {
	wantDev, _ := config.XFRMIfNameAndID("st0.0")
	stubTunnelLink7949(t, wantDev)
	prevXfrm := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = prevXfrm })
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }

	cases := []struct {
		name     string
		lines    []string
		wantRows bool
	}{
		{
			name: "tunnel_is_the_only_interface",
			lines: []string{
				"set security ipsec vpn v bind-interface st0.0",
				"set security zones security-zone vpn interfaces st0.0",
			},
			wantRows: true,
		},
		{
			// No interfaces and no secure tunnel. The zone carries no
			// member because strict commit rejects a zone member naming no
			// configured interface — and its own message records the #4515
			// exemption this issue is about ("nor materialized as the lo0
			// loopback or an IPsec secure-tunnel bind-interface"), which is
			// why the case above compiles and this one has to be empty.
			name:     "no_interfaces_and_no_tunnel",
			lines:    []string{"set security zones security-zone trust"},
			wantRows: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileForTest5619(t, tc.lines...)
			viaWrapper := buildInterfaceSnapshots(cfg)
			viaInner := buildInterfaceSnapshotsFrom(cfg, nil)
			if (len(viaWrapper) > 0) != (len(viaInner) > 0) {
				t.Fatalf("the two entry points disagree: buildInterfaceSnapshots -> %d rows, "+
					"buildInterfaceSnapshotsFrom -> %d rows. A duplicated guard has drifted, "+
					"so the fix works through one door and not the other",
					len(viaWrapper), len(viaInner))
			}
			if got := len(viaWrapper) > 0; got != tc.wantRows {
				t.Fatalf("rows present = %v, want %v (rows = %+v)", got, tc.wantRows, viaWrapper)
			}
		})
	}
}
