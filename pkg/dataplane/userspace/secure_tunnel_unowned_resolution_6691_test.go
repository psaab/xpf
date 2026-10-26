package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6691 round 6. Round 5 moved the EXCLUSION predicate from a name shape to
// ownership. The NAME RESOLVER did not move: Config.SecureTunnelUnitNetdev
// still returned ok=true with the verbatim ref for EVERY `st<N>.<unit>` that no
// VPN owned, and it is consulted FIRST by all three resolvers
// (ResolveKernelIfName, snapshotLinuxName, junosHostLinuxName). Half of a
// two-part mechanism moving is the worst outcome available: the half that moved
// is defended by tests, and the half that stayed is what ships.
//
// These pin the resolver half. Every case here has NO VPN binding the ref, so
// the honest device is whatever the ordinary resolution names — a NIC, a VLAN
// device, a GRE device — and the verbatim dotted ref names nothing at all.

// unownedStConfig compiles a config through the real parser and compiler. The
// hand-built `*config.Config` shortcut would not prove these configs COMMIT,
// which is the premise of the whole finding: nothing reserves the `st` prefix,
// so `set interfaces st5 ...` with no IPsec anywhere is an ordinary interface.
func unownedStConfig(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	return compileForTest5619(t, lines...)
}

// TestUnownedSecureTunnelUnitResolvesToItsRealDevice is the RED-on-revert guard
// for the resolver half.
//
// Fail-on-revert: make SecureTunnelUnitNetdev return `(LinuxIfName(ref), true)`
// for the unowned case (the round-5 behaviour) and every `snapshot` and
// `junosHost` expectation below goes RED — the rows resolve to `st5.0`,
// `st5.3` and `st0.1`, three names that exist on no box.
//
// Why the names matter, stated as the operator sees it: at a name nothing
// creates, buildLinkSnapshot reports ifindex 0, and the Rust plane gates on it.
// `userspace-dp/src/filter/compiler.rs` skips `if iface.ifindex <= 0`, so the
// unit's `filter input` is never installed; `populate_interfaces`,
// `assign_interface_filters` and `populate_egress` drop it likewise. The
// junos-host column is the same failure in the security direction — a
// `to-zone junos-host ... deny` scoped by iifname to a nonexistent device
// cannot fire.
func TestUnownedSecureTunnelUnitResolvesToItsRealDevice(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
		ref  string
		// snapshot is the netdev the dataplane snapshot must name for `ref`.
		snapshot string
		// junosHost is the full per-zone iifname scope for zone trust. Some
		// logical units (such as GRE) have no separate base netdev.
		junosHost []string
		// resolveKernel is ResolveKernelIfName's answer. It deliberately
		// KEEPS the verbatim ref for an unowned unit — that is what it
		// returned before #5619 and this fix does not change it. Pinned so a
		// future change to that fallback is a deliberate one.
		resolveKernel string
	}{
		{
			// A wildcard-authored NIC that happens to be spelled `st5` — on
			// bare metal, `set chassis device-map` will rename a real card to
			// exactly this. No IPsec anywhere in the config.
			name: "plain unit 0 — an ordinary NIC named st5",
			set: []string{
				"set interfaces st5 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st5.0",
			},
			ref:           "st5.0",
			snapshot:      "st5",
			junosHost:     []string{"st5"},
			resolveKernel: "st5.0",
		},
		{
			// The VLAN device is `st5.80` — the VLAN ID, never the unit
			// number. Round 5 resolved it to `st5.3`, which is neither.
			name: "802.1Q unit — the device is parent.vlanid",
			set: []string{
				"set interfaces st5 vlan-tagging",
				"set interfaces st5 unit 3 vlan-id 80 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st5.3",
			},
			ref:           "st5.3",
			snapshot:      "st5.80",
			junosHost:     []string{"st5", "st5.80"},
			resolveKernel: "st5.3",
		},
		{
			// #6861 r5 established TunnelNameMap-FIRST for a tunnel unit.
			// Placing the st arm ahead of it at two NEW call sites reversed
			// that where it was never pinned: the ordering invariant was
			// bound at ResolveKernelIfName only, and an invariant bound at
			// one call site does not survive a second one being added.
			name: "GRE tunnel unit — the device comes from TunnelNameMap",
			set: []string{
				"set interfaces st0 unit 1 tunnel mode gre",
				"set interfaces st0 unit 1 tunnel source 10.0.0.1",
				"set interfaces st0 unit 1 tunnel destination 10.0.0.2",
				"set security zones security-zone trust interfaces st0.1",
			},
			ref:           "st0.1",
			snapshot:      "st0u1",
			junosHost:     []string{"st0u1"},
			resolveKernel: "st0.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := unownedStConfig(t, tc.set...)

			// PREMISE: nothing binds this ref. If a fixture ever grew a VPN,
			// every assertion below would be about the owned path instead.
			if dev, ok := cfg.SecureTunnelNetdevForRef(tc.ref); ok {
				t.Fatalf("premise broken: %q is owned by a VPN (device %q); this "+
					"case is about the UNOWNED path", tc.ref, dev)
			}

			var row InterfaceSnapshot
			var found bool
			for _, s := range buildInterfaceSnapshots(cfg) {
				if s.Name == tc.ref {
					row, found = s, true
				}
			}
			if !found {
				t.Fatalf("premise broken: no %q row in the snapshot", tc.ref)
			}
			if row.LinuxName != tc.snapshot {
				t.Errorf("snapshotLinuxName(%s) = %q, want %q — no VPN binds this ref, so "+
					"the xfrmi reconciler creates nothing for it and the device is whatever "+
					"the ordinary resolution names. At a name that exists on no box the row "+
					"reports ifindex 0 and the Rust plane drops it from populate_interfaces, "+
					"assign_interface_filters and populate_egress",
					tc.ref, row.LinuxName, tc.snapshot)
			}
			if row.SecureTunnel {
				t.Errorf("snapshot row %q has secureTunnel=true with no VPN binding it — "+
					"an `st` name is a secure tunnel because a configuration BINDS it", tc.ref)
			}

			got := config.JunosHostZoneIngressNetdevs(cfg)["trust"]
			if !slices.Equal(got, tc.junosHost) {
				t.Errorf("junos-host iifname scope for zone trust = %v, want %v — a "+
					"`to-zone junos-host ... deny` is rendered as an nft rule scoped by "+
					"iifname, so a scope naming a device that exists on no box is a "+
					"security guard that CANNOT FIRE", got, tc.junosHost)
			}

			if k := cfg.ResolveKernelIfName(tc.ref); k != tc.resolveKernel {
				t.Errorf("ResolveKernelIfName(%s) = %q, want %q", tc.ref, k, tc.resolveKernel)
			}
		})
	}
}

// TestSecureTunnelOwnershipRequiresTheAuthoredSpelling pins the F2 half: the
// if_id is a LOSSY digest of the authored string, so it cannot decide ownership
// on its own.
//
// XFRMIfNameAndID derives the index with strconv.Atoi, which erases a leading
// `+` and leading zeros. `st5`, `st05`, `st+5` and `st0000005` therefore all
// derive if_id 0x50001 while LinuxIfName keeps them as four DIFFERENT device
// names, and pkg/routing/xfrm.go creates the device under the AUTHORED name. So
// `bind-interface st05` creates a netdev called `st05` and nothing called
// `st5` — and before this fix it nonetheless claimed a wildcard-authored NIC
// named `st5`, returning both `st5` rows as secure tunnels with an empty
// ingress set and an empty RSS allowlist. A live NIC removed from the dataplane
// by a VPN that never names it.
//
// Commit does not stop this: ValidateSecureTunnelBindInterface only requires
// if_id != 0, and `st05` is a perfectly good (if unusual) xfrmi name. Rejecting
// it at commit was the alternative, and it was rejected as the fix — a new
// commit-time rejection would brick a persisted or peer-synced config that
// already carries the spelling (#1960).
//
// Fail-on-revert: drop the bindInterfaceOwnsRef call from
// secureTunnelBindingForRef (ownership by if_id alone) and every assertion in
// the `st05` row goes RED.
//
// #6691 round 7: this fixture carries ONE VPN, so no if_id collision is ever
// possible in it and the ORDER of the ownership and veto tests is invisible
// here. TestSecureTunnelCollisionVetoRequiresAnOwner is where that order is
// bound. Both spellings below are BARE, so the DIRECTION of ownership is
// likewise invisible here; TestSecureTunnelBareRowRequiresTheBareSpelling
// carries that.
func TestSecureTunnelOwnershipRequiresTheAuthoredSpelling(t *testing.T) {
	for _, tc := range []struct {
		bindIface string
		// wantOwned is whether the bind-interface owns the NIC's ref `st5.0`.
		wantOwned bool
	}{
		{bindIface: "st5", wantOwned: true},
		{bindIface: "st05", wantOwned: false},
		{bindIface: "st+5", wantOwned: false},
		{bindIface: "st0000005", wantOwned: false},
	} {
		t.Run(tc.bindIface, func(t *testing.T) {
			// PREMISE: every spelling here really does derive the SAME if_id
			// under a DIFFERENT device name. Without that the case is not
			// about the lossy digest at all.
			bindDev, bindID := config.XFRMIfNameAndID(tc.bindIface)
			refDev, refID := config.XFRMIfNameAndID("st5.0")
			if bindID == 0 || bindID != refID {
				t.Fatalf("premise broken: bind-interface %q derives if_id %#x, ref st5.0 "+
					"derives %#x — this case needs them equal", tc.bindIface, bindID, refID)
			}
			if (bindDev == "st5") != tc.wantOwned {
				t.Fatalf("premise broken: bind-interface %q creates device %q (ref device "+
					"%q); ownership of the NIC `st5` must follow the device NAME",
					tc.bindIface, bindDev, refDev)
			}

			cfg := unownedStConfig(t,
				"set security ipsec vpn v bind-interface "+tc.bindIface,
				"set interfaces st5 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st5.0",
			)

			if _, ok := cfg.SecureTunnelNetdevForRef("st5.0"); ok != tc.wantOwned {
				t.Errorf("SecureTunnelNetdevForRef(st5.0) ok = %v, want %v under "+
					"`bind-interface %s` — routing creates the xfrmi under the AUTHORED "+
					"name %q, so it owns `st5.0` only when that name IS `st5`",
					ok, tc.wantOwned, tc.bindIface, bindDev)
			}

			for _, s := range buildInterfaceSnapshots(cfg) {
				if s.Name != "st5" && s.Name != "st5.0" {
					continue
				}
				if s.SecureTunnel != tc.wantOwned {
					t.Errorf("snapshot row %q secureTunnel = %v, want %v under "+
						"`bind-interface %s`", s.Name, s.SecureTunnel, tc.wantOwned, tc.bindIface)
				}
			}

			// The consequence an operator sees: the NIC keeps (or loses) its
			// RSS/binding entry. Asserted as an exact membership question so
			// it cannot be satisfied by the other spelling's name.
			bound := slices.Contains(UserspaceBoundLinuxInterfaces(cfg), "st5")
			if bound == tc.wantOwned {
				t.Errorf("`st5` in the RSS/binding allowlist = %v under `bind-interface %s`, "+
					"want %v — an unowned NIC keeps its binding; a bound tunnel loses it",
					bound, tc.bindIface, !tc.wantOwned)
			}
		})
	}
}

// TestSecureTunnelOwnershipPrecedesTheTunnelNameMap pins the ARM ORDER at the
// two dataplane resolvers, which is otherwise decided only by where the lines
// happen to sit.
//
// The two arms are disjoint everywhere except this config, which names `st0.1`
// as both a bound xfrmi and a GRE tunnel. That overlap is the ONLY input where
// the order is observable, so it is the only place the invariant can be bound.
//
// Ownership wins, matching ResolveKernelIfName's own ordering (its `st` arm has
// always preceded the tunnel-name map) — an explicit `bind-interface` is the
// stronger statement about what the unit is.
//
// Fail-on-revert: move the SecureTunnelUnitNetdev arm below the TunnelNameMap
// lookup in snapshotLinuxName or in junosHostLinuxName and the matching
// assertion goes RED. Before this test both moves left the whole suite green.
func TestSecureTunnelOwnershipPrecedesTheTunnelNameMap(t *testing.T) {
	cfg := unownedStConfig(t,
		"set security ipsec vpn v bind-interface st0.1",
		"set interfaces st0 unit 1 tunnel mode gre",
		"set interfaces st0 unit 1 tunnel source 10.0.0.1",
		"set interfaces st0 unit 1 tunnel destination 10.0.0.2",
		"set security zones security-zone trust interfaces st0.1",
	)

	// PREMISE: both arms really do claim this ref. If either stopped, the
	// ordering assertion below would pass without ordering anything.
	dev, owned := cfg.SecureTunnelNetdevForRef("st0.1")
	if !owned || dev != "st0.1" {
		t.Fatalf("premise broken: SecureTunnelNetdevForRef(st0.1) = (%q, %v), want "+
			"(\"st0.1\", true)", dev, owned)
	}
	if tun := cfg.TunnelNameMap()["st0.1"]; tun != "st0u1" {
		t.Fatalf("premise broken: TunnelNameMap[st0.1] = %q, want \"st0u1\" — without a "+
			"competing tunnel name this config does not exercise the arm order", tun)
	}

	var row InterfaceSnapshot
	for _, s := range buildInterfaceSnapshots(cfg) {
		if s.Name == "st0.1" {
			row = s
		}
	}
	if row.LinuxName != dev {
		t.Errorf("snapshotLinuxName(st0.1) = %q, want %q — an explicit `bind-interface` "+
			"outranks the tunnel-name map", row.LinuxName, dev)
	}
	if got := config.JunosHostZoneIngressNetdevs(cfg)["trust"]; !slices.Contains(got, dev) {
		t.Errorf("junos-host iifname scope for zone trust = %v, missing %q — the two "+
			"dataplane resolvers must agree on the arm order, or the deny is scoped to a "+
			"different device than the snapshot programs", got, dev)
	}
	if k := cfg.ResolveKernelIfName("st0.1"); k != dev {
		t.Errorf("ResolveKernelIfName(st0.1) = %q, want %q", k, dev)
	}
}

// TestResolveKernelIfNameUsesTheAuthoredBindInterface binds the production line
// at pkg/config/types.go that reverting to master left GREEN.
//
// Master resolved a dotted `st` ref to the verbatim ref, full stop. That is
// right for an unowned unit (pinned above) and WRONG for a bound one: a bare
// `bind-interface st0` creates a device called `st0`, while the unit ref is
// `st0.0` either way, so the name cannot be reconstructed from the ref.
//
// Fail-on-revert: delete the SecureTunnelUnitNetdev call from
// ResolveKernelIfName (leaving master's verbatim arm) and the `st0` row goes
// RED. Before this test, reverting that line to master left the whole suite
// green.
func TestResolveKernelIfNameUsesTheAuthoredBindInterface(t *testing.T) {
	for _, tc := range []struct {
		bindIface string
		want      string
	}{
		// The device is `st0`; the ref is `st0.0`. Only reading the authored
		// string gets this right.
		{bindIface: "st0", want: "st0"},
		{bindIface: "st0.0", want: "st0.0"},
	} {
		t.Run(tc.bindIface, func(t *testing.T) {
			wantDev, ifID := config.XFRMIfNameAndID(tc.bindIface)
			if ifID == 0 || wantDev != tc.want {
				t.Fatalf("premise broken: bind-interface %q creates device %q/if_id %#x, "+
					"want device %q", tc.bindIface, wantDev, ifID, tc.want)
			}
			cfg := unownedStConfig(t,
				"set security ipsec vpn v bind-interface "+tc.bindIface,
				"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
				"set security zones security-zone vpn interfaces st0.0",
			)
			if got := cfg.ResolveKernelIfName("st0.0"); got != tc.want {
				t.Errorf("ResolveKernelIfName(st0.0) = %q, want %q under `bind-interface "+
					"%s` — the xfrmi reconciler creates the device under the AUTHORED "+
					"string, and both spellings share the unit ref `st0.0`",
					got, tc.want, tc.bindIface)
			}
		})
	}
}

// TestSecureTunnelOwnershipPrecedesVlanID pins the OTHER arm-order collision
// (#6691 round 8), which had no doc and no test on either revision.
//
// `set interfaces st5 unit 3 vlan-id 80` makes the unit a VLAN child: its
// kernel device is `st5.80` — parent netdev plus VLAN TAG, not plus unit
// number. `set security ipsec vpn v bind-interface st5.3` makes the SAME unit
// an xfrmi whose device is the authored ref, `st5.3`. Both arms claim the ref
// and they name DIFFERENT devices, so the resolver's arm order decides which
// one every ifindex-keyed set is programmed against.
//
// Strict compile ACCEPTS this config on master and on this branch — nothing
// rejects the combination — so an operator can author it and the only signal is
// which device the dataplane picks. The `st` arm is FIRST in both
// snapshotLinuxName and ResolveKernelIfName, so ownership wins: the row
// resolves to `st5.3`, the VLAN device `st5.80` is not what gets programmed,
// and the secure-tunnel exclusion then applies to the row.
//
// This test does not argue that order is the right one — it pins it so it
// cannot move silently, and names the consequence if it does: the two resolvers
// would program a filter, a zone and a junos-host deny against two different
// netdevs for one config ref.
func TestSecureTunnelOwnershipPrecedesVlanID(t *testing.T) {
	cfg := unownedStConfig(t,
		"set interfaces st5 vlan-tagging",
		"set interfaces st5 unit 3 vlan-id 80",
		"set interfaces st5 unit 3 family inet address 10.9.9.1/24",
		"set security ipsec vpn v bind-interface st5.3",
		"set security zones security-zone trust interfaces st5.3",
	)

	// PREMISE: both arms really do claim this ref, and they disagree. Without
	// the disagreement the ordering assertion orders nothing.
	dev, owned := cfg.SecureTunnelNetdevForRef("st5.3")
	if !owned || dev != "st5.3" {
		t.Fatalf("premise broken: SecureTunnelNetdevForRef(st5.3) = (%q, %v), want (\"st5.3\", true)",
			dev, owned)
	}
	iface := cfg.Interfaces.Interfaces["st5"]
	if iface == nil || iface.Units[3] == nil || iface.Units[3].VlanID != 80 {
		t.Fatalf("premise broken: st5 unit 3 must carry vlan-id 80, else the VLAN arm " +
			"never competes for this ref")
	}

	var row InterfaceSnapshot
	found := false
	for _, s := range buildInterfaceSnapshots(cfg) {
		if s.Name == "st5.3" {
			row, found = s, true
		}
	}
	if !found {
		t.Fatal("no snapshot row for st5.3")
	}
	if row.LinuxName != dev {
		t.Errorf("snapshotLinuxName(st5.3) = %q, want %q — `bind-interface` outranks "+
			"`vlan-id`; a change here silently moves every ifindex-keyed set onto the "+
			"VLAN device %q instead", row.LinuxName, dev, "st5.80")
	}
	if k := cfg.ResolveKernelIfName("st5.3"); k != dev {
		t.Errorf("ResolveKernelIfName(st5.3) = %q, want %q — the two resolvers must agree "+
			"on the arm order, or a filter/zone/junos-host deny is scoped to a different "+
			"device than the snapshot programs", k, dev)
	}
	// And the ownership verdict is what the exclusion keys on, so the row must
	// carry it: an operator who authors both spellings gets the secure-tunnel
	// treatment, not the VLAN-child treatment.
	if !row.SecureTunnel {
		t.Errorf("st5.3 row SecureTunnel = false; the ref a VPN binds must be flagged " +
			"even when the unit also carries a vlan-id")
	}
}
