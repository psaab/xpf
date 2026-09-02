package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// The encap-type table. The two tuntap rows are the ones that decide the
// predicate's shape and they were MEASURED, not transcribed: a TUN and a TAP
// are both `netlink.Link.Type() == "tuntap"` and differ only here, so a
// predicate keyed on the link KIND would have refused the TAP as well and
// still told us nothing about the tunnel case.
func TestNetdevCarriesEthernetFraming8279(t *testing.T) {
	for _, tc := range []struct {
		encap string
		want  bool
		note  string
	}{
		{"ether", true, "physical NIC / VLAN / bond / reth / L2 IPVLAN"},
		{"none", false, "TUN, xfrmi — raw L3, NO Ethernet header"},
		{"loopback", false, "lo"},
		{"sit", false, "6in4"},
		{"tunnel", false, "ipip"},
		{"tunnel6", false, "ip6tnl"},
		{"ipgre", false, "kernel GRE"},
		{"", false, "link never resolved — refuse, do not assume"},
		{"ETHER", false, "case matters; netlink emits lowercase"},
		{"ethernet", false, "an unknown spelling is refused, not guessed"},
	} {
		if got := netdevCarriesEthernetFraming(tc.encap); got != tc.want {
			t.Errorf("netdevCarriesEthernetFraming(%q) = %v, want %v (%s)",
				tc.encap, got, tc.want, tc.note)
		}
	}
}

// The gate must be able to tell "not Ethernet" from "could not tell", because
// it acts on only the first. Refusing an unresolvable link would guarantee an
// unadjudicated netdev to avoid a misparse that may not even apply to it.
func TestNetdevFramingKnownSeparatesUnknownFromNonEthernet8279(t *testing.T) {
	if _, known := netdevFramingKnown(nil, nil); known {
		t.Error("a nil link must report known=false, not a framing verdict")
	}
	l := &netlink.Device{LinkAttrs: netlink.LinkAttrs{EncapType: "ether"}}
	if _, known := netdevFramingKnown(l, errStub8279{}); known {
		t.Error("a lookup error must report known=false even when the link value " +
			"is non-nil and looks fine")
	}
	got, known := netdevFramingKnown(l, nil)
	if !known || got != "ether" {
		t.Errorf("resolved link must report (%q,true), got (%q,%v)", "ether", got, known)
	}
}

type errStub8279 struct{}

func (errStub8279) Error() string { return "stub link error" }

func framingCfg8279(phys string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{phys + ".0"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		phys: {
			Name:  phys,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.1.1/24"}}},
		},
	}
	return cfg
}

// FAIL-ON-REVERT for the WIRING (#8279).
//
// The predicate above is inert on its own — what matters is that
// `compileZones` consults it before putting an ifindex into `pendingXDP`, which
// is what `attachUserspaceShimXDP` attaches the shim to. Deleting the gate in
// `compiler_iface.go` leaves every predicate assertion above GREEN.
//
// TWO ARMS, and the `ether` arm is the point of the test rather than padding.
// A guard that excluded everything would satisfy the `none` arm perfectly; only
// a control on the most nearly-correct input — a netdev identical in every
// respect except that its frames DO carry an Ethernet header — shows the
// exclusion is aimed rather than merely present.
func TestCompileZonesRefusesShimOnNonEthernetNetdev8279(t *testing.T) {
	const phys = "ge-0-0-9"
	const idx = 8279

	for _, arm := range []struct {
		name      string
		encap     string
		wantArmed bool
	}{
		{"ethernet netdev is armed (CONTROL)", "ether", true},
		{"raw-L3 netdev is refused", "none", false},
	} {
		t.Run(arm.name, func(t *testing.T) {
			cfg := framingCfg8279(phys)
			result := newValidationResult()
			assignZoneIDs(result, cfg)
			assignScreenIDs(result, cfg)
			link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{
				Name: phys, Index: idx, EncapType: arm.encap,
			}}
			result.ifCache[phys] = &net.Interface{Index: idx, Name: phys}
			result.linkCache[phys] = link
			result.linkIdxMap[idx] = link

			if err := compileZones(convergenceTestDP{}, cfg, result); err != nil {
				t.Fatalf("compileZones: %v", err)
			}

			armed := false
			for _, got := range result.pendingXDP {
				if got == idx {
					armed = true
				}
			}
			if armed != arm.wantArmed {
				t.Fatalf("encap=%q: ifindex in pendingXDP = %v, want %v. "+
					"pendingXDP=%v. The shim parses a 14-byte Ethernet header "+
					"unconditionally, so a netdev whose frames carry none must never "+
					"reach the attach set (#8279).",
					arm.encap, armed, arm.wantArmed, result.pendingXDP)
			}

			// The refusal owes an operator-visible reason, not a silent skip:
			// the netdev is UP and zoned with no XDP, which is #5275's
			// policy-free-router state and must show up in the arm-coverage
			// proof.
			var found *UnarmedSurface
			for i := range result.unarmedSurfaces {
				if result.unarmedSurfaces[i].Ifindex == idx {
					found = &result.unarmedSurfaces[i]
				}
			}
			if arm.wantArmed {
				if found != nil {
					t.Fatalf("an armed Ethernet netdev must NOT be recorded unarmed, got %+v", *found)
				}
				return
			}
			if found == nil {
				t.Fatalf("a refused netdev must be recorded as an unarmed surface; "+
					"surfaces=%+v", result.unarmedSurfaces)
			}
			if !strings.Contains(found.Reason, "not Ethernet") ||
				!strings.Contains(found.Reason, "8279") {
				t.Fatalf("the unarmed reason must name the CAUSE, not just the fact; got %q",
					found.Reason)
			}
			if !found.StillForwarding {
				t.Fatal("a refused netdev is UP, zoned and now has no XDP, so the surface " +
					"must be marked StillForwarding — that is the #5275 state the operator " +
					"needs to see, and silently trading it away is the defect this guard exists for")
			}
		})
	}
}
