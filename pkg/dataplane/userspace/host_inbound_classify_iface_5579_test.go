package userspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// host_inbound_classify_iface_5579_test.go guards the #5579 per-interface
// host-inbound classification: the match-policies host-inbound classifier used to
// OR every effective view in a zone and return on the FIRST admitting view, so a
// MIXED zone (one interface with an ssh override, a sibling default-deny) reported
// a zone-wide token-admit even for the sibling interface the runtime denies. The
// classifier now (a) reports HostInboundAmbiguous for an unqualified zone-scoped
// query when the per-interface views disagree, and (b) classifies ONLY the named
// interface's effective view when an ingress interface is supplied.

const (
	hi5579TCP = uint8(6)
)

// Test_5579_ZoneScopedMixedZoneIsAmbiguous asserts an UNQUALIFIED (no ingress
// interface) host-inbound classification of a mixed zone reports ambiguity rather
// than folding the divergent per-interface views into a zone-wide first-admit.
//
// hostInboundCfg3362() builds a `wan` zone where reth0.50 admits ssh (override)
// and reth1.0 default-denies (no override, no zone-level stanza). A tcp/22 query
// therefore admits on reth0.50 and denies on reth1.0.
//
// RED-on-revert: revert ClassifyHostInbound to the pre-#5579 first-admit fold
// (return on the first admitting view) and this query returns HostInboundTokenAdmit
// ("ssh") — the false zone-wide admission — instead of HostInboundAmbiguous, so
// the status assertion below fails.
func Test_5579_ZoneScopedMixedZoneIsAmbiguous(t *testing.T) {
	cfg := hostInboundCfg3362()

	got := ClassifyHostInbound(cfg, "wan", hi5579TCP, true, 22, nil, "ip")
	if got.Status != HostInboundAmbiguous {
		t.Fatalf("zone-scoped tcp/22 status = %v, want ambiguous (reth0.50 admits ssh, reth1.0 denies)", got.Status)
	}
	// The ambiguity report must name BOTH divergent interface groups so the
	// operator sees which admits and which denies.
	if len(got.Ambiguous) < 2 {
		t.Fatalf("ambiguous groups = %d, want >= 2 (the admit + deny views)", len(got.Ambiguous))
	}
	var sawAdmit, sawDeny bool
	for _, g := range got.Ambiguous {
		switch g.Status {
		case HostInboundTokenAdmit:
			if g.Token == "ssh" && ifaceInGroup(g.Interfaces, "reth0.50") {
				sawAdmit = true
			}
		case HostInboundDenied:
			if ifaceInGroup(g.Interfaces, "reth1.0") {
				sawDeny = true
			}
		}
	}
	if !sawAdmit {
		t.Errorf("ambiguous groups %+v missing the reth0.50 ssh token-admit", got.Ambiguous)
	}
	if !sawDeny {
		t.Errorf("ambiguous groups %+v missing the reth1.0 deny", got.Ambiguous)
	}
	// Describe() must direct the operator at the ingress-interface selector.
	if d := got.Describe(); !strings.Contains(d, "ingress-interface") {
		t.Errorf("ambiguous Describe() = %q, want it to mention ingress-interface", d)
	}
}

// Test_5579_IngressInterfaceScopesToTruePosture is the core fail-on-revert: a
// query scoped to a SPECIFIC ingress interface reports THAT interface's true
// host-inbound posture — admit for the ssh-override interface, DENY for the
// sibling — not the zone-wide first-admit fold.
//
// RED-on-revert: revert ClassifyHostInboundForInterface to delegate to the
// zone-wide ClassifyHostInbound (first-admit OR across all views) and the reth1.0
// query folds to the zone's ssh admit — HostInboundTokenAdmit instead of
// HostInboundDenied — so the deny assertion fails.
func Test_5579_IngressInterfaceScopesToTruePosture(t *testing.T) {
	cfg := hostInboundCfg3362()

	admit := ClassifyHostInboundForInterface(cfg, "wan", "reth0.50", hi5579TCP, true, 22, nil, "ip")
	if admit.Status != HostInboundTokenAdmit || admit.Token != "ssh" {
		t.Errorf("reth0.50 tcp/22 = %v/%q, want token-admit/ssh", admit.Status, admit.Token)
	}

	deny := ClassifyHostInboundForInterface(cfg, "wan", "reth1.0", hi5579TCP, true, 22, nil, "ip")
	if deny.Status != HostInboundDenied {
		t.Errorf("reth1.0 tcp/22 = %v, want denied (sibling has no host-inbound override, default-deny)", deny.Status)
	}
}

// Test_5579_IngressInterfaceReplacesZoneLevel asserts the interface-scoped
// classifier resolves the zone↔interface levels the way enforcement does: a
// zone-level `ping` with reth0.50's `ssh` override admits ssh and DENIES ping on
// reth0.50, while reth1.0 — which declares no stanza — admits the zone-level ping
// and denies ssh.
//
// #6515: this asserted the UNION before, and the ping-on-reth0.50 case was the
// one it never sampled — the old body claimed in a comment that reth0.50 "admits
// ssh AND ping" but only ever queried tcp/22 there. A fixture that varies the
// right axis and samples only the passing point cannot discriminate the two
// combination rules, so it passed unchanged when the semantics flipped under it.
// All four (interface × service) cells are queried now.
func Test_5579_IngressInterfaceReplacesZoneLevel(t *testing.T) {
	cfg := hostInboundCfg3362()
	cfg.Security.Zones["wan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ping"}}

	// reth1.0 declares no stanza: it admits the zone-level ping (icmp echo
	// type 8) and denies ssh.
	if a := ClassifyHostInboundForInterface(cfg, "wan", "reth1.0", uint8(1), true, 0, u8ptr(8), "ip"); a.Status != HostInboundTokenAdmit || a.Token != "ping" {
		t.Errorf("reth1.0 icmp echo = %v/%q, want token-admit/ping (zone-level)", a.Status, a.Token)
	}
	if a := ClassifyHostInboundForInterface(cfg, "wan", "reth1.0", hi5579TCP, true, 22, nil, "ip"); a.Status != HostInboundDenied {
		t.Errorf("reth1.0 tcp/22 = %v, want denied (ssh only on reth0.50)", a.Status)
	}
	// reth0.50 declares `ssh`: it admits ssh and NO LONGER inherits the zone's
	// ping, because its stanza replaces the zone stanza (#6515).
	if a := ClassifyHostInboundForInterface(cfg, "wan", "reth0.50", hi5579TCP, true, 22, nil, "ip"); a.Status != HostInboundTokenAdmit || a.Token != "ssh" {
		t.Errorf("reth0.50 tcp/22 = %v/%q, want token-admit/ssh", a.Status, a.Token)
	}
	if a := ClassifyHostInboundForInterface(cfg, "wan", "reth0.50", uint8(1), true, 0, u8ptr(8), "ip"); a.Status != HostInboundDenied {
		t.Errorf("reth0.50 icmp echo = %v/%q, want DENIED: the interface stanza lists only "+
			"ssh and REPLACES the zone-level ping (#6515)", a.Status, a.Token)
	}
}

// Test_5579_ResolveIngressInterfaceValidation guards the fail-closed selector
// validator: an unknown interface, a zone-mismatched interface, and a
// management/cluster lifeline are all rejected; a real interface of the queried
// zone and an empty (omitted) selector pass.
func Test_5579_ResolveIngressInterfaceValidation(t *testing.T) {
	cfg := hostInboundCfg3362()

	if err := ResolveHostInboundIngressInterface(cfg, "wan", "reth0.50"); err != nil {
		t.Errorf("valid reth0.50 rejected: %v", err)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "wan", ""); err != nil {
		t.Errorf("empty (omitted) selector rejected: %v", err)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "wan", "ge-9/9/9.9"); err == nil {
		t.Error("unknown interface accepted, want reject")
	}

	// Zone-mismatch: add a second zone owning a different interface.
	cfg.Interfaces.Interfaces["reth2"] = &config.InterfaceConfig{Name: "reth2", Units: map[int]*config.InterfaceUnit{
		0: {Number: 0, Addresses: []string{"10.0.99.1/24"}},
	}}
	cfg.Security.Zones["lan"] = &config.ZoneConfig{Name: "lan", Interfaces: []string{"reth2.0"}}
	if err := ResolveHostInboundIngressInterface(cfg, "wan", "reth2.0"); err == nil {
		t.Error("zone-mismatched reth2.0 (in lan) accepted for from-zone wan, want reject")
	}
}

// Test_5579_ResolveIngressInterfaceRejectsLifeline asserts a management/cluster
// lifeline (fxp0) is rejected — its host traffic is served unconditionally, so a
// per-interface host-inbound verdict would be a fresh false answer.
func Test_5579_ResolveIngressInterfaceRejectsLifeline(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.2/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mgmt": {Name: "mgmt", Interfaces: []string{"fxp0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	err := ResolveHostInboundIngressInterface(cfg, "mgmt", "fxp0.0")
	if err == nil {
		t.Fatal("lifeline fxp0.0 accepted, want reject (served unconditionally)")
	}
	if !strings.Contains(err.Error(), "lifeline") {
		t.Errorf("lifeline reject error = %q, want it to mention lifeline", err)
	}
}

// Test_5579_ResolveIngressInterfaceRejectsBarePhysical guards the review fold: a
// bare-PHYSICAL ingress-interface ref (e.g. `reth0`, whose unit reth0.50 admits
// ssh) must be REJECTED, because the classifier keys the effective host-inbound
// set on the LOGICAL-UNIT ref — a bare physical would silently drop the
// unit-authored override and report a FALSE-DENY. The validator's accepted
// namespace must equal what the classifier keys on.
//
// RED-on-revert: drop the bare-physical reject and `reth0` is accepted, then
// ClassifyHostInboundForInterface(cfg, "wan", "reth0", ...) keys on the physical
// ref (no unit-level override) and returns HostInboundDenied — a false-deny that
// disagrees with reth0.50's token-admit. Both assertions below then fail.
func Test_5579_ResolveIngressInterfaceRejectsBarePhysical(t *testing.T) {
	cfg := hostInboundCfg3362() // reth0 has unit 50 (ssh override); reth1 has unit 0.

	err := ResolveHostInboundIngressInterface(cfg, "wan", "reth0")
	if err == nil {
		t.Fatal("bare-physical reth0 accepted, want reject (classifier keys on the logical unit)")
	}
	if !strings.Contains(err.Error(), "reth0.50") {
		t.Errorf("bare-physical reject error = %q, want it to name the logical unit reth0.50", err)
	}

	// The false-deny the reject prevents: the physical ref, if classified, drops
	// the unit-authored ssh override and denies, while the logical unit admits.
	physical := ClassifyHostInboundForInterface(cfg, "wan", "reth0", hi5579TCP, true, 22, nil, "ip")
	unit := ClassifyHostInboundForInterface(cfg, "wan", "reth0.50", hi5579TCP, true, 22, nil, "ip")
	if unit.Status != HostInboundTokenAdmit || unit.Token != "ssh" {
		t.Errorf("reth0.50 = %v/%q, want token-admit/ssh", unit.Status, unit.Token)
	}
	if physical.Status == unit.Status && physical.Token == unit.Token {
		t.Errorf("physical reth0 classify (%v/%q) matched the unit — the namespace gap that the reject guards is gone; the reject is the load-bearing fix", physical.Status, physical.Token)
	}
}

func ifaceInGroup(ifaces []string, want string) bool {
	for _, i := range ifaces {
		if i == want {
			return true
		}
	}
	return false
}

// Test_5579_IngressInterfaceHonorsZoneQuarantine11068 ensures the selector
// classifies a colliding StableZoneID zone from the same empty post-quarantine
// view as ClassifyHostInbound, rather than granting its raw configured service.
func Test_5579_IngressInterfaceHonorsZoneQuarantine11068(t *testing.T) {
	var first, second string
	owners := map[uint16]string{}
	for i := 0; i < 300000 && second == ""; i++ {
		name := fmt.Sprintf("host-inbound-quarantine-%d", i)
		id := config.StableZoneID(name)
		if previous, ok := owners[id]; ok {
			first, second = previous, name
		} else {
			owners[id] = name
		}
	}
	if second == "" {
		t.Fatal("fixture: failed to find a StableZoneID collision")
	}
	excluded := config.ZoneQuarantineExclusions([]string{first, second})
	if len(excluded) != 1 {
		t.Fatalf("fixture collision quarantine = %v, want exactly one excluded zone", excluded)
	}
	var quarantined, surviving string
	for _, name := range []string{first, second} {
		if _, drop := excluded[name]; drop {
			quarantined = name
		} else {
			surviving = name
		}
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		quarantined: {
			Name: quarantined, Interfaces: []string{"ge-0/0/1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		surviving: {Name: surviving, Interfaces: []string{"ge-0/0/2.0"}},
	}
	zone := ClassifyHostInbound(cfg, quarantined, hi5579TCP, true, 22, nil, "ip")
	iface := ClassifyHostInboundForInterface(cfg, quarantined, "ge-0/0/1.0", hi5579TCP, true, 22, nil, "ip")
	if zone.Status != HostInboundDenied || iface.Status != zone.Status {
		t.Fatalf("quarantined tcp/22 = zone %v, interface %v; both must use the empty, default-deny view",
			zone.Status, iface.Status)
	}
	if global := ClassifyHostInboundForInterface(cfg, quarantined, "ge-0/0/1.0", 50, true, 0, nil, "ip"); global.Status != HostInboundGlobalAccept {
		t.Errorf("quarantined interface must preserve the global ESP accept, got %v", global.Status)
	}
}
