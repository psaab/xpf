// #6987: a session's recorded ingress {ifindex, VLAN} is stamped at INSTALL,
// while `ifaceNamesByKey` is rebuilt from the CURRENT config and the CURRENT
// kernel ifindexes on EVERY query. A kernel ifindex is RECYCLED — a tunnel,
// VLAN unit or XFRM interface is destroyed and its number handed to a different
// interface later — so a stale ifindex does not merely MISS the rebuilt table.
// It can HIT it and name an interface the session never arrived on, and there
// was nothing in the output to tell that apart from a correct answer: one
// confident WRONG interface name, and an interface filter selecting rows for
// traffic that never touched the named interface.
//
// The row carries one other identity recorded at the same instant — its ingress
// ZONE, whose id is name-derived and stable across commits (assignZoneIDs) — so
// the hit is corroborated against it. A disagreement is treated as a miss.
//
// Each test below carries its own over-reach control, because "stop naming the
// interface" and "stop resolving the identity at all" are indistinguishable
// without one.
package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

const (
	stale6987TrustZone uint16 = 1
	stale6987VPNZone   uint16 = 3
)

// stale6987Config is the config as it stands AT QUERY TIME. `gr-0/0/0`, the
// interface the session actually arrived on, is already gone: torn down and
// removed from the config, which is what freed its kernel ifindex.
func stale6987Config() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
				// Created AFTER the tunnel died, and handed its ifindex.
				"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			},
		},
	}
}

// stale6987Filter builds the filter with `ge-0/0/2` occupying ifindex 42 — the
// number the vpn-zone tunnel held when the session installed.
//
// The vpn zone is given a SURVIVING member (`ge-0/0/7.0`, a second tunnel) so
// the fallback is a real interface list rather than an empty one. With an empty
// vpn zone the corroboration check and a plain "return nothing" would produce
// the same candidate set, and the filter assertions could not tell them apart.
func stale6987Filter(t *testing.T, iface string) *sessionFilter {
	t.Helper()
	cfg := stale6987Config()
	cfg.Interfaces.Interfaces["ge-0/0/7"] = &config.InterfaceConfig{
		Name:  "ge-0/0/7",
		Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
	}
	lookup := func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 11, nil
		case "ge-0-0-2":
			return 42, nil // RECYCLED: gr-0/0/0's ifindex at install time
		case "ge-0-0-7":
			return 47, nil
		}
		t.Fatalf("unexpected interface lookup %q", name)
		return 0, nil
	}
	return &sessionFilter{
		iface: iface,
		zoneIfaces: map[uint16][]string{
			stale6987TrustZone: {"ge-0/0/0", "ge-0/0/2"},
			stale6987VPNZone:   {"ge-0/0/7.0"},
		},
		ifaceNamesByKey: buildSessionEgressIfacesWithLookup(cfg, lookup),
	}
}

// stale6987Session is the row: installed on the vpn-zone tunnel that held
// ifindex 42, egressing ge-0/0/0.
func stale6987Session() (dataplane.SessionKey, dataplane.SessionValue) {
	return dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{
		IngressZone:    stale6987VPNZone,
		EgressZone:     stale6987TrustZone,
		IngressIfindex: 42,
		IngressVlanID:  0,
		FibIfindex:     11, // ge-0/0/0 — a precise egress arm, never ge-0/0/2
	}
}

// TestRecycledIfindexDoesNotResolveToTheNewOwner6987 is the resolver binding.
//
// RED on revert: `return ifName, zoneBindsIface(...)` -> `return ifName, true`
// makes the resolver answer [ge-0/0/2] for a row whose recorded ingress zone is
// vpn, which is the confident wrong name the issue is about.
func TestRecycledIfindexDoesNotResolveToTheNewOwner6987(t *testing.T) {
	f := stale6987Filter(t, "")

	got := f.resolveIngressIfaces(42, 0, stale6987VPNZone)
	for _, name := range got {
		if name == "ge-0/0/2" {
			t.Errorf("resolveIngressIfaces(42, 0, vpn) = %v: names ge-0/0/2, an interface in "+
				"zone trust that took the tunnel's recycled ifindex and that this session "+
				"never arrived on (#6987)", got)
		}
	}
	if len(got) != 1 || got[0] != "ge-0/0/7.0" {
		t.Errorf("resolveIngressIfaces(42, 0, vpn) = %v, want the recorded ingress zone's "+
			"members [ge-0/0/7.0] — a disputed identity must fall back, not resolve to "+
			"nothing", got)
	}

	// OVER-REACH CONTROL. A CORROBORATED identity must still collapse to the
	// one interface it names: ifindex 42 read from a row whose recorded ingress
	// zone IS trust is the ordinary, non-recycled case and must stay exact. A
	// fix that simply stopped consulting the identity passes every assertion
	// above and fails this one.
	if got := f.resolveIngressIfaces(42, 0, stale6987TrustZone); len(got) != 1 || got[0] != "ge-0/0/2" {
		t.Errorf("resolveIngressIfaces(42, 0, trust) = %v, want [ge-0/0/2]: a corroborated "+
			"identity must still resolve exactly", got)
	}
}

// TestRecycledIfindexIsNotSelectedByInterfaceFilter6987 is the filter binding.
// The same predicate backs `clear security flow session interface <name>`, so a
// selection on an untrustworthy name is a DELETION of sessions that never
// touched the named interface.
func TestRecycledIfindexIsNotSelectedByInterfaceFilter6987(t *testing.T) {
	key, val := stale6987Session()

	for _, tc := range []struct {
		filter string
		want   bool
		why    string
	}{
		{"ge-0/0/2", false, "the recycled ifindex's NEW owner — the session never touched it"},
		{"ge-0/0/7.0", true, "a member of the row's own recorded ingress zone"},
		{"ge-0/0/0", true, "the row's nameable FIB egress interface"},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			f := stale6987Filter(t, tc.filter)
			if got := f.matchesV4(key, val); got != tc.want {
				t.Errorf("matchesV4(filter=%q) = %v, want %v (%s)", tc.filter, got, tc.want, tc.why)
			}
		})
	}

	// OVER-REACH CONTROL: the corroborated case still selects. A session that
	// really did arrive on ge-0/0/2 (recorded ingress zone trust) must still be
	// selected by `interface ge-0/0/2`, or the guard has simply broken the
	// filter rather than narrowed it.
	f := stale6987Filter(t, "ge-0/0/2")
	live := dataplane.SessionValue{
		IngressZone:    stale6987TrustZone,
		EgressZone:     stale6987VPNZone,
		IngressIfindex: 42,
		FibIfindex:     47, // egresses ge-0/0/7.0, so only the ingress arm can match
	}
	if !f.matchesV4(key, live) {
		t.Errorf("a session that genuinely arrived on ge-0/0/2 is no longer selected by " +
			"`interface ge-0/0/2`")
	}
}

// TestDisputedIdentityReportsNoInterfaceName6987 pins the reported column for a
// disputed hit: nothing, even though the recorded ingress zone here binds
// exactly ONE interface and the no-identity rule would have named it. The row
// carries positive evidence that the interface table and its own recorded zone
// disagree, which is where a confident name is most likely to be wrong.
//
// RED on revert: dropping the `if ifName != "" { return "" }` arm of
// ingressIfaceDisplay makes it report ge-0/0/7.0 for a row whose identity
// points somewhere else entirely.
func TestDisputedIdentityReportsNoInterfaceName6987(t *testing.T) {
	f := stale6987Filter(t, "")

	if got := f.ingressIfaceDisplay(42, 0, stale6987VPNZone); got != "" {
		t.Errorf("ingressIfaceDisplay(42, 0, vpn) = %q, want \"\" so the caller reports the "+
			"zone: the identity names ge-0/0/2 and the recorded zone does not bind it, so "+
			"neither name is supportable (#6987)", got)
	}

	// OVER-REACH CONTROLS: the two cases that MUST still produce a name.
	if got := f.ingressIfaceDisplay(42, 0, stale6987TrustZone); got != "ge-0/0/2" {
		t.Errorf("ingressIfaceDisplay(42, 0, trust) = %q, want ge-0/0/2: a corroborated "+
			"identity is still reported exactly", got)
	}
	if got := f.ingressIfaceDisplay(0, 0, stale6987VPNZone); got != "ge-0/0/7.0" {
		t.Errorf("ingressIfaceDisplay(0, 0, vpn) = %q, want ge-0/0/7.0: with NO identity and "+
			"a zone binding exactly one interface, the approximation has one answer and is "+
			"reported", got)
	}
	if got := f.ingressIfaceDisplay(0, 0, stale6987TrustZone); got != "" {
		t.Errorf("ingressIfaceDisplay(0, 0, trust) = %q, want \"\": with NO identity and a "+
			"zone binding TWO interfaces, naming the first claims an interface the row does "+
			"not support", got)
	}
}

// TestShowFlowSessionIfColumnDeclinesDisputedIdentity6987 drives the
// operator-visible surface end to end: `show security flow session`, through
// the real printer, on the #4983 fixture.
//
// The row's recorded ingress identity resolves to `lo.50`, which the fixture
// binds to the TRUST zone — but the row's recorded ingress zone is UNTRUST.
// That is the shape a recycled ifindex produces. The `If:` column must not
// print `lo.50`, and must not print untrust's own single member `ge-0/0/9.0`
// either, because the disagreement is evidence and not merely absence.
func TestShowFlowSessionIfColumnDeclinesDisputedIdentity6987(t *testing.T) {
	lo := loIfindex(t)
	c := ingressIfColumnCLIWith(t, lo, 50, ingressIfColumnUntrustZoneID)
	// #16065: on a host without lo.50 the disputed name cannot arise
	// (the identity is simply unnameable, which prints the zone's
	// single member — a different arm). Skip so the disputed-hit arm
	// is not silently re-ascribed to the fallback.
	requireLoUnitsNameable16065(t, c)
	out := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	got := ingressIfColumnValues(t, out)
	if len(got) != 2 {
		t.Fatalf("want one In line for each of the v4 and v6 sessions, got %d: %q\n%s",
			len(got), got, out)
	}
	for i, name := range got {
		if name == "lo.50" {
			t.Errorf("In-line If: column %d = %q: the identity resolves to an interface the "+
				"row's own recorded ingress zone does not bind, which is what a RECYCLED "+
				"ifindex looks like, and it was printed as fact (#6987)", i, name)
		}
		if name != "untrust" {
			t.Errorf("In-line If: column %d = %q, want the zone name %q", i, name, "untrust")
		}
	}
}
