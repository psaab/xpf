package nftables

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// host_inbound_any_service_verdict_6618_test.go binds the DECIDED semantics of
// `system-services any-service` on the LIVE netlink build path — the path
// InstallHostInbound actually installs (buildHostInboundNetlink →
// emitHostInboundZoneNetlink → hostInboundAllowsAll), not the pkg/daemon text
// oracle, which has had no non-test caller since the #6387 netlink migration.
//
// #6618 asked whether xpf should narrow `any-service` to the Junos reading.
// Juniper's statement page defines it as "All system services on an entire port
// range including the system services that are not defined" — a PORT-range
// widening over the system-service vocabulary, which is entirely TCP/UDP/ICMP —
// while a separate `host-inbound-traffic protocols` knob carries protocol
// traffic and its own blanket token means "all possible protocols available",
// i.e. that statement's enumerated list. So Junos nowhere admits an arbitrary IP
// protocol number, and xpf's packet-wide reading is a deliberate SUPERSET.
//
// The decision (docs/host-inbound-service-matrix.md, "`any-service` is a
// deliberate superset") is to KEEP the packet-wide reading: narrowing would
// leave no token at all for a raw IP protocol outside the `protocols`
// vocabulary, and an lo0 filter provably cannot rescue a host-inbound deny on
// either enforcement path. This test is what makes that decision a contract
// rather than a comment: it asserts the VERDICT for raw IP protocols, so a
// narrowing turns RED here and has to be an explicit, reviewed flip.
//
// The assertion is on the PROPERTY, not on a rule spelling: the single rule that
// accepts for an `any-service` zone carries no L4 discriminator at all, so an
// OSPF(89) / GRE(47) / VRRP(112) / SCTP(132) packet matches exactly the rule a
// TCP/22 packet matches — and no drop rule exists behind it. The narrow-service
// control below proves the same harness DOES see protocol discrimination and a
// catch-all drop when the zone is not full-admit, so neither assertion can pass
// vacuously.

// anyServiceRawProtocols are the raw IP protocol numbers whose host-inbound
// verdict this file pins. Each is outside the TCP/UDP port space that Junos's
// "entire port range" wording reaches, so each is a case where the xpf superset
// is observable.
var anyServiceRawProtocols = []struct {
	name  string
	proto uint8
}{
	{"ospf", 89}, {"gre", 47}, {"vrrp", 112}, {"pim", 103}, {"sctp", 132},
}

const (
	anyServiceZoneName = "admin"
	anyServiceV4       = "10.0.10.1"
	anyServiceV6       = "2001:db8:10::1"
)

// buildOneZonePlan runs the REAL host-inbound build over a spec holding exactly
// one zone view, so the rules under test come from the production builder rather
// than a hand-assembled rule. No programs / unzoned addresses, so the only DROP
// that can appear is the zone's own #3361 catch-all.
func buildOneZonePlan(t *testing.T, services []string) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_6618", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		NoIPv6RejectZeroHopLimit: true,
		Views: []HostInboundZoneView{{
			Zone:           anyServiceZoneName,
			SystemServices: services,
			V4Addrs:        []string{anyServiceV4},
			V6Addrs:        []string{anyServiceV6},
		}},
	})
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	return p
}

// addrHex renders an address the way canonRule prints a Cmp payload, so the
// rule filter below keys on the zone's own daddr and cannot silently match
// nothing because of a hand-typed constant.
func addrHex(t *testing.T, addr string) string {
	t.Helper()
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("unparseable test address %q", addr)
	}
	if v4 := ip.To4(); v4 != nil {
		return hex.EncodeToString(v4)
	}
	return hex.EncodeToString(ip.To16())
}

// zoneRules returns the canonical form of every built rule that matches the
// zone's own destination address. It FAILS when none does — an empty filter
// result would otherwise satisfy every "must not contain" assertion below.
func zoneRules(t *testing.T, p *nlPlan, addr string) []string {
	t.Helper()
	want := addrHex(t, addr)
	var out []string
	for _, r := range p.rules {
		line := canonRule(p, r)
		if strings.Contains(line, want) {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no built rule carries the zone daddr %s (%s) — the rule filter matched nothing, so nothing below is being tested.\nplan:\n%s",
			addr, want, canonRules(p))
	}
	return out
}

// TestAnyServiceAdmitsEveryIPProtocol6618 is the #6618 decision lock. It fails
// if `any-service` is ever narrowed to the Junos port-range reading without an
// explicit flip of this contract.
//
// FAIL-ON-REVERT: drop "any-service" from config.HostInboundFullAdmitService (or
// give the full-admit branch an L4 predicate) and hostInboundAllowsAll stops
// short-circuiting — the zone falls through to the per-match path, every rule
// gains an l4proto discriminator and the catch-all drop re-arms, turning the
// no-discriminator, no-drop and no-deny-counter assertions RED.
func TestAnyServiceAdmitsEveryIPProtocol6618(t *testing.T) {
	p := buildOneZonePlan(t, []string{"any-service"})

	for _, fam := range []struct {
		family string
		addr   string
	}{{"ip", anyServiceV4}, {"ip6", anyServiceV6}} {
		rules := zoneRules(t, p, fam.addr)
		if len(rules) != 1 {
			t.Fatalf("%s: `any-service` must render exactly ONE rule for the zone's address (the bare full admit); got %d:\n%s",
				fam.family, len(rules), strings.Join(rules, "\n"))
		}
		rule := rules[0]

		// The verdict is accept. verdict(1) is NF_ACCEPT; verdict(0) is NF_DROP.
		if !strings.HasSuffix(rule, "verdict(1)") {
			t.Errorf("%s: the `any-service` rule must end in accept; got %q", fam.family, rule)
		}
		// The property that decides every raw protocol at once: the accepting
		// rule carries NO L4 discriminator. meta(key=16) is NFT_META_L4PROTO and
		// payload(base=2) is NFT_PAYLOAD_TRANSPORT_HEADER — either one would let
		// the rule distinguish protocols. With neither, the match is nfproto +
		// daddr only.
		protocolAgnostic := true
		for _, forbidden := range []string{"meta(key=16", "payload(base=2"} {
			if strings.Contains(rule, forbidden) {
				protocolAgnostic = false
				t.Errorf("%s: the `any-service` rule carries the L4 discriminator %q, so it no longer admits every IP protocol: %q",
					fam.family, forbidden, rule)
			}
		}
		// Logged only once the property actually holds, so a mutated build cannot
		// print an ACCEPT line the ruleset no longer delivers.
		if protocolAgnostic {
			for _, raw := range anyServiceRawProtocols {
				t.Logf("%s: host-bound %s (IP protocol %d) matches %q -> ACCEPT (no L4 discriminator, no drop behind it)",
					fam.family, raw.name, raw.proto, rule)
			}
		}
	}

	// Nothing may drop behind the full admit — the #3361 catch-all is exactly
	// what hostInboundEmitsDrop suppresses for a full-admit zone. A drop here
	// would deny every protocol the bare accept did not reach first.
	for i, r := range p.rules {
		if line := canonRule(p, r); strings.Contains(line, "verdict(0)") {
			t.Errorf("rule %d is a DROP in an `any-service`-only ruleset; nothing may deny behind the full admit: %q", i, line)
		}
	}
	// ... and the deny counter must not even be declared, so the #5719
	// Counted-state read cannot report a deny scope for a zone that never denies.
	for _, family := range []string{"ip", "ip6"} {
		name := HostInboundDenyCounterName(anyServiceZoneName, family)
		for _, got := range p.counters {
			if got == name {
				t.Errorf("deny counter %q declared for an `any-service` zone, which emits no drop", name)
			}
		}
	}
}

// TestNarrowServiceDiscriminatesByProtocol6618 is the non-vacuity control for
// the test above: with a NARROW system-service the same builder, fixture and
// rule filter must produce protocol discrimination, a catch-all drop and a deny
// counter. Without this, an `emitHostInboundZoneNetlink` that emitted nothing at
// all would satisfy every "must not contain" assertion above.
func TestNarrowServiceDiscriminatesByProtocol6618(t *testing.T) {
	p := buildOneZonePlan(t, []string{"ssh"})

	for _, fam := range []struct {
		family string
		addr   string
	}{{"ip", anyServiceV4}, {"ip6", anyServiceV6}} {
		rules := zoneRules(t, p, fam.addr)
		var discriminated, dropped bool
		for _, r := range rules {
			if strings.Contains(r, "meta(key=16") {
				discriminated = true
			}
			if strings.Contains(r, "verdict(0)") {
				dropped = true
			}
		}
		if !discriminated {
			t.Errorf("%s: a narrow `ssh` zone must carry an l4proto discriminator — the control cannot distinguish a full admit from an empty build:\n%s",
				fam.family, strings.Join(rules, "\n"))
		}
		if !dropped {
			t.Errorf("%s: a narrow `ssh` zone must render the #3361 catch-all drop:\n%s",
				fam.family, strings.Join(rules, "\n"))
		}
	}
	for _, family := range []string{"ip", "ip6"} {
		name := HostInboundDenyCounterName(anyServiceZoneName, family)
		found := false
		for _, got := range p.counters {
			if got == name {
				found = true
			}
		}
		if !found {
			t.Errorf("deny counter %q must be declared for a narrow zone; got %v", name, p.counters)
		}
	}
}
