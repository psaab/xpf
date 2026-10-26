package nftables

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17894: the early (pre-junos-host-jump) ND helper still skipped
// any-service retaining views, leaving mixed-zone ND behind the fine
// chain's terminal drop. Fixture: an untrust view with
// system-services any-service PLUS a junos-host terminal-drop program
// (the restricted permit / deny-all hardening shape from #16862), and a
// trust ssh view that retains default ND. Before the fix the helper
// emitted only trust's scoped ND accepts before the jump; an untrust
// NS/NA missed them and was dropped by untrust's fine chain before
// reaching its later coarse any-service admission.
//
// RED on revert: restoring the `(hostInboundAllowsAll(v) && counted)`
// skip makes the untrust-scoped (ge-0-0-1) ND accept before the jump
// disappear, so this test fails.
//
// Controls (non-vacuity): the scoped ssh view also gets an early ND
// accept before the jump (the helper still emits), and an ndp-except
// view gets no early ND accept on its ingress at all (exclusion still
// honoured). Scope keys on the hex-encoded ifname as rendered by the
// canonical form, so the assertions bind to the ingress scope, not to
// any address that happens to share a rule.

func nd17894IfnameHex(name string) string {
	padded := make([]byte, 16)
	copy(padded, name)
	return hex.EncodeToString(padded)
}

func TestHostInboundAnyServiceNDBeforeJunosJump17894(t *testing.T) {
	p := newBuildPlan(t, "xpf_17894", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		Views: []HostInboundZoneView{
			{
				Zone:           "untrust",
				SystemServices: []string{"any-service"},
				V6Addrs:        []string{"2001:db8:2::10"},
				IngressNetdevs: []string{"ge-0-0-1"},
			},
			{
				Zone:           "trust",
				SystemServices: []string{"ssh"},
				V6Addrs:        []string{"2001:db8:1::10"},
				IngressNetdevs: []string{"ge-0-0-0"},
			},
			{
				Zone:            "except",
				SystemServices:  []string{"ssh"},
				ProtocolsExcept: []string{"ndp"},
				V6Addrs:         []string{"2001:db8:3::10"},
				IngressNetdevs:  []string{"ge-0-0-2"},
			},
			{
				Zone:           "open",
				SystemServices: []string{"any-service"},
				V6Addrs:        []string{"2001:db8:4::10"},
				IngressNetdevs: []string{"ge-0-0-3"},
			},
		},
		Programs: []JunosHostProgram{{
			Zone:           "untrust",
			IngressIfnames: []string{"ge-0-0-1"},
			RulesV6: []JunosHostDenyRule{
				{Family: "ip6", SrcAny: true, DstAny: true, Verdict: config.JunosHostDrop},
			},
		}},
		DataplaneFresh: true,
	})
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	rules := canonRules(p)

	// Locate the fine junos-host jump for untrust (same detection as
	// the #16862 order test: a bare verdict(-3) with no payload pred).
	jumpAt := -1
	ndAt := make(map[string]int) // interface scope -> first counted ND accept rule
	unicastNDAt := -1
	targetAddr := addrHex(t, "2001:db8:2::10")
	for i, r := range p.rules {
		line := canonRule(p, r)
		if jumpAt < 0 && strings.HasSuffix(line, "verdict(-3)") && !strings.Contains(line, "payload(base=1") {
			jumpAt = i
			continue
		}
		if !strings.Contains(line, HostInboundAcceptCounterName(HostInboundAcceptICMP6ND)) {
			continue
		}
		if !strings.Contains(line, "verdict(1)") {
			continue
		}
		for _, dev := range []string{"ge-0-0-1", "ge-0-0-0", "ge-0-0-2", "ge-0-0-3"} {
			if strings.Contains(line, nd17894IfnameHex(dev)) {
				if _, ok := ndAt[dev]; !ok {
					ndAt[dev] = i
				}
			}
		}
		if strings.Contains(line, nd17894IfnameHex("ge-0-0-1")) && strings.Contains(line, targetAddr) && unicastNDAt < 0 {
			unicastNDAt = i
		}
	}
	if jumpAt < 0 {
		t.Fatalf("junos-host jump not found:\n%s", rules)
	}
	// The discriminating assertion is the ND accept for untrust's unicast
	// address, not merely its separate ff02::/16 multicast ND accept. A later
	// scoped zone accept cannot help after the terminal subchain drop.
	if unicastNDAt < 0 || unicastNDAt >= jumpAt {
		t.Fatalf("any-service unicast ND accept must precede the junos-host jump; accept rule=%d jump=%d:\n%s", unicastNDAt, jumpAt, rules)
	}
	// Control: the ssh retaining view also gets an early scoped ND accept.
	if trustND, ok := ndAt["ge-0-0-0"]; !ok || trustND >= jumpAt {
		t.Fatalf("ssh retaining view lost its early scoped ND accept (trust=%v jump=%d):\n%s", ndAt["ge-0-0-0"], jumpAt, rules)
	}
	// A full-service view with no fine program stays on its existing later
	// path and gets no early counted ND accept from another zone's program.
	if openND, ok := ndAt["ge-0-0-3"]; ok && openND < jumpAt {
		t.Fatalf("any-service view without a junos-host program got an early counted ND accept; accept rule=%d jump=%d:\n%s", openND, jumpAt, rules)
	}
	// Control: the ndp-except view must get no counted ND accept on its
	// ingress anywhere in the plan.
	if _, ok := ndAt["ge-0-0-2"]; ok {
		t.Fatalf("ndp-except view got a counted ND accept on ge-0-0-2:\n%s", rules)
	}
}

func TestHostInboundAnyServiceNDICMPScreenBeforeJunosJump17894(t *testing.T) {
	views := []HostInboundZoneView{
		{
			Zone:               "untrust",
			SystemServices:     []string{"any-service"},
			V4Addrs:            []string{"192.0.2.10"},
			V6Addrs:            []string{"2001:db8:2::10"},
			ICMPFloodThreshold: 3,
			IngressNetdevs:     []string{"ge-0-0-1"},
		},
		{
			Zone:           "trust",
			SystemServices: []string{"ssh"},
			V4Addrs:        []string{"192.0.2.1"},
			V6Addrs:        []string{"2001:db8:1::10"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
	}
	p := newBuildPlan(t, "xpf_17894_screen", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		Views: views,
		Programs: []JunosHostProgram{{
			Zone:           "untrust",
			IngressIfnames: []string{"ge-0-0-1"},
			RulesV4: []JunosHostDenyRule{
				{Family: "ip", SrcAny: true, DstAny: true, Verdict: config.JunosHostDrop},
			},
		}},
		DataplaneFresh: true,
	})
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	findRules := func(needle string) (int, int) {
		first, count := -1, 0
		for i, r := range p.rules {
			if strings.Contains(canonRule(p, r), needle) {
				if first < 0 {
					first = i
				}
				count++
			}
		}
		return first, count
	}
	ndAt, jumpAt := -1, -1
	targetAddr := addrHex(t, "2001:db8:2::10")
	for i, r := range p.rules {
		line := canonRule(p, r)
		if strings.HasSuffix(line, "verdict(-3)") && !strings.Contains(line, "payload(base=1") && jumpAt < 0 {
			jumpAt = i
		}
		if strings.Contains(line, HostInboundAcceptCounterName(HostInboundAcceptICMP6ND)) &&
			strings.Contains(line, nd17894IfnameHex("ge-0-0-1")) &&
			strings.Contains(line, targetAddr) && strings.Contains(line, "verdict(1)") && ndAt < 0 {
			ndAt = i
		}
	}
	if ndAt < 0 || jumpAt < 0 || ndAt >= jumpAt {
		t.Fatalf("untrust ND accept must remain before the fine junos-host jump (ND=%d jump=%d)", ndAt, jumpAt)
	}
	err6At, err6Count := findRules(HostInboundAcceptCounterName(HostInboundAcceptICMP6Error))
	err4At, err4Count := findRules(HostInboundAcceptCounterName(HostInboundAcceptICMP4Error))
	if err6Count != 1 || err4Count != 1 {
		t.Fatalf("mandatory ICMP accepts missing/duplicated (v6=%d/%d v4=%d/%d)", err6At, err6Count, err4At, err4Count)
	}
	seenV4, seenV6 := false, false
	for _, screen := range HostInboundScreenFloodRules(views) {
		if screen.Protocol != "icmp" && screen.Protocol != "icmpv6" {
			continue
		}
		switch screen.Protocol {
		case "icmp":
			seenV4 = true
		case "icmpv6":
			seenV6 = true
		}
		for _, source := range []bool{true, false} {
			name := HostInboundScreenFloodCounterName(screen, source)
			var screenIndices []int
			for i, r := range p.rules {
				if strings.Contains(canonRule(p, r), name) {
					screenIndices = append(screenIndices, i)
				}
			}
			if len(screenIndices) != 2 {
				t.Fatalf("%s meter rule count = %d, want one reply and one original-direction rule (rules:\n%s)", name, len(screenIndices), canonRules(p))
			}
			replyRules, originalAt := 0, -1
			for _, at := range screenIndices {
				line := canonRule(p, p.rules[at])
				if !strings.Contains(line, "verdict(0)") {
					t.Fatalf("%s screen must retain its over-threshold drop action: %s", name, line)
				}
				if strings.Contains(line, "ct(key=1,") {
					replyRules++
				} else {
					originalAt = at
				}
			}
			if replyRules != 1 || originalAt < 0 {
				t.Fatalf("%s meters need exactly one reply and one original-direction rule (reply=%d original=%d)",
					name, replyRules, originalAt)
			}
			if originalAt >= err6At || originalAt >= err4At || originalAt >= ndAt {
				t.Fatalf("%s original-direction screen must run before every mandatory ICMP/ND accept; screen=%d mandatory-v6=%d mandatory-v4=%d ND=%d",
					name, originalAt, err6At, err4At, ndAt)
			}
		}
	}
	if !seenV4 || !seenV6 {
		t.Fatalf("fixture must exercise both IPv4 and IPv6 ICMP screens (v4=%t v6=%t)", seenV4, seenV6)
	}
}
