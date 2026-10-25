package nftables

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16862: the netlink builder must emit the mandatory L3 admits (ICMPv6
// error 1-4, per-view ND 133-136, ICMPv4 3/11/12) BEFORE the junos-host
// program jump, mirroring the text oracle. Canon order is the verdict:
// an ND accept rendered after the jump is unreachable for a packet the
// subchain's terminal drop matches.
//
// RED on revert: moving emitHostInboundICMPAcceptsNetlink back after the
// jumps makes the ND/error accept indices exceed the jump index here.
func TestHostInboundNetlinkNDBeforeJunosJump16862(t *testing.T) {
	p := newBuildPlan(t, "xpf_16862", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		Views: []HostInboundZoneView{{
			Zone:           "untrust",
			SystemServices: []string{"ssh"},
			V6Addrs:        []string{"2001:db8:2::10"},
			IngressNetdevs: []string{"ge-0-0-1"},
		}},
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
	// Canon renders a jump as verdict(-3) with only the iifname predicate
	// (multicast jumps also carry a daddr set and are excluded — they do
	// not match the unicast ND packet this fix protects).
	jumpAt := -1
	ndAt, err6At, err4At := -1, -1, -1
	for i, r := range p.rules {
		line := canonRule(p, r)
		if strings.HasSuffix(line, "verdict(-3)") && !strings.Contains(line, "payload(base=1") && jumpAt < 0 {
			jumpAt = i
		}
		switch {
		case strings.Contains(line, HostInboundAcceptCounterName(HostInboundAcceptICMP6ND)):
			if ndAt < 0 {
				ndAt = i
			}
		case strings.Contains(line, HostInboundAcceptCounterName(HostInboundAcceptICMP6Error)):
			if err6At < 0 {
				err6At = i
			}
		case strings.Contains(line, HostInboundAcceptCounterName(HostInboundAcceptICMP4Error)):
			if err4At < 0 {
				err4At = i
			}
		}
	}
	if jumpAt < 0 || ndAt < 0 || err6At < 0 || err4At < 0 {
		t.Fatalf("missing rule class (jump=%d nd=%d err6=%d err4=%d):\n%s", jumpAt, ndAt, err6At, err4At, rules)
	}
	if ndAt > jumpAt || err6At > jumpAt || err4At > jumpAt {
		t.Fatalf("mandatory admits must precede the junos-host jump (jump=%d nd=%d err6=%d err4=%d):\n%s",
			jumpAt, ndAt, err6At, err4At, rules)
	}
}
