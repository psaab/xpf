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
	ndAt := map[string]int{} // ifname-hex scope -> first counted ND accept index
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
	}
	if jumpAt < 0 {
		t.Fatalf("junos-host jump not found:\n%s", rules)
	}
	// The discriminating assertion: an ND accept scoped to the
	// any-service view's own ingress must precede the fine jump. A later
	// scoped zone accept cannot help after the terminal subchain drop.
	anyND, ok := ndAt["ge-0-0-1"]
	if !ok || anyND >= jumpAt {
		t.Fatalf("any-service ND accept must precede the junos-host jump; accept rule=%d jump=%d:\n%s", anyND, jumpAt, rules)
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
