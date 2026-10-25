package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16862 (R3-B06-02): in xpf_hostinbound the per-zone junos-host jump came
// BEFORE the ICMPv6 error and ND (133-136) accepts. A restricted permit's
// #11065 terminal `meta nfproto ipv6 drop` — including the v6 terminal a
// v4-only permit adds — or an explicit `application any` deny therefore
// dropped NS/NA/RS/RA on that zone, breaking IPv6 neighbour resolution.
//
// The fix emits the mandatory admits (ICMPv6 error 1-4, per-view ND
// honouring `ndp except`, ICMPv4 3/11/12) before the junos-host jumps in
// both the text oracle and the netlink builder (T1 parity). Echo and other
// ICMP stay subject to authored denies.
//
// RED on revert: moving emitHostInboundICMPAccepts back after the jumps
// makes the assertOrder cells below fail (the jump precedes the ICMPv6
// error accept), and the first-match walker again returns "drop" for ND.

func junosHostND16862Config(t *testing.T) (*config.Config, string, []dpuserspace.JunosHostProgram) {
	t.Helper()
	cfg := junosHostDenyTestConfig()
	// Give untrust a v6 local address so the ND scoped admit has a unicast
	// destination union to render.
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses = []string{"10.0.2.10/24", "2001:db8:2::10/64"}
	cfg.Security.AddressBook.Addresses["admin-net"] = &config.Address{Name: "admin-net", Value: "10.0.0.0/24"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("admin-ssh", "src:admin-net", "app:junos-ssh"),
		}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 junos-host program, got %d: %+v", len(programs), programs)
	}
	// Sanity: the v6 terminal drop that caused the defect must be present —
	// without it this test proves nothing.
	cn6 := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip6")
	terminal := `meta nfproto ipv6 counter name "` + cn6 + `" drop`
	if !strings.Contains(payload, terminal) {
		t.Fatalf("fixture lost the #11065 v6 terminal drop %q:\n%s", terminal, payload)
	}
	return cfg, payload, programs
}

func TestJunosHostNDMandatoryAdmitsBeforeJump16862(t *testing.T) {
	_, payload, _ := junosHostND16862Config(t)
	jump := `iifname "ge-0-0-1" jump ` + xnft.HostInboundJunosHostChainName(0, "untrust")
	// Every mandatory admit precedes the fine jump.
	assertOrder(t, payload,
		"icmpv6 type { 1, 2, 3, 4 }",
		jump,
	)
	assertOrder(t, payload,
		"icmp type { destination-unreachable, time-exceeded, parameter-problem }",
		jump,
	)
	ndLines := ndLines15931(payload)
	if len(ndLines) == 0 {
		t.Fatalf("payload lost the ND (133-136) accepts:\n%s", payload)
	}
	for _, l := range ndLines {
		if strings.Index(payload, l) > strings.Index(payload, jump) {
			t.Fatalf("ND accept must precede the junos-host jump: %q\n%s", l, payload)
		}
	}
	// First-match verdicts: ND and ICMPv6 errors are admitted before the
	// subchain can drop them; ssh from a non-admin source is still dropped
	// by the terminal deny; echo stays subject to the authored program.
	if got := junosHostFirstMatch16862(payload, "icmpv6-nd"); got != "accept" {
		t.Fatalf("ND first-match = %q, want accept (jh deny must stay 0)", got)
	}
	if got := junosHostFirstMatch16862(payload, "icmpv6-error"); got != "accept" {
		t.Fatalf("ICMPv6 error first-match = %q, want accept", got)
	}
	if got := junosHostFirstMatch16862(payload, "icmpv4-error"); got != "accept" {
		t.Fatalf("ICMPv4 error first-match = %q, want accept", got)
	}
	if got := junosHostFirstMatch16862(payload, "ssh-nonadmin"); got != "drop" {
		t.Fatalf("non-admin ssh first-match = %q, want terminal drop", got)
	}
	if got := junosHostFirstMatch16862(payload, "echo"); got != "drop" {
		t.Fatalf("echo first-match = %q, want drop (echo stays subject to authored denies)", got)
	}
}

func TestJunosHostNDExceptStillDropsND16862(t *testing.T) {
	// View-level ndp except (ProtocolsExcept, the compiled shape) with a
	// hand-built terminal-drop program on the same ingress: the scoped ND
	// admit must be withdrawn for this view, so ND stays dropped while
	// ICMP errors remain admitted.
	views := []dpuserspace.ZoneHostInboundView{{
		Zone:            "untrust",
		SystemServices:  []string{"ssh"},
		Protocols:       []string{"ospf"},
		ProtocolsExcept: []string{"ndp"},
		V4Addrs:         []string{"10.0.2.10"},
		V6Addrs:         []string{"2001:db8:2::10"},
		IngressNetdevs:  []string{"ge-0-0-1"},
	}}
	programs := []dpuserspace.JunosHostProgram{{
		Zone:           "untrust",
		IngressIfnames: []string{"ge-0-0-1"},
		RulesV6: []config.JunosHostDenyRule{
			{Family: "ip6", SrcAny: true, DstAny: true, Verdict: config.JunosHostDrop},
		},
	}}
	payload := buildHostInboundFilterPayload(views, nil, nil, programs, nil, true)
	// No ND accept may be scoped to this view's ingress or addresses.
	for _, l := range ndLines15931(payload) {
		if strings.Contains(l, `"ge-0-0-1"`) || strings.Contains(l, "2001:db8:2::10") {
			t.Fatalf("ndp-except view admitted ND: %q\n%s", l, payload)
		}
	}
	if got := junosHostFirstMatch16862(payload, "icmpv6-nd"); got != "drop" {
		t.Fatalf("ndp-except ND first-match = %q, want drop", got)
	}
	if got := junosHostFirstMatch16862(payload, "icmpv6-error"); got != "accept" {
		t.Fatalf("ndp-except ICMPv6 error first-match = %q, want accept", got)
	}
}

func TestJunosHostDenyAllND16862(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses = []string{"10.0.2.10/24", "2001:db8:2::10/64"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "deny-all", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 junos-host program, got %d", len(programs))
	}
	if got := junosHostFirstMatch16862(payload, "icmpv6-nd"); got != "accept" {
		t.Fatalf("deny-all ND first-match = %q, want accept", got)
	}
	if got := junosHostFirstMatch16862(payload, "ssh-nonadmin"); got != "drop" {
		t.Fatalf("deny-all ssh first-match = %q, want drop", got)
	}
}

// junosHostFirstMatch16862 walks the rendered input chain in order for a
// synthetic packet class arriving on ge-0-0-1 to the zone's unicast
// address. It models only the rules that can decide these classes: the
// mandatory ICMP accepts, the unconditional iifname-scoped jump into the
// subchain (whose terminal/app-any drop decides ssh and echo), and the
// subchain return. Multicast-group jumps (`ip6 daddr { ff02::... } jump`)
// do not match a unicast packet and are skipped because the jump match
// below requires the bare `iifname "ge-0-0-1" jump` form. Returns the
// first terminal verdict ("accept"/"drop"/"return").
func junosHostFirstMatch16862(payload, class string) string {
	jump := `iifname "ge-0-0-1" jump ` + xnft.HostInboundJunosHostChainName(0, "untrust")
	inInput := false
	for _, l := range strings.Split(payload, "\n") {
		trim := strings.TrimSpace(l)
		if strings.HasPrefix(trim, "chain input {") {
			inInput = true
			continue
		}
		if !inInput {
			continue
		}
		if trim == "}" {
			break
		}
		switch class {
		case "icmpv6-nd":
			if strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
				return "accept"
			}
		case "icmpv6-error":
			if strings.Contains(l, "icmpv6 type { 1, 2, 3, 4 }") && strings.Contains(l, "accept") {
				return "accept"
			}
		case "icmpv4-error":
			if strings.Contains(l, "icmp type { destination-unreachable") && strings.Contains(l, "accept") {
				return "accept"
			}
		}
		if strings.Contains(l, jump) {
			// Enter the subchain in first-match order. For ssh-nonadmin the
			// authored ssh permit (10.0.0.0/24) does not match, so the first
			// deciding rule is the terminal drop; for echo likewise. A
			// `return` ahead of any drop means the packet falls through to
			// the coarse gate (not decided here).
			for _, cl := range junosHostChainLines(payload) {
				if strings.Contains(cl, "return") {
					continue
				}
				if strings.Contains(cl, "drop") {
					return "drop"
				}
			}
			return "return"
		}
	}
	return "return"
}
