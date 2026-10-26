package nftables

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/psaab/xpf/pkg/config"
)

// TestColdBootFenceRetainsCatalogDropsAndESPAHAdmit17879 is RED on revert of
// the #17879 fence restoration: zero-hop rejection must coexist with the
// catalog multicast drops and global ESP/AH admit, not replace them.
func TestColdBootFenceRetainsCatalogDropsAndESPAHAdmit17879(t *testing.T) {
	for _, tc := range []struct {
		name          string
		noZeroHopDrop bool
	}{
		{name: "default_zero_hop_reject"},
		{name: "zero_hop_opt_out", noZeroHopDrop: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newBuildPlan(t, HostInboundTableName, hostInboundPriority)
			buildHostInboundFenceNetlink(p, FenceSpec{
				NoIPv6RejectZeroHopLimit: tc.noZeroHopDrop,
				Views: []HostInboundZoneView{
					{
						Zone: "routing", V4Addrs: []string{"192.0.2.1"}, V6Addrs: []string{"2001:db8::1"},
						IngressNetdevs: []string{"routing0"},
					},
					{
						Zone: "routing-vrf",
						IngressVRFScopes: []config.HostInboundVRFIngressScope{{
							Master: "vrf-routing", Slaves: []string{"ge-0-0-0"},
						}},
					},
				},
			})
			if p.err != nil {
				t.Fatalf("build cold-boot fence: %v", p.err)
			}

			zeroHopAt, espAHAt, establishedAt := -1, -1, -1
			for i, rule := range p.rules {
				var sawHopLimit, sawFib, sawDrop bool
				for _, e := range rule {
					switch x := e.(type) {
					case *expr.Payload:
						if x.Base == expr.PayloadBaseNetworkHeader && x.Offset == 7 && x.Len == 1 {
							sawHopLimit = true
						}
					case *expr.Fib:
						sawFib = true
					case *expr.Verdict:
						if x.Kind == expr.VerdictDrop {
							sawDrop = true
						}
					}
				}
				if sawHopLimit && sawFib && sawDrop {
					zeroHopAt = i
				}

				line := canonRule(p, rule)
				if line == "meta(key=16,reg=1) lookup(inv=false,set=[32,33]) verdict(1)" {
					espAHAt = i
				}
				if line == "ct(key=0,reg=1) bitwise(len=4,mask=06000000,xor=00000000) cmp(op=1,reg=1,00000000) verdict(1)" {
					establishedAt = i
				}
			}

			if tc.noZeroHopDrop {
				if zeroHopAt >= 0 {
					t.Fatalf("zero-hop opt-out still emitted local drop at rule %d", zeroHopAt)
				}
			} else if zeroHopAt < 0 {
				t.Fatal("default fence is missing the zero-hop-limit local drop")
			}
			if espAHAt < 0 {
				t.Fatal("cold-boot fence is missing the global ESP/AH accept")
			}
			if establishedAt < 0 {
				t.Fatal("cold-boot fence is missing the established/related accept")
			}
			if zeroHopAt >= 0 && zeroHopAt >= espAHAt {
				t.Fatalf("zero-hop drop rule %d must precede ESP/AH accept rule %d", zeroHopAt, espAHAt)
			}

			ingressScopes := []struct {
				name    string
				ifnames []string
			}{
				{name: "direct", ifnames: []string{"routing0"}},
				{name: "VRF", ifnames: []string{"vrf-routing", "ge-0-0-0"}},
			}
			for _, ingress := range ingressScopes {
				for _, family := range []string{"ip", "ip6"} {
					for _, group := range config.HostInboundMulticastGroupsForFamily(family) {
						wantAddr := addrHex(t, group)
						matched := false
						for i, rule := range p.rules {
							line := canonRule(p, rule)
							if i <= espAHAt || i >= establishedAt ||
								!strings.Contains(line, wantAddr) || !strings.Contains(line, "verdict(0)") {
								continue
							}
							scoped := true
							for _, ifname := range ingress.ifnames {
								scoped = scoped && strings.Contains(line, hex.EncodeToString(ifname16(ifname)))
							}
							if scoped {
								matched = true
								break
							}
						}
						if !matched {
							t.Errorf("catalog group %s has no %s-scoped fence drop before established acceptance", group, ingress.name)
						}
					}
				}
			}
		})
	}
}
