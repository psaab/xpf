package nftables

import (
	"strings"
	"testing"
)

// netlink_lo0_ports_test.go is the no-kernel parent-RED for the #6405 lo0
// port/DSCP fail-open fix. It asserts the netlink builder RESOLVES a named port
// to the same number nft would (ssh -> 22) and FAILS the plan CLOSED on any
// token it cannot represent numerically — never drops the predicate and widens
// a port/DSCP-constrained rule to match-all. Reverting parsePortTokens/lo0DSCPs
// to the pre-fix omit-on-unparseable behavior turns every fail-closed sub-case
// RED (p.err becomes nil) and the named-port sub-case RED (22 no longer emitted).
func TestLo0PortResolveOrFailClosed(t *testing.T) {
	build := func(t *testing.T, term Lo0FilterTerm) *nlPlan {
		t.Helper()
		p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
		buildLo0FilterNetlink(p, Lo0FilterSpec{NoIPv6RejectZeroHopLimit: true, V4Terms: []Lo0FilterTerm{term}})
		return p
	}

	t.Run("named_dport_resolves_to_number", func(t *testing.T) {
		p := build(t, Lo0FilterTerm{
			Name: "ssh-in", Protocols: []string{"tcp"},
			DestinationPorts: []string{"ssh"}, Action: "accept",
		})
		if p.err != nil {
			t.Fatalf("named port ssh must resolve (not fail), got build error: %v", p.err)
		}
		// nft `th dport ssh` -> port 22 -> cmp against big-endian 0x0016.
		if got := canonRules(p); !strings.Contains(got, "cmp(op=0,reg=1,0016)") {
			t.Errorf("named port ssh must resolve to 22 (0x0016) bit-identically to nft; got:\n%s", got)
		}
	})

	failClosed := []struct {
		name string
		term Lo0FilterTerm
	}{
		{"unresolvable_dport", Lo0FilterTerm{
			Name: "bad-dport", Protocols: []string{"tcp"},
			DestinationPorts: []string{"definitely-not-a-service"}, Action: "accept",
		}},
		{"unresolvable_sport", Lo0FilterTerm{
			Name: "bad-sport", SourcePorts: []string{"nonesuch"}, Action: "accept",
		}},
		{"unresolvable_source_port_except", Lo0FilterTerm{
			Name: "bad-sport-except", SourcePortsExcept: []string{"nonesuch"}, Action: "accept",
		}},
		{"malformed_port_range", Lo0FilterTerm{
			Name: "bad-range", DestinationPorts: []string{"5000-1000"}, Action: "accept",
		}},
		{"unresolvable_dscp", Lo0FilterTerm{
			Name: "bad-dscp", DSCPs: []string{"not-a-dscp"}, Action: "accept",
		}},
	}
	for _, tc := range failClosed {
		t.Run("fail_closed_"+tc.name, func(t *testing.T) {
			p := build(t, tc.term)
			if p.err == nil {
				t.Fatalf("build MUST fail closed on %s: an unrepresentable token was dropped and the "+
					"constrained accept widened to match-all (the #6405 fail-open)", tc.name)
			}
		})
	}
}
