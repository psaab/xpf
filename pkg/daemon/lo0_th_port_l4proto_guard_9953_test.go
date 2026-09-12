package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #9953, text-oracle half. The netlink builder's half lives in
// pkg/nftables/lo0_th_port_l4proto_guard_9953_test.go; both must emit the guard,
// because the oracle is what `nft -f -` loads and the builder is what the
// netlink installer programs, and a term that is guarded on one path and bare on
// the other is a divergence in the host-inbound filter.
//
// The defect: `th sport` / `th dport` compare two bytes at an offset into the
// transport header with nothing establishing that the packet HAS transport
// ports. On the lo0 input chain that means SCTP, GRE and ICMP reaching a
// firewall-local address are judged by a port they do not have.

func rulesForTerm9953(t *testing.T, term *config.FirewallFilterTerm) string {
	t.Helper()
	return strings.Join(nftRulesFromTerm(term, "ip", map[string]*config.PrefixList{}), "\n")
}

// THE REPRODUCTION.
func TestOracleEmitsL4ProtoWithBarePortMatch_9953(t *testing.T) {
	for _, tc := range []struct {
		name string
		term *config.FirewallFilterTerm
	}{
		{"dport", &config.FirewallFilterTerm{Name: "ssh", DestinationPorts: []string{"22"}, Action: "accept"}},
		{"sport", &config.FirewallFilterTerm{Name: "ssh-s", SourcePorts: []string{"22"}, Action: "accept"}},
		{"dport_set", &config.FirewallFilterTerm{Name: "mgmt", DestinationPorts: []string{"22", "161"}, Action: "accept"}},
		{"dport_except", &config.FirewallFilterTerm{Name: "not-ssh", DestPortsExcept: []string{"22"}, Action: "discard"}},
		{"sport_except", &config.FirewallFilterTerm{Name: "not-ssh-s", SourcePortsExcept: []string{"22"}, Action: "discard"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesForTerm9953(t, tc.term)
			if !strings.Contains(got, "meta l4proto") {
				t.Errorf("#9953: the oracle emitted a bare `th %s` with no protocol predicate. "+
					"nft will compare two bytes of a GRE or ICMP header against a port number, so "+
					"an accept term fails OPEN on a chance match and a discard term drops traffic "+
					"the operator never named.\ngot: %q", tc.name, got)
			}
		})
	}
}

// POSITIVE CONTROL: an operator-specified protocol must survive unchanged. The
// fallback must never ADD to a term that already constrains the protocol —
// widening `protocol tcp` to also match UDP would be a fail-open introduced by
// the fix itself.
func TestOracleKeepsTheOperatorsProtocol_9953(t *testing.T) {
	got := rulesForTerm9953(t, &config.FirewallFilterTerm{
		Name: "ssh", Protocols: []string{"tcp"},
		DestinationPorts: []string{"22"}, Action: "accept",
	})
	// tcp resolves to 6 (#3436 numeric spelling).
	if !strings.Contains(got, "meta l4proto 6") {
		t.Fatalf("premise: a `protocol tcp` term must emit `meta l4proto 6`; got %q", got)
	}
	if strings.Contains(got, "17") {
		t.Errorf("#9953: a `protocol tcp` term acquired UDP (17). The fallback applies only "+
			"where the operator named NO protocol.\ngot: %q", got)
	}
}

// An UNRESOLVABLE protocol token is deliberately kept verbatim so `nft -f -`
// REJECTS the whole ruleset and the prior generation is retained (#6806). That
// term HAS a protocol predicate, so the fallback must not fire — replacing a
// deliberate fail-closed with a silently widened rule would undo #6806 on
// exactly the inputs it was written for.
//
// This is why the condition keys on the emitted predicate being empty rather
// than on len(term.Protocols).
func TestOracleDoesNotRescueAnUnresolvableProtocol_9953(t *testing.T) {
	// `junos-gre` is NOT the token to use here: the appid SSOT resolves it to 47,
	// which is the whole point of #3436. Measured, after this cell's premise check
	// caught the first attempt asserting against `meta l4proto 47 th dport 22`.
	const unresolvable = "definitely-not-a-protocol"
	got := rulesForTerm9953(t, &config.FirewallFilterTerm{
		Name: "weird", Protocols: []string{unresolvable},
		DestinationPorts: []string{"22"}, Action: "accept",
	})
	if !strings.Contains(got, unresolvable) {
		t.Fatalf("premise: #6806 keeps an unresolvable token VERBATIM so the load fails "+
			"closed; got %q", got)
	}
	if strings.Contains(got, "meta l4proto { 6, 17 }") {
		t.Errorf("#9953: the fallback fired on a term whose protocol token was kept verbatim "+
			"for #6806. That term is MEANT to reject the ruleset; supplying {tcp, udp} turns a "+
			"deliberate fail-closed into a widened rule that loads.\ngot: %q", got)
	}
}

// A term with an icmp-type already acquires a protocol dependency from the ICMP
// lowering. Adding {tcp, udp} would make the rule match NOTHING — dead for an
// accept term, but a fail-OPEN for a discard term, which would stop dropping
// what it was written to drop.
func TestOracleDoesNotGuardAnICMPTerm_9953(t *testing.T) {
	got := rulesForTerm9953(t, &config.FirewallFilterTerm{
		Name: "icmp-ports", ICMPTypes: []int{8},
		DestinationPorts: []string{"22"}, Action: "discard",
	})
	if strings.Contains(got, "meta l4proto { 6, 17 }") {
		t.Errorf("#9953: the fallback fired on a term carrying an icmp-type. The ICMP lowering "+
			"already supplies the protocol dependency, so this rule would require the packet to "+
			"be BOTH icmp and tcp/udp — it matches nothing, and a `discard` that matches nothing "+
			"is a fail-open.\ngot: %q", got)
	}
}

// A term with no port comparison must not be narrowed at all.
func TestOracleDoesNotNarrowAPortlessTerm_9953(t *testing.T) {
	got := rulesForTerm9953(t, &config.FirewallFilterTerm{
		Name: "from-net", SourceAddresses: []string{"10.0.0.0/8"}, Action: "accept",
	})
	if strings.Contains(got, "meta l4proto") {
		t.Errorf("#9953: a term comparing no port acquired a protocol guard. The guard exists "+
			"to make a PORT comparison meaningful; on a portless term it just narrows the "+
			"operator's rule.\ngot: %q", got)
	}
}

// The two render paths must agree on the TEXT and the NUMBERS, not merely both
// "have a guard". They are driven from one SSOT in pkg/nftables precisely so
// this cannot drift; this cell is what would notice if someone re-derived it.
func TestBothRenderPathsUseTheSameFallback_9953(t *testing.T) {
	got := rulesForTerm9953(t, &config.FirewallFilterTerm{
		Name: "ssh", DestinationPorts: []string{"22"}, Action: "accept",
	})
	want := xnft.Lo0PortFallbackL4ProtoExpr()
	if want == "" {
		t.Fatal("premise: the shared fallback expression resolved to empty")
	}
	if !strings.Contains(got, want) {
		t.Errorf("#9953: the oracle did not emit the SHARED fallback expression %q. Both render "+
			"paths take it from pkg/nftables so they agree by construction; a hand-written copy "+
			"here is how they drift.\ngot: %q", want, got)
	}
}
