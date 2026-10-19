package natshow

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// dest_ports_15226.go — #15226 (A42-02), the port sibling of #7363.
//
// Every NAT display surface rendered a multi-port or port-range DNAT match
// as its FIRST port only: gRPC GetNATDestination copied the singular
// back-compat field into dst_port, GetNATRuleStats appended ":<first>" to
// the destination match, the natshow rule-detail text printed the singular
// field, the in-daemon CLI copies did the same, and REST natDestHandler
// copied the singular field into dst_port. The dataplane enforces the full
// list (coalescePortRanges over Match.DestinationPorts), so an operator or
// audit view understated inward exposure: `destination-port [ 80 443 ]`
// and `destination-port 20000 to 20003` both displayed as the first port.
//
// The plural supersedes the singular rather than joining it, for the same
// reason as the address match (#7363): DestinationPort is the FIRST element
// of DestinationPorts, kept for back-compat, so concatenating the two would
// print the first port twice on every bracket-list rule. A peer-synced or
// hand-built match that carries only the scalar still renders that scalar.
//
// Ports outside 1..65535 are skipped: they can never match a flow (the
// strict commit gate rejects them; the snapshot builder coalesces them
// away), and rendering one as if it were part of the enforced set would be
// the same class of lie in the other direction. A configured-but-unusable
// token therefore renders as no port constraint here; the rule's
// not-installed / strict-gate story is carried by its own surfaces, not by
// inventing a port in this renderer.

// RuleMatchDestPorts returns the rule's complete destination-port match as
// the ordered list of valid ports, plural superseding singular. An empty
// result means the rule carries no (valid) destination-port constraint.
func RuleMatchDestPorts(rule *config.NATRule) []int {
	if rule == nil {
		return nil
	}
	ports := rule.Match.DestinationPorts
	if len(ports) == 0 && rule.Match.DestinationPort != 0 {
		ports = []int{rule.Match.DestinationPort}
	}
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// RuleMatchDestPortsText renders the port set compactly for text surfaces:
// contiguous runs collapse to "low-high" (mirroring the dataplane's
// coalescePortRanges), discrete ports are comma-separated, e.g.
// "80,443", "20000-20003", "80,443,9000-9002". Empty means no constraint.
func RuleMatchDestPortsText(rule *config.NATRule) string {
	ports := RuleMatchDestPorts(rule)
	if len(ports) == 0 {
		return ""
	}
	var parts []string
	lo, hi := ports[0], ports[0]
	flush := func() {
		if lo == hi {
			parts = append(parts, fmt.Sprintf("%d", lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", lo, hi))
		}
	}
	for _, p := range ports[1:] {
		if p == hi+1 {
			hi = p
			continue
		}
		flush()
		lo, hi = p, p
	}
	flush()
	return strings.Join(parts, ",")
}

// RuleMatchDestinationWithPorts renders the destination-address match with
// the complete port set appended as ":<ports>" when a port constraint
// exists — the shared form behind GetNATRuleStats' destination_match and
// the CLI rule-all view, which previously appended only the first port.
func RuleMatchDestinationWithPorts(rule *config.NATRule) string {
	dst := RuleMatchDestination(rule)
	if text := RuleMatchDestPortsText(rule); text != "" {
		dst += ":" + text
	}
	return dst
}
