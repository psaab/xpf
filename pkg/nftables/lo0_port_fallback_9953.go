package nftables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
)

// #9953: a transport-port comparison with no protocol predicate.
//
// `th sport` / `th dport` load two bytes at an offset into whatever the kernel
// calls the TRANSPORT HEADER and compare them to a port number. The load is
// unconditional — nothing in the rule establishes that the packet is TCP or UDP.
//
// On the `inet xpf_lo0` INPUT chain that is not theoretical. buildLo0FilterNetlink
// fills the chain at nftLo0FilterPriority with policy accept, and its terms carry
// source/destination scopes but no `iif` predicate, so every packet arriving at
// the kernel input hook is evaluated against them. The host-bound set reaching
// that hook is not "TCP and UDP to the firewall":
//
//   - the AF_XDP shim's local-destination arm hands host-bound traffic to the
//     kernel on every bound interface, keyed on the DESTINATION being local and
//     NOT on protocol, so SCTP, GRE and ICMP to a firewall-local address take
//     that arm exactly as TCP and UDP do;
//   - the lifelines (fxp0, em0, fab*) are never AF_XDP-bound at all and are
//     served on the kernel path unconditionally.
//
// So an operator's `destination-port 22` term is evaluated against a GRE or ICMP
// packet, reading two arbitrary header bytes as a port. An `accept` term fails
// OPEN when those bytes happen to match; a `discard` term drops traffic the
// operator never named. Neither is what the configuration says.
//
// Restricting the comparison to {tcp, udp} is the same posture this code already
// takes everywhere a narrowing predicate could go missing — #6405 for ports and
// DSCP, #6512 for addresses, #6806 for protocols. As the protocol lowering puts
// it: a dropped narrowing token is never the safe direction.
//
// This file is the SSOT for that decision because it is made on BOTH render
// paths — the netlink builder in netlink_lo0.go and the nft text oracle in
// pkg/daemon/daemon_nft_term_lower.go. They are checked against each other by
// the parity test, but agreeing by construction is better than agreeing by
// assertion.

// lo0PortFallbackTokens is the protocol set a bare port comparison is restricted
// to. TCP and UDP are the only protocols on this chain for which the two bytes
// at the port offsets ARE ports.
var lo0PortFallbackTokens = []string{"tcp", "udp"}

// Lo0PortFallbackProtocols returns the fallback protocol NUMBERS, resolved
// through the shared appid SSOT rather than written as literals — the same
// resolution the configured-protocol path uses, so the two cannot disagree about
// what "tcp" is.
func Lo0PortFallbackProtocols() []uint8 {
	out := make([]uint8, 0, len(lo0PortFallbackTokens))
	for _, tok := range lo0PortFallbackTokens {
		if n, ok := appid.ProtocolNumber(tok); ok {
			out = append(out, n)
		}
	}
	return out
}

// Lo0PortFallbackL4ProtoExpr renders the nft TEXT form of the same guard, in the
// numeric spelling #3436 requires (nft does not understand this project's Junos
// protocol aliases, and a raw alias is a parse error that rejects the whole
// atomic table).
//
// Returns "" when the protocol set cannot be resolved, which the caller must
// treat as "emit nothing" — an unresolvable fallback is a bug in the SSOT, not
// an operator input, and a malformed predicate would reject the entire ruleset.
func Lo0PortFallbackL4ProtoExpr() string {
	nums := Lo0PortFallbackProtocols()
	if len(nums) == 0 {
		return ""
	}
	if len(nums) == 1 {
		return "meta l4proto " + strconv.Itoa(int(nums[0]))
	}
	parts := make([]string, 0, len(nums))
	for _, n := range nums {
		parts = append(parts, strconv.Itoa(int(n)))
	}
	return fmt.Sprintf("meta l4proto { %s }", strings.Join(parts, ", "))
}

// Lo0NeedsPortProtocolFallback reports whether a term compares a transport port
// while carrying nothing that already constrains the protocol.
//
// The ICMP exclusion is load-bearing and is NOT redundant with the protocol
// check. A term with an icmp-type but no `from protocol` already acquires an
// l4proto predicate from the ICMP lowering itself (nft's `icmp type` carries the
// dependency; the netlink builder's icmpType calls needL4proto). Adding {tcp,
// udp} on top would make the rule match NOTHING — which for an `accept` term is
// merely dead, but for a `discard` term is a fail-OPEN: a rule written to drop
// something stops dropping it. Narrowing a match is only safe when you know
// which direction the verdict points, so the safe move is to leave a
// protocol-constrained term alone.
func Lo0NeedsPortProtocolFallback(hasProtocols, hasICMP, comparesPort bool) bool {
	return comparesPort && !hasProtocols && !hasICMP
}

// Lo0TermComparesPort reports whether any of the four port-token lists is
// populated. Taking the slices rather than a term type lets the netlink builder
// (Lo0FilterTerm) and the nft oracle (config.FirewallFilterTerm) ask the same
// question of their differently-shaped terms.
func Lo0TermComparesPort(srcPorts, dstPorts, srcExcept, dstExcept []string) bool {
	return len(srcPorts) > 0 || len(dstPorts) > 0 || len(srcExcept) > 0 || len(dstExcept) > 0
}
