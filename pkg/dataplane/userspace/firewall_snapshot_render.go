package userspace

import (
	"fmt"
	"strconv"
	"strings"
)

// RenderFirewallFilterSnapshot renders one compiled FirewallFilterSnapshot as
// the operator-facing `show firewall ... effective` block and returns it as a
// string (#4967). It is the single source of truth for that rendering, shared
// by the local CLI (pkg/cli), the gRPC ShowText server (pkg/grpcapi), and thus
// the remote CLI — so the advertised grammar and the executable rendering can
// no longer drift across surfaces.
//
// The `[effective]` tag in the heading distinguishes it from the raw
// `show firewall filter` output. Terms are printed exactly as the matcher
// enforces them: prefix-list references resolved to literal prefixes,
// address/port `except` folded, DSCP tokens resolved to numeric code points,
// TCP-flags lowered to required/forbidden masks, `then next term` fall-through
// computed, and any unrepresentable match marked fail-closed.
func RenderFirewallFilterSnapshot(snap *FirewallFilterSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Filter: %s (family %s) [effective]\n", snap.Name, snap.Family)
	if len(snap.Terms) == 0 {
		b.WriteString("  (no terms — matches nothing)\n")
		b.WriteString("\n")
		return b.String()
	}
	for i := range snap.Terms {
		term := &snap.Terms[i]
		fmt.Fprintf(&b, "  Term: %s\n", term.Name)

		// --- from (match conditions, as lowered for the matcher) ---
		if s := effectiveAddrMatchLine("source", term.SourceAddresses, term.SourceExcept, term.SourceConstrained); s != "" {
			b.WriteString(s)
		}
		if s := effectiveAddrMatchLine("destination", term.DestAddresses, term.DestExcept, term.DestConstrained); s != "" {
			b.WriteString(s)
		}
		if term.AddressUnrepresentable {
			fmt.Fprintf(&b, "    from address <unrepresentable — snapshot fails closed>\n")
		}
		// #9875: a whole `from` leaf the dataplane does not enforce (or a
		// value-bearing leaf written with no operand) — the snapshot carrying
		// this term is refused, so `effective` shows the refusal, never the
		// widened match the pre-fix builder shipped.
		if term.FromUnrepresentable {
			fmt.Fprintf(&b, "    from <unrepresentable — snapshot fails closed>\n")
		}
		for _, p := range term.Protocols {
			fmt.Fprintf(&b, "    from protocol %s\n", p)
		}
		if len(term.SourcePorts) > 0 {
			fmt.Fprintf(&b, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
		}
		if len(term.SourcePortsExcept) > 0 {
			fmt.Fprintf(&b, "    from source-port-except %s\n", strings.Join(term.SourcePortsExcept, ", "))
		}
		if len(term.DestPorts) > 0 {
			fmt.Fprintf(&b, "    from destination-port %s\n", strings.Join(term.DestPorts, ", "))
		}
		if len(term.DestPortsExcept) > 0 {
			fmt.Fprintf(&b, "    from destination-port-except %s\n", strings.Join(term.DestPortsExcept, ", "))
		}
		if term.PortsUnrepresentable {
			fmt.Fprintf(&b, "    from port <unrepresentable — snapshot fails closed>\n")
		}
		if len(term.DSCPValues) > 0 {
			fmt.Fprintf(&b, "    from dscp %s\n", formatWireUint8List(term.DSCPValues))
		}
		if term.DSCPMatchUnrepresentable {
			fmt.Fprintf(&b, "    from dscp <unrepresentable — snapshot fails closed>\n")
		}
		if len(term.ICMPTypes) > 0 {
			fmt.Fprintf(&b, "    from icmp-type %s\n", formatWireUint8List(term.ICMPTypes))
		}
		if term.ICMPTypeUnrepresentable {
			fmt.Fprintf(&b, "    from icmp-type <unrepresentable — snapshot fails closed>\n")
		}
		if len(term.ICMPCodes) > 0 {
			fmt.Fprintf(&b, "    from icmp-code %s\n", formatWireUint8List(term.ICMPCodes))
		}
		if term.ICMPCodeUnrepresentable {
			fmt.Fprintf(&b, "    from icmp-code <unrepresentable — snapshot fails closed>\n")
		}
		if term.TCPFlags != nil {
			fmt.Fprintf(&b, "    from tcp-flags require 0x%02x\n", *term.TCPFlags)
		}
		if term.TCPFlagsForbidden != nil {
			fmt.Fprintf(&b, "    from tcp-flags forbid 0x%02x\n", *term.TCPFlagsForbidden)
		}
		if term.TCPFlagsUnparseable {
			fmt.Fprintf(&b, "    from tcp-flags <unparseable — snapshot fails closed>\n")
		}
		if term.IsFragment {
			fmt.Fprintf(&b, "    from is-fragment\n")
		}
		if fm := term.FlexMatch; fm != nil {
			base := fm.MatchStart
			if base == "" {
				base = "layer-3"
			}
			fmt.Fprintf(&b, "    from flexible-match-range match-start %s offset %d length %d value 0x%x mask 0x%x\n",
				base, fm.Offset, fm.Length, fm.Value, fm.Mask)
		}

		// --- then (action + modifiers) ---
		if term.RoutingInstance != "" {
			fmt.Fprintf(&b, "    then routing-instance %s\n", term.RoutingInstance)
		}
		if term.ForwardingClass != "" {
			fmt.Fprintf(&b, "    then forwarding-class %s\n", term.ForwardingClass)
		}
		if term.PolicerName != "" {
			fmt.Fprintf(&b, "    then policer %s\n", term.PolicerName)
		}
		if term.DSCPRewrite != nil {
			fmt.Fprintf(&b, "    then dscp %d\n", *term.DSCPRewrite)
		}
		if term.Log {
			fmt.Fprintf(&b, "    then log\n")
		}
		// #6853: rendered in ADDITION to `then log`, not instead of it — a
		// `then syslog` term carries both bits, and dropping the `log` line
		// would misrepresent the term the dataplane was actually given.
		if term.Syslog {
			fmt.Fprintf(&b, "    then syslog\n")
		}
		if term.Count != "" {
			fmt.Fprintf(&b, "    then count %s\n", term.Count)
		}
		// NextTerm marks a fall-through term (no terminating action); a
		// non-fall-through term terminates with its action (default accept).
		if term.NextTerm {
			fmt.Fprintf(&b, "    then next term (fall-through)\n")
		} else {
			action := term.Action
			if action == "" {
				action = "accept"
			}
			// #6854: render the reject message-type alongside the action, so a
			// term configured `then reject host-unreachable` is distinguishable
			// in the snapshot from a bare `then reject`.
			if term.RejectMessageType != "" {
				fmt.Fprintf(&b, "    then %s %s\n", action, term.RejectMessageType)
			} else {
				fmt.Fprintf(&b, "    then %s\n", action)
			}
		}
	}
	b.WriteString("\n")
	return b.String()
}

// effectiveAddrMatchLine formats one direction's compiled address match. It
// distinguishes the four post-resolution states the matcher enforces
// (resolvePrefixListAddrs / ResolveFilterPrefixListAddrs): unconstrained
// (matches any — emits nothing), a positive set (empty positive = matches
// nothing, fail-closed), an `except` set (empty except = matches any), and the
// populated forms.
func effectiveAddrMatchLine(dir string, addrs []string, except, constrained bool) string {
	if !constrained {
		return ""
	}
	switch {
	case except && len(addrs) == 0:
		return fmt.Sprintf("    from %s-address except (empty set — matches any)\n", dir)
	case except:
		return fmt.Sprintf("    from %s-address except %s\n", dir, strings.Join(addrs, ", "))
	case len(addrs) == 0:
		return fmt.Sprintf("    from %s-address (empty set — matches nothing)\n", dir)
	default:
		return fmt.Sprintf("    from %s-address %s\n", dir, strings.Join(addrs, ", "))
	}
}

// formatWireUint8List renders a compiled uint8 match set (DSCP code points,
// ICMP type/code bytes) as comma-separated decimals.
func formatWireUint8List(vals WireUint8List) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ", ")
}
