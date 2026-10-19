// Package firewallshow renders the raw (authored-config) `show firewall`
// view from config.FirewallFilterTerm so the local CLI, the gRPC ShowText
// server, and the REST show-text handler emit the same term lines and
// cannot drift apart (#15173, B18-02).
//
// Before this package each surface hand-rolled its own subset: except-ports,
// tcp-flags, is-fragment, flexible-match-range, reject message-type,
// policer, syslog, and explicit `next term` were dropped on one or more
// surfaces, and an empty Action — which is either an authored `next term`
// fall-through or a modifier-only term that terminates as implicit accept
// (#14632) — was printed as a bare terminating `accept`. A narrow discard
// (for example `tcp except port 22, discard`) therefore read as a broad
// discard, and a fall-through term read as an accept.
//
// The renderer is raw, not effective: it prints authored values verbatim
// (DSCP tokens, port names, prefix-list references with their `except`
// flag, authored tcp-flags strings, the FlexMatchConfig as authored). It
// does NOT resolve prefix lists, lower tcp-flags to masks, or mark
// unrepresentable matches — that compiled view is
// dpuserspace.RenderFirewallFilterSnapshot (`show firewall effective`).
//
// Hit-count / policer-status lines are dataplane state, not term config,
// and stay with each caller after the shared term block.
package firewallshow

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// SortedFilterNames returns the non-nil, non-suppressed filter names in
// deterministic order for the all-filters view.
func SortedFilterNames(filters map[string]*config.FirewallFilter) []string {
	names := make([]string, 0, len(filters))
	for name, f := range filters {
		if f == nil {
			continue
		}
		if source, _ := f.SuppressedMemberFBF11321(); source != "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// WriteFilterHeader writes the `Filter: <name> (family <family>)` heading.
func WriteFilterHeader(buf *strings.Builder, name, family string) {
	fmt.Fprintf(buf, "Filter: %s (family %s)\n", name, family)
}

// WriteTerm writes one raw term: the `  Term:` line (optionally preceded by
// a blank line, matching the per-filter view), every authored `from`
// predicate, and every `then` modifier/action. A nil term writes nothing.
func WriteTerm(buf *strings.Builder, term *config.FirewallFilterTerm, leadingBlank bool) {
	if term == nil {
		return
	}
	if leadingBlank {
		buf.WriteString("\n")
	}
	fmt.Fprintf(buf, "  Term: %s\n", term.Name)
	for _, d := range term.DSCPs {
		fmt.Fprintf(buf, "    from dscp %s\n", d)
	}
	for _, p := range term.Protocols {
		fmt.Fprintf(buf, "    from protocol %s\n", p)
	}
	for _, addr := range term.SourceAddresses {
		fmt.Fprintf(buf, "    from source-address %s\n", addr)
	}
	for _, ref := range term.SourcePrefixLists {
		mod := ""
		if ref.Except {
			mod = " except"
		}
		fmt.Fprintf(buf, "    from source-prefix-list %s%s\n", ref.Name, mod)
	}
	for _, addr := range term.DestAddresses {
		fmt.Fprintf(buf, "    from destination-address %s\n", addr)
	}
	for _, ref := range term.DestPrefixLists {
		mod := ""
		if ref.Except {
			mod = " except"
		}
		fmt.Fprintf(buf, "    from destination-prefix-list %s%s\n", ref.Name, mod)
	}
	if len(term.SourcePorts) > 0 {
		fmt.Fprintf(buf, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
	}
	if len(term.DestinationPorts) > 0 {
		fmt.Fprintf(buf, "    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
	}
	if len(term.SourcePortsExcept) > 0 {
		fmt.Fprintf(buf, "    from source-port-except %s\n", strings.Join(term.SourcePortsExcept, ", "))
	}
	if len(term.DestPortsExcept) > 0 {
		fmt.Fprintf(buf, "    from destination-port-except %s\n", strings.Join(term.DestPortsExcept, ", "))
	}
	for _, t := range term.ICMPTypes {
		fmt.Fprintf(buf, "    from icmp-type %d\n", t)
	}
	for _, c := range term.ICMPCodes {
		fmt.Fprintf(buf, "    from icmp-code %d\n", c)
	}
	if len(term.TCPFlags) > 0 {
		fmt.Fprintf(buf, "    from tcp-flags %s\n", strings.Join(term.TCPFlags, ", "))
	}
	if term.IsFragment {
		buf.WriteString("    from is-fragment\n")
	}
	if fm := term.FlexMatch; fm != nil {
		base := fm.MatchStart
		if base == "" {
			base = "layer-3"
		}
		fmt.Fprintf(buf, "    from flexible-match-range match-start %s offset %d length %d value 0x%x mask 0x%x\n",
			base, fm.ByteOffset, fm.BitLength, fm.Value, fm.Mask)
	}
	if term.RoutingInstance != "" {
		fmt.Fprintf(buf, "    then routing-instance %s\n", term.RoutingInstance)
	}
	if term.ForwardingClass != "" {
		fmt.Fprintf(buf, "    then forwarding-class %s\n", term.ForwardingClass)
	}
	if term.LossPriority != "" {
		fmt.Fprintf(buf, "    then loss-priority %s\n", term.LossPriority)
	}
	if term.DSCPRewrite != "" {
		buf.WriteString(DSCPRewriteLine(term.DSCPRewrite))
	}
	if term.Log {
		buf.WriteString("    then log\n")
	}
	// #6853: `then syslog` sets Log too; render both so the raw view does
	// not hide the authored syslog sink behind the log line.
	if term.Syslog {
		buf.WriteString("    then syslog\n")
	}
	if term.Count != "" {
		fmt.Fprintf(buf, "    then count %s\n", term.Count)
	}
	if term.Policer != "" {
		fmt.Fprintf(buf, "    then policer %s\n", term.Policer)
	}
	writeThenAction(buf, term)
}

// writeThenAction renders the terminating disposition honestly (#15173):
// an authored `next term` with no terminating action and no
// routing-instance is a fall-through, a modifier-only term (empty action,
// no next-term bit) terminates as implicit accept (#14632), a
// routing-instance term terminates on its routing decision, and a
// contradictory next-term bit beside a terminating action/routing-instance
// is disclosed as ignored rather than printed as fall-through (#10012).
func writeThenAction(buf *strings.Builder, term *config.FirewallFilterTerm) {
	fallThrough := term.NextTerm && term.Action == "" && term.RoutingInstance == ""
	if fallThrough {
		buf.WriteString("    then next term\n")
		return
	}
	if term.Action != "" {
		if term.RejectMessageType != "" {
			fmt.Fprintf(buf, "    then %s %s\n", term.Action, term.RejectMessageType)
		} else {
			fmt.Fprintf(buf, "    then %s\n", term.Action)
		}
	} else if term.RoutingInstance == "" {
		// Modifier-only: Junos nonterminating actions carry an implicit
		// accept and terminate (#14632) — never a fall-through.
		buf.WriteString("    then accept\n")
	}
	// Routing-instance alone terminates on the routing-instance line above.
	if term.NextTerm {
		buf.WriteString("    then next term (ignored — contradictory with terminating action)\n")
	}
}

// WriteAllFilters renders the complete raw all-filters view (both families,
// sorted, suppressed-member clones hidden) without hit counts. An empty
// config renders the no-filters notice.
func WriteAllFilters(buf *strings.Builder, cfg *config.Config) {
	if cfg == nil || (len(cfg.Firewall.FiltersInet) == 0 && len(cfg.Firewall.FiltersInet6) == 0) {
		buf.WriteString("No firewall filters configured\n")
		return
	}
	writeFamily := func(family string, filters map[string]*config.FirewallFilter) {
		for _, name := range SortedFilterNames(filters) {
			WriteFilterHeader(buf, name, family)
			for _, term := range filters[name].Terms {
				WriteTerm(buf, term, false)
			}
			buf.WriteString("\n")
		}
	}
	writeFamily("inet", cfg.Firewall.FiltersInet)
	writeFamily("inet6", cfg.Firewall.FiltersInet6)
}
