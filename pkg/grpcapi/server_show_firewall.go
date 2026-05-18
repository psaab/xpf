// Phase 1 of #1043: extract the `firewall` ShowText case body into a
// dedicated method to take the first ~130 LOC bite out of
// `server_show.go`'s 4,072-LOC modularity-discipline violation.
// Semantic relocation — the case body is moved verbatim apart from
// (a) `&buf` references becoming `buf` (now a passed-in
// `*strings.Builder`) and (b) the original `if !hasFilters { ... }
// else { ... }` structure flattened into an early-return form
// (`if !hasFilters { ...; return }; ...`). Output is unchanged.
// The dispatcher in `server_show.go` becomes
// `s.showFirewall(cfg, &buf)`.

package grpcapi

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// showFirewall renders the `cli show firewall` output. Writes to
// `buf`. Returns no error — the original case body had no error
// returns; counters that fail to load are silently skipped (same
// as the original).
func (s *Server) showFirewall(cfg *config.Config, buf *strings.Builder) {
	hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
	if !hasFilters {
		buf.WriteString("No firewall filters configured\n")
		return
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := s.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)
	// Resolve filter IDs for counter display
	var filterIDs map[string]uint32
	if s.dp != nil && s.dp.IsLoaded() {
		if cr := s.applyResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}

	printFilters := func(family string, filters map[string]*config.FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			fmt.Fprintf(buf, "Filter: %s (family %s)\n", name, family)

			// Get filter config for counter lookup
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+name]; ok {
					if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					}
				}
			}
			ruleOffset := ruleStart

			for _, term := range filter.Terms {
				fmt.Fprintf(buf, "  Term: %s\n", term.Name)
				if term.DSCP != "" {
					fmt.Fprintf(buf, "    from dscp %s\n", term.DSCP)
				}
				if term.Protocol != "" {
					fmt.Fprintf(buf, "    from protocol %s\n", term.Protocol)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Fprintf(buf, "    from source-address %s\n", addr)
				}
				for _, pl := range term.SourcePrefixLists {
					if pl.Except {
						fmt.Fprintf(buf, "    from source-prefix-list %s except\n", pl.Name)
					} else {
						fmt.Fprintf(buf, "    from source-prefix-list %s\n", pl.Name)
					}
				}
				for _, addr := range term.DestAddresses {
					fmt.Fprintf(buf, "    from destination-address %s\n", addr)
				}
				for _, pl := range term.DestPrefixLists {
					if pl.Except {
						fmt.Fprintf(buf, "    from destination-prefix-list %s except\n", pl.Name)
					} else {
						fmt.Fprintf(buf, "    from destination-prefix-list %s\n", pl.Name)
					}
				}
				if len(term.SourcePorts) > 0 {
					fmt.Fprintf(buf, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
				}
				if len(term.DestinationPorts) > 0 {
					fmt.Fprintf(buf, "    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
				}
				if term.ICMPType >= 0 {
					fmt.Fprintf(buf, "    from icmp-type %d\n", term.ICMPType)
				}
				if term.ICMPCode >= 0 {
					fmt.Fprintf(buf, "    from icmp-code %d\n", term.ICMPCode)
				}
				if term.RoutingInstance != "" {
					fmt.Fprintf(buf, "    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.Log {
					buf.WriteString("    then log\n")
				}
				if term.Count != "" {
					fmt.Fprintf(buf, "    then count %s\n", term.Count)
				}
				if term.ForwardingClass != "" {
					fmt.Fprintf(buf, "    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Fprintf(buf, "    then loss-priority %s\n", term.LossPriority)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				fmt.Fprintf(buf, "    then %s\n", action)

				numRules := firewallFilterTermExpansionCount(cfg, term)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						}
					}
					ruleOffset += numRules
				}
				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: name, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				if hasCounters || userspaceOk {
					fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			buf.WriteString("\n")
		}
	}
	printFilters("inet", cfg.Firewall.FiltersInet)
	printFilters("inet6", cfg.Firewall.FiltersInet6)
}
