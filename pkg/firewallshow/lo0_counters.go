package firewallshow

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// Lo0CountersForFilter returns the kernel lo0 counters to render beside the
// RAW view of one filter, or nil when the filter is not the lo0 input filter
// for its family (#16457). The kernel `inet xpf_lo0` chain enforces the lo0
// filter for ALL host-stack traffic (including fxp0 management traffic that
// never reaches the AF_XDP helper), while the helper also evaluates the same
// filter for AF_XDP host-bound packets — so a lo0 filter's per-term helper
// "Hit count" is only part of the picture. The kernel named counters are
// keyed by `then count <name>` and shared across terms and families (Junos
// named-counter semantics), so they are returned per count name, not merged
// into the per-term helper totals.
//
// lookup is the ReadLo0Counters-shaped source, a parameter so both show
// surfaces can seam it in tests; a nil lookup yields nil. A read error is
// returned so the caller can surface "counter unavailable" rather than a
// misleading absence (the #3345 missing-sample contract). When the filter is
// not lo0-referenced the lookup is never invoked, so non-lo0 filters are
// byte-unchanged and pay no netlink read.
func Lo0CountersForFilter(cfg *config.Config, family, filterName string, lookup func() ([]xnft.Lo0Count, error)) ([]xnft.Lo0Count, error) {
	if cfg == nil || lookup == nil {
		return nil, nil
	}
	lo0Name := ""
	switch family {
	case "inet":
		lo0Name = cfg.System.Lo0FilterInputV4
	case "inet6":
		lo0Name = cfg.System.Lo0FilterInputV6
	default:
		return nil, nil
	}
	if lo0Name == "" || lo0Name != filterName {
		return nil, nil
	}
	return lookup()
}

// WriteLo0KernelCounters renders the kernel `inet xpf_lo0` named counters
// relevant to a filter's terms, labelled by count name (#16457). Only count
// names actually referenced by the filter's `then count` terms are shown:
// the kernel object for an unreferenced name (a stale rebuild artifact or a
// name shared with the other family's lo0 filter) is not this filter's
// count. Lines are emitted in the order the counters were read. Callers
// invoke this only for a lo0-referenced filter (see Lo0CountersForFilter).
func WriteLo0KernelCounters(buf *strings.Builder, filter *config.FirewallFilter, counts []xnft.Lo0Count) {
	if filter == nil || len(counts) == 0 {
		return
	}
	wanted := map[string]bool{}
	for _, term := range filter.Terms {
		if term != nil && term.Count != "" {
			wanted[term.Count] = true
		}
	}
	if len(wanted) == 0 {
		return
	}
	for _, ctr := range counts {
		if !wanted[ctr.Counter] {
			continue
		}
		fmt.Fprintf(buf, "    Kernel lo0 counter %s: %d packets, %d bytes (inet xpf_lo0 chain; includes host-stack traffic such as fxp0 that bypasses the helper)\n", ctr.Counter, ctr.Packets, ctr.Bytes)
	}
}

// WriteLo0ImplicitDiscardCounter renders the kernel lo0 chain's implicit
// final discard counter for a lo0 filter with no terminal catch-all (#18728).
// It writes nothing for a filter with a catch-all (no such rule is
// installed) or when the read returned no row for this family. The kernel
// drop exempts loopback and the cluster control/fabric links
// (config.Lo0ImplicitDiscardExemptNetdevs), which the line says so the count
// is not read as all unmatched host-bound traffic. Callers invoke this only
// for a lo0-referenced filter (see Lo0CountersForFilter).
func WriteLo0ImplicitDiscardCounter(buf *strings.Builder, filter *config.FirewallFilter, family string, counts []xnft.Lo0Count) {
	if filter == nil || config.FirewallFilterHasCatchAll(filter) {
		return
	}
	for _, ctr := range counts {
		if ctr.ImplicitDiscardFamily != family {
			continue
		}
		fmt.Fprintf(buf, "    Kernel lo0 implicit-discard: %d packets, %d bytes (inet xpf_lo0 chain; unmatched host-bound %s traffic, except loopback and the cluster control/fabric links)\n", ctr.Packets, ctr.Bytes, family)
		return
	}
}
