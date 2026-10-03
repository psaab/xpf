package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *CLI) showFirewallFilters() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.Firewall.FiltersInet) == 0 && len(cfg.Firewall.FiltersInet6) == 0 {
		fmt.Println("No firewall filters configured")
		return nil
	}

	// Look up filter IDs from compile result for counter display
	var filterIDs map[string]uint32
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	// #3408: surface a filter counter read failure as a warning AFTER all
	// filters, rather than printing clean-zero / omitted hit counts.
	var readErr error
	showFilters := func(family string, filters map[string]*config.FirewallFilter, names []string) {
		for _, name := range names {
			f := filters[name]
			fmt.Printf("Filter: %s (family %s)\n", name, family)

			// Get filter config for counter lookup
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+name]; ok {
					if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					} else if readErr == nil {
						readErr = err
					}
				}
			}

			ruleOffset := ruleStart
			for _, term := range f.Terms {
				fmt.Printf("  Term: %s\n", term.Name)
				for _, d := range term.DSCPs {
					fmt.Printf("    from dscp %s\n", d)
				}
				for _, p := range term.Protocols {
					fmt.Printf("    from protocol %s\n", p)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Printf("    from source-address %s\n", addr)
				}
				for _, addr := range term.DestAddresses {
					fmt.Printf("    from destination-address %s\n", addr)
				}
				for _, port := range term.DestinationPorts {
					fmt.Printf("    from destination-port %s\n", port)
				}
				for _, port := range term.SourcePorts {
					fmt.Printf("    from source-port %s\n", port)
				}
				for _, ref := range term.SourcePrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
				}
				for _, ref := range term.DestPrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
				}
				for _, t := range term.ICMPTypes {
					fmt.Printf("    from icmp-type %d\n", t)
				}
				for _, c := range term.ICMPCodes {
					fmt.Printf("    from icmp-code %d\n", c)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				if term.RoutingInstance != "" {
					fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.ForwardingClass != "" {
					fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Printf("    then loss-priority %s\n", term.LossPriority)
				}
				if term.DSCPRewrite != "" {
					fmt.Print(filterDSCPRewriteLine(term.DSCPRewrite))
				}
				if term.Log {
					fmt.Printf("    then log\n")
				}
				if term.Count != "" {
					fmt.Printf("    then count %s\n", term.Count)
				}
				fmt.Printf("    then %s\n", action)

				// Sum counters across all expanded BPF rules for this term.
				// Stride comes from the shared SSOT (#3459) so CLI, gRPC, and
				// Prometheus agree with the compiler's expandFilterTerm layout.
				numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						} else if readErr == nil {
							readErr = err
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
					fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			fmt.Println()
		}
	}

	// Sort filter names for deterministic output (matches compiler order)
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name, filter := range cfg.Firewall.FiltersInet {
		if filter == nil {
			continue
		}
		if source, _ := filter.SuppressedMemberFBF11321(); source == "" {
			inetNames = append(inetNames, name)
		}
	}
	sort.Strings(inetNames)

	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name, filter := range cfg.Firewall.FiltersInet6 {
		if filter == nil {
			continue
		}
		if source, _ := filter.SuppressedMemberFBF11321(); source == "" {
			inet6Names = append(inet6Names, name)
		}
	}
	sort.Strings(inet6Names)

	showFilters("inet", cfg.Firewall.FiltersInet, inetNames)
	showFilters("inet6", cfg.Firewall.FiltersInet6, inet6Names)
	if readErr != nil {
		fmt.Printf("warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
	return nil
}

func (c *CLI) showFirewallFilter(name, requestedFamily string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	requestedFamily = strings.TrimSpace(requestedFamily)
	if requestedFamily != "" && requestedFamily != "inet" && requestedFamily != "inet6" {
		fmt.Printf("invalid family: %s\n", requestedFamily)
		return nil
	}

	var filter *config.FirewallFilter
	var family string
	switch requestedFamily {
	case "inet":
		filter = cfg.Firewall.FiltersInet[name]
		family = "inet"
	case "inet6":
		filter = cfg.Firewall.FiltersInet6[name]
		family = "inet6"
	default:
		if f, ok := cfg.Firewall.FiltersInet[name]; ok {
			filter = f
			family = "inet"
		} else if f, ok := cfg.Firewall.FiltersInet6[name]; ok {
			filter = f
			family = "inet6"
		}
	}
	if filter == nil {
		if requestedFamily != "" {
			fmt.Printf("Filter not found: %s (family %s)\n", name, requestedFamily)
		} else {
			fmt.Printf("Filter not found: %s\n", name)
		}
		return nil
	}

	// Resolve filter IDs for counter display. #3408: surface a read failure
	// as a warning AFTER all terms rather than printing clean-zero counts.
	var readErr error
	var ruleStart uint32
	var hasCounters bool
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			if fid, ok := cr.FilterIDs[family+":"+name]; ok {
				if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
					ruleStart = fcfg.RuleStart
					hasCounters = true
				} else if readErr == nil {
					readErr = err
				}
			}
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	fmt.Printf("Filter: %s (family %s)\n", name, family)

	ruleOffset := ruleStart
	for _, term := range filter.Terms {
		fmt.Printf("\n  Term: %s\n", term.Name)
		for _, d := range term.DSCPs {
			fmt.Printf("    from dscp %s\n", d)
		}
		for _, p := range term.Protocols {
			fmt.Printf("    from protocol %s\n", p)
		}
		for _, addr := range term.SourceAddresses {
			fmt.Printf("    from source-address %s\n", addr)
		}
		for _, ref := range term.SourcePrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
		}
		for _, addr := range term.DestAddresses {
			fmt.Printf("    from destination-address %s\n", addr)
		}
		for _, ref := range term.DestPrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
		}
		if len(term.SourcePorts) > 0 {
			fmt.Printf("    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
		}
		if len(term.DestinationPorts) > 0 {
			fmt.Printf("    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
		}
		for _, t := range term.ICMPTypes {
			fmt.Printf("    from icmp-type %d\n", t)
		}
		for _, c := range term.ICMPCodes {
			fmt.Printf("    from icmp-code %d\n", c)
		}
		if term.RoutingInstance != "" {
			fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
		}
		if term.ForwardingClass != "" {
			fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
		}
		if term.LossPriority != "" {
			fmt.Printf("    then loss-priority %s\n", term.LossPriority)
		}
		if term.DSCPRewrite != "" {
			fmt.Print(filterDSCPRewriteLine(term.DSCPRewrite))
		}
		if term.Log {
			fmt.Printf("    then log\n")
		}
		if term.Count != "" {
			fmt.Printf("    then count %s\n", term.Count)
		}
		action := term.Action
		if action == "" {
			action = "accept"
		}
		fmt.Printf("    then %s\n", action)

		// Sum counters across all expanded BPF rules for this term
		numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
		var totalPkts, totalBytes uint64
		if hasCounters {
			for i := uint32(0); i < numRules; i++ {
				if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
					totalPkts += ctrs.Packets
					totalBytes += ctrs.Bytes
				} else if readErr == nil {
					readErr = err
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
			fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
		}
	}
	fmt.Println()
	if readErr != nil {
		fmt.Printf("warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
	return nil
}

// showEffectiveFirewallFilters renders the EFFECTIVE (compiled) firewall-filter
// snapshots for `show firewall effective` (#4422). Unlike showFirewallFilters
// (which prints the raw typed config), this rebuilds the FirewallFilterSnapshot
// the config compiler emits and prints the terms exactly as the matcher would
// enforce them: prefix-list references resolved to literal prefixes, address/
// port `except` folded (positive-wins on a mixed term), DSCP tokens resolved to
// numeric code points, TCP-flags lowered to required/forbidden masks, `then next
// term` / modifier-only fall-through computed, and any unrepresentable match
// marked fail-closed. It is read-only — it derives the snapshot from the active
// config and never touches the dataplane.
//
// #5067: the snapshots are compiled from ActiveConfig(), which commitAndApply
// promotes via store.Commit() BEFORE applyAndSyncCommitted runs. A required-
// protocol-gate apply error (applyErrSkipsPeerSync / compileErrorMustAbortApply,
// pkg/daemon/daemon_apply.go) leaves the dataplane DISARMED while ActiveConfig is
// already the new generation, so the compiled-desired snapshot is NOT what the
// dataplane is enforcing. printFirewallEffectiveBanner binds the view to the
// helper-acknowledged generation: it certifies the output as live only when the
// dataplane is armed and the acknowledged generation matches the last applied
// generation, and otherwise prints a prominent compiled-desired / drift banner
// so the operator is not misled.
func (c *CLI) showEffectiveFirewallFilters(family string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	family = strings.TrimSpace(family)
	if family != "" && family != "inet" && family != "inet6" {
		fmt.Printf("invalid family: %s\n", family)
		return nil
	}
	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	matched := make([]int, 0, len(snaps))
	for i := range snaps {
		if family != "" && snaps[i].Family != family {
			continue
		}
		matched = append(matched, i)
	}
	if len(matched) == 0 {
		if family != "" {
			fmt.Printf("No firewall filters configured (family %s)\n", family)
		} else {
			fmt.Println("No firewall filters configured")
		}
		return nil
	}
	c.printFirewallEffectiveBanner()
	for _, i := range matched {
		renderEffectiveFilterSnapshot(&snaps[i])
	}
	return nil
}

// showEffectiveFirewallFilter renders the effective (compiled) snapshot for a
// single named filter (#4422). Family "" auto-selects whichever family defines
// the name (inet then inet6), matching showFirewallFilter.
func (c *CLI) showEffectiveFirewallFilter(name, family string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	family = strings.TrimSpace(family)
	if family != "" && family != "inet" && family != "inet6" {
		fmt.Printf("invalid family: %s\n", family)
		return nil
	}
	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	matched := make([]int, 0, len(snaps))
	for i := range snaps {
		if snaps[i].Name != name {
			continue
		}
		if family != "" && snaps[i].Family != family {
			continue
		}
		matched = append(matched, i)
	}
	if len(matched) == 0 {
		if family != "" {
			fmt.Printf("Filter not found: %s (family %s)\n", name, family)
		} else {
			fmt.Printf("Filter not found: %s\n", name)
		}
		return nil
	}
	// #5067: same generation-liveness caveat as the all-filters view.
	c.printFirewallEffectiveBanner()
	for _, i := range matched {
		renderEffectiveFilterSnapshot(&snaps[i])
	}
	return nil
}

// renderEffectiveFilterSnapshot prints one compiled FirewallFilterSnapshot. The
// rendering itself is the shared SSOT dpuserspace.RenderFirewallFilterSnapshot
// (#4967) so the local CLI, the gRPC ShowText server, and the remote CLI all
// emit byte-identical output.
func renderEffectiveFilterSnapshot(snap *dpuserspace.FirewallFilterSnapshot) {
	fmt.Print(dpuserspace.RenderFirewallFilterSnapshot(snap))
}

// firewallEffectiveLiveness records whether the compiled firewall-filter
// snapshots rendered by the `effective` view are actually what the dataplane is
// enforcing (#5067). The view derives its content from ActiveConfig(), but
// commitAndApply promotes the active config via store.Commit() BEFORE
// applyAndSyncCommitted runs the dataplane apply; a required-protocol-gate apply
// error (applyErrSkipsPeerSync / compileErrorMustAbortApply) leaves the
// dataplane DISARMED while ActiveConfig is already the new generation. This
// binds the rendered content to the HELPER-ACKNOWLEDGED generation instead of
// blindly certifying the promoted config as live.
type firewallEffectiveLiveness struct {
	// determined is true when a dataplane runtime is loaded AND its helper
	// status was obtained — i.e. we can actually compare the acknowledged
	// generation against the last applied generation. When false (no runtime,
	// or status unavailable) the view is compiled-desired that we cannot
	// confirm is live.
	determined bool
	// live is true only when the dataplane is armed AND the helper-acknowledged
	// snapshot generation is at or ahead of the daemon's last successfully-
	// applied generation — the state in which the compiled snapshots equal what
	// the dataplane is enforcing. (Helper-ahead is benign; see
	// firewallEffectiveLiveness.)
	live bool
	// appliedGen is the daemon's last successfully-recorded apply generation
	// (0 when no apply has ever been recorded).
	appliedGen uint64
	// ackedGen is the generation the userspace helper reports it has applied
	// (status.LastSnapshotGeneration).
	ackedGen uint64
	// reason explains why the view is not live (disarmed / generation drift).
	reason string
}

// firewallEffectiveLiveness inspects the dataplane apply-result and userspace
// helper status to decide whether the `effective` firewall view can be
// certified as dataplane-acknowledged (#5067).
func (c *CLI) firewallEffectiveLiveness() firewallEffectiveLiveness {
	var v firewallEffectiveLiveness
	if !c.dataplaneLoaded() {
		return v // undetermined: no runtime to confirm against
	}
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return v // undetermined: helper status unavailable
	}
	v.determined = true
	v.ackedGen = status.LastSnapshotGeneration
	cr := c.applyResult()
	if cr != nil {
		v.appliedGen = cr.Generation
	}
	// Armed requires the helper to be enabled + forwarding-armed with forwarding
	// supported, AND a recorded apply that itself reported forwarding supported.
	// A required-protocol-gate disarm sets ForwardingArmed=false without
	// advancing the recorded apply result, so this is false in the #5067 window.
	armed := status.Enabled && status.ForwardingArmed &&
		status.Capabilities.ForwardingSupported &&
		cr != nil && cr.Capabilities.ForwardingSupported
	// Coherent requires the helper's acknowledged generation to be AT OR AHEAD
	// of the daemon's last successfully-applied generation. Helper-BEHIND
	// (acked < applied) is real drift — the helper has not caught up to (or
	// rejected) the applied configuration. Helper-AHEAD (acked > applied) is
	// BENIGN: a scheduler-only republish (Manager.UpdatePolicyScheduleState)
	// advances the helper's snapshot generation WITHOUT calling
	// recordApplyResultLocked, so LastApplyResult().Generation lags the helper
	// on a perfectly healthy box. That republish only re-times policy
	// enable/disable — it carries the SAME filter content — so the effective
	// view is still live. The genuine #5067 disarm is caught by the `armed`
	// predicate (ForwardingArmed=false) independent of this compare, so
	// accepting helper-ahead does not weaken the original fix.
	coherent := cr != nil && status.LastSnapshotGeneration >= cr.Generation
	switch {
	case !armed:
		v.reason = "dataplane disarmed (forwarding not armed)"
	case !coherent:
		v.reason = "dataplane generation drift (helper is behind the applied configuration)"
	default:
		v.live = true
	}
	return v
}

// printFirewallEffectiveBanner prints the generation-liveness context for the
// `effective` firewall-filter view (#5067) BEFORE the compiled snapshots, so an
// operator is never misled into reading a compiled-desired-but-unapplied config
// as what the dataplane is enforcing.
func (c *CLI) printFirewallEffectiveBanner() {
	v := c.firewallEffectiveLiveness()
	switch {
	case !v.determined:
		fmt.Println("Note: dataplane status unavailable — the firewall filters below are")
		fmt.Println("  compiled-desired; the dataplane's acknowledged generation could not be")
		fmt.Println("  confirmed.")
		fmt.Println()
	case v.live:
		fmt.Printf("Effective firewall filters — dataplane-acknowledged (generation %d).\n\n", v.ackedGen)
	default:
		fmt.Println("WARNING: dataplane is NOT enforcing the active configuration.")
		fmt.Println("  The firewall filters below are COMPILED-DESIRED (what the active")
		fmt.Println("  configuration compiles to), NOT what the dataplane is enforcing.")
		fmt.Printf("  Reason: %s.\n", v.reason)
		fmt.Printf("  Last dataplane-acknowledged generation: %d.\n", v.ackedGen)
		if v.appliedGen != v.ackedGen {
			fmt.Printf("  Last daemon-applied generation: %d.\n", v.appliedGen)
		}
		fmt.Println("  Desired: active configuration (not acknowledged).")
		fmt.Println()
	}
}

// filterDSCPRewriteLine renders one `then dscp` / `then traffic-class` line for
// `show firewall`, annotating a rewrite the dataplane does NOT install.
//
// #6565 row 8 / #7422: the snapshot builder DROPS an unresolvable rewrite
// (pkg/dataplane/userspace/filters.go — "CoS marking lost — the term still
// matches and acts") while both call sites printed it unconditionally, so
// `show firewall` reported a marking the dataplane was not applying. The
// commit gate (config.validateFilterDSCPStrict, #3309) hard-rejects such a
// token, but the tolerant load / cluster config-sync path (#1960 no-brick)
// downgrades that to a warning and the config goes ACTIVE — which is the state
// this renderer is reached in.
//
// Annotate rather than hide: the operator authored the line and needs to see
// BOTH that it is configured and that it is not installed. Hiding it would
// make `show firewall` disagree with `show configuration`.
//
// EXTRACTED from the two call sites so the guard has a subject: two renderers
// of one field drift exactly the way the renderer and the builder did, and a
// test that could only reach one of them would certify the other.
func filterDSCPRewriteLine(rewrite string) string {
	if _, ok := dataplane.ResolveFilterDSCP(rewrite); ok {
		return fmt.Sprintf("    then dscp %s\n", rewrite)
	}
	return fmt.Sprintf("    then dscp %s  [NOT INSTALLED: unresolvable dscp/"+
		"traffic-class value — no CoS marking is applied; the term still "+
		"matches and acts]\n", rewrite)
}
