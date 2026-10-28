package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/firewallshow"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// readLo0CountersCLI is the kernel lo0 counter source for the RAW show
// views, a package var so tests can inject a fixture without netlink
// (#16457), mirroring pkg/api's readLo0Counters seam.
var readLo0CountersCLI = xnft.ReadLo0Counters

// resetLo0CountersCLI is the `clear firewall all` kernel lo0 reset seam
// (#16457).
var resetLo0CountersCLI = xnft.ResetLo0Counters

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

	// #16451: warn before pairing active-config terms with stale counters.
	c.printFirewallRawCounterWarning()

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
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndexForConfig(userspaceStatus, cfg)
	// #16457: kernel lo0 counters for lo0-referenced filters.
	var lo0Err error
	lo0For := func(family, name string) []xnft.Lo0Count {
		counts, err := firewallshow.Lo0CountersForFilter(cfg, family, name, readLo0CountersCLI)
		if err != nil && lo0Err == nil {
			lo0Err = err
		}
		return counts
	}

	// #3408: surface a filter counter read failure as a warning AFTER all
	// filters, rather than printing clean-zero / omitted hit counts.
	var readErr error
	cloneFold16464 := dpuserspace.BuildCloneCounterFold16464(cfg)
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

			// #16464: eBPF map slots for this source also include clone
			// slots (compiler iterates every filter incl. clones).
			cloneRuleStart16464 := make(map[string]uint32)
			cloneHas16464 := make(map[string]bool)
			if filterIDs != nil {
				for cloneName, source := range cloneFold16464[family] {
					if source != name {
						continue
					}
					if fid, ok := filterIDs[family+":"+cloneName]; ok {
						if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
							cloneRuleStart16464[cloneName] = fcfg.RuleStart
							cloneHas16464[cloneName] = true
						} else if readErr == nil {
							readErr = err
						}
					}
				}
			}
			ruleOffset := ruleStart
			// #16460: the per-instance ordinal is the term's position
			// among non-nil instances; a nil slot owns no runtime
			// counter and must not shift later instances' ordinals.
			termOrdinal := uint32(0)
			for _, term := range f.Terms {
				if term == nil {
					continue
				}
				var tb strings.Builder
				firewallshow.WriteTerm(&tb, term, false)
				fmt.Print(tb.String())

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
				// #16464: fold each clone's eBPF slots for this term
				// (same-ordinal clone term) into the source total.
				for cloneName := range cloneHas16464 {
					var cloneFilter *config.FirewallFilter
					if family == "inet" {
						cloneFilter = cfg.Firewall.FiltersInet[cloneName]
					} else {
						cloneFilter = cfg.Firewall.FiltersInet6[cloneName]
					}
					if cloneFilter == nil {
						continue
					}
					cloneOffset := cloneRuleStart16464[cloneName]
					matched := false
					for _, ct := range cloneFilter.Terms {
						if ct == nil {
							continue
						}
						cn := config.FilterTermExpansionCount(ct, cfg.PolicyOptions.PrefixLists)
						if ct.Name == term.Name && !matched {
							for i := uint32(0); i < cn; i++ {
								if ctrs, err := c.dp.ReadFilterCounters(cloneOffset + i); err == nil {
									totalPkts += ctrs.Packets
									totalBytes += ctrs.Bytes
								} else if readErr == nil {
									readErr = err
								}
							}
							matched = true
						}
						cloneOffset += cn
					}
				}
				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: name, TermOrdinal: termOrdinal,
				}]
				termOrdinal++
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				// #16454 + #16464: uncounted terms render no numeric Hit
				// count; clone map slots only gate a counted term.
				if term.Count != "" && (hasCounters || len(cloneHas16464) > 0 || userspaceOk) {
					fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			// #16457: kernel lo0 chain counts (fxp0/host-stack traffic the
			// helper never sees), labelled by count name.
			var lo0Buf strings.Builder
			firewallshow.WriteLo0KernelCounters(&lo0Buf, f, lo0For(family, name))
			fmt.Print(lo0Buf.String())
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
	if lo0Err != nil {
		fmt.Printf("warning: kernel lo0 counter read failed (lo0 kernel counts may be incomplete): %v\n", lo0Err)
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
	// #16464: clone eBPF slots folded into this source filter below.
	cloneFold16464 := dpuserspace.BuildCloneCounterFold16464(cfg)
	cloneRuleStart16464 := make(map[string]uint32)
	cloneHas16464 := make(map[string]bool)
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil && cr.FilterIDs != nil {
			for cloneName, source := range cloneFold16464[family] {
				if source != name {
					continue
				}
				if fid, ok := cr.FilterIDs[family+":"+cloneName]; ok {
					if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
						cloneRuleStart16464[cloneName] = fcfg.RuleStart
						cloneHas16464[cloneName] = true
					} else if readErr == nil {
						readErr = err
					}
				}
			}
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndexForConfig(userspaceStatus, cfg)

	// #16451: same stale-counter warning as the all-filters raw view.
	c.printFirewallRawCounterWarning()
	fmt.Printf("Filter: %s (family %s)\n", name, family)
	ruleOffset := ruleStart
	// #16460: per-instance ordinal among non-nil instances (see the
	// all-filters view).
	termOrdinal := uint32(0)
	for _, term := range filter.Terms {
		if term == nil {
			continue
		}
		var tb strings.Builder
		firewallshow.WriteTerm(&tb, term, true)
		fmt.Print(tb.String())

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
		for cloneName := range cloneHas16464 {
			var cloneFilter *config.FirewallFilter
			if family == "inet" {
				cloneFilter = cfg.Firewall.FiltersInet[cloneName]
			} else {
				cloneFilter = cfg.Firewall.FiltersInet6[cloneName]
			}
			if cloneFilter == nil {
				continue
			}
			cloneOffset := cloneRuleStart16464[cloneName]
			matched := false
			for _, ct := range cloneFilter.Terms {
				if ct == nil {
					continue
				}
				cn := config.FilterTermExpansionCount(ct, cfg.PolicyOptions.PrefixLists)
				if ct.Name == term.Name && !matched {
					for i := uint32(0); i < cn; i++ {
						if ctrs, err := c.dp.ReadFilterCounters(cloneOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						} else if readErr == nil {
							readErr = err
						}
					}
					matched = true
				}
				cloneOffset += cn
			}
		}
		userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
			Family: family, FilterName: name, TermOrdinal: termOrdinal,
		}]
		termOrdinal++
		if userspaceOk {
			totalPkts += userspaceCounter.Packets
			totalBytes += userspaceCounter.Bytes
		}
		// #16454 + #16464: uncounted terms render no numeric Hit
		// count; clone map slots only gate a counted term.
		if term.Count != "" && (hasCounters || len(cloneHas16464) > 0 || userspaceOk) {
			fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
		}
	}
	// #16457: kernel lo0 chain counts beside the helper counts.
	lo0Counts, lo0Err := firewallshow.Lo0CountersForFilter(cfg, family, name, readLo0CountersCLI)
	var lo0Buf strings.Builder
	firewallshow.WriteLo0KernelCounters(&lo0Buf, filter, lo0Counts)
	fmt.Print(lo0Buf.String())
	fmt.Println()
	if readErr != nil {
		fmt.Printf("warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
	if lo0Err != nil {
		fmt.Printf("warning: kernel lo0 counter read failed (lo0 kernel counts may be incomplete): %v\n", lo0Err)
	}
	return nil
}

// showEffectiveFirewallFilters renders the EFFECTIVE (compiled) firewall-filter
// snapshots for `show firewall effective` (#4422). Unlike showFirewallFilters
// (which prints the raw typed config), this rebuilds the FirewallFilterSnapshot
// the config compiler emits and prints the terms exactly as the matcher would
// enforce them: prefix-list references resolved to literal prefixes, address/
// port `except` folded (positive-wins on a mixed term), DSCP tokens resolved to
// numeric code points, TCP-flags lowered to required/forbidden masks, authored
// `then next term` fall-through / modifier-only implicit accept computed
// (#14632), and any unrepresentable match marked fail-closed. It is
// read-only — it derives the snapshot from the active config and never
// touches the dataplane.
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
// enforcing (#5067, #16451). The view derives its content from ActiveConfig(), but
// commitAndApply promotes the active config via store.Commit() BEFORE
// applyAndSyncCommitted runs the dataplane apply; a required-protocol-gate apply
// error (applyErrSkipsPeerSync / compileErrorMustAbortApply) leaves the
// dataplane DISARMED while ActiveConfig is already the new generation. This
// binds the rendered content to the HELPER-ACKNOWLEDGED generation instead of
// blindly certifying the promoted config as live.
//
// #16451: an in-band helper REFUSAL (ok=false, e.g. a snapshot-integrity
// rejection) is a third window the generation compare alone cannot see: the
// helper keeps its prior snapshot, stays armed, and nothing is adopted, so
// LastApplyResult.Generation and LastSnapshotGeneration BOTH stay at the prior
// generation N and `acked >= applied` reads coherent (N >= N) over the refused
// config's compiled filters. Only store.ActiveApplied() binds the rendered
// content (the active config text) to a completed apply: it is false after a
// promotion whose apply has not succeeded — including after a refused apply
// under degrade-not-fail — and is cleared by InvalidateAppliedDigest on any
// failed apply. `live` therefore additionally requires ActiveApplied().
type firewallEffectiveLiveness struct {
	// determined is true when a dataplane runtime is loaded AND its helper
	// status was obtained — i.e. we can actually compare the acknowledged
	// generation against the last applied generation. When false (no runtime,
	// or status unavailable) the view is compiled-desired that we cannot
	// confirm is live.
	determined bool
	// live is true only when the dataplane is armed, the helper-acknowledged
	// snapshot generation is at or ahead of the daemon's last successfully-
	// applied generation, AND the active config is the one that completed an
	// apply (store.ActiveApplied) — the state in which the compiled snapshots
	// equal what the dataplane is enforcing. (Helper-ahead is benign; see
	// firewallEffectiveLiveness.)
	live bool
	// appliedGen is the daemon's last successfully-recorded apply generation
	// (0 when no apply has ever been recorded).
	appliedGen uint64
	// ackedGen is the generation the userspace helper reports it has applied
	// (status.LastSnapshotGeneration).
	ackedGen uint64
	// reason explains why the view is not live (disarmed / generation drift /
	// active config not applied).
	reason string
}

// firewallEffectiveLiveness inspects the dataplane apply-result, userspace
// helper status, and the store's applied marker to decide whether the
// `effective` firewall view can be certified as dataplane-acknowledged
// (#5067, #16451).
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
	// BENIGN: a scheduler-only republish (Manager.UpdatePolicyScheduleStateWithLatch)
	// advances the helper's snapshot generation WITHOUT calling
	// recordApplyResultLocked, so LastApplyResult().Generation lags the helper
	// on a perfectly healthy box. That republish only re-times policy
	// enable/disable — it carries the SAME filter content — so the effective
	// view is still live. The genuine #5067 disarm is caught by the `armed`
	// predicate (ForwardingArmed=false) independent of this compare, so
	// accepting helper-ahead does not weaken the original fix.
	coherent := cr != nil && status.LastSnapshotGeneration >= cr.Generation
	// Applied requires the ACTIVE config text to be the one that completed a
	// full apply (#16451). After an in-band helper refusal both generations
	// stay frozen at the prior generation, so armed+coherent alone certify the
	// refused config; ActiveApplied() is false in exactly that window (the
	// promotion moved the active text off the stamped digest, and a failed
	// apply clears the marker via InvalidateAppliedDigest). A nil store (only
	// in tests that never wire one) cannot vouch for an apply, so it reads
	// not-applied rather than certifying.
	applied := firewallshow.Applied(c.store)
	switch {
	case !armed:
		v.reason = "dataplane disarmed (forwarding not armed)"
	case !coherent:
		v.reason = "dataplane generation drift (helper is behind the applied configuration)"
	case !applied:
		v.reason = "active configuration not applied (dataplane is enforcing a previous configuration)"
	default:
		v.live = true
	}
	return v
}

// firewallCountersStale reports whether hit counters printed beside the
// ACTIVE config's terms on the RAW `show firewall` views would belong to a
// previous generation (#16451). The raw views look counters up only by
// (family, filter, term name), so after a helper refusal the previous filter
// set's counters appear under the refused config's same-named terms. The
// counters are stale exactly when the dataplane is determined-live-able
// (runtime loaded + helper status obtained) but the active config is not
// the applied one — the same not-live predicate as the effective view,
// minus the undetermined case (no counters can be attributed either way
// when no helper status exists, and the raw view already carries no
// liveness claim there).
func (c *CLI) firewallCountersStale() bool {
	v := c.firewallEffectiveLiveness()
	return v.determined && !v.live
}

// printFirewallRawCounterWarning prints the #16451 stale-counter warning for
// the RAW views. It is emitted BEFORE the filter listing so the previous
// generation's counters are never read as the active config's.
func (c *CLI) printFirewallRawCounterWarning() {
	if !c.firewallCountersStale() {
		return
	}
	fmt.Print(firewallshow.StaleCounterWarning)
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
