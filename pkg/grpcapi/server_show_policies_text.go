// Phase 10 of #1043: extract the three policy-related ShowText case
// bodies (`policies-hit-count`, `policies-detail`, `policy-options`)
// into dedicated methods. Same methodology as Phases 1-9: semantic
// relocation, no behavior change. Each case body is moved verbatim
// apart from `&buf` references becoming `buf` (passed-in
// `*strings.Builder`) and `break`/early-`else` patterns flattened
// into early-return form.
//
// `showPoliciesHitCount` and `showPoliciesDetail` take a `filter`
// string parameter (originally `req.Filter`) so the bodies no longer
// reference the gRPC request struct directly.

package grpcapi

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// parseZoneFilter parses the optional `from-zone X to-zone Y` selector
// that gates the policies-hit-count / policies-detail views. It rejects
// an unrecognized token (e.g. a typo'd `from-zonee`) rather than
// silently ignoring it — an ignored key left the corresponding filter
// dimension empty, which widened the view to ALL zones and could make an
// operator read a narrow policy set as the whole table. Mirrors the
// unknown-key rejection the other show surfaces adopted (#4814/#3696).
// Both showPoliciesHitCount and showPoliciesDetail route through this one
// parser so the two surfaces stay in lockstep (#5557).
func parseZoneFilter(filter string) (from, to string, err error) {
	parts := strings.Fields(filter)
	for i := 0; i < len(parts); {
		switch parts[i] {
		case "from-zone":
			if i+1 >= len(parts) {
				return "", "", fmt.Errorf("from-zone requires a zone name")
			}
			from = parts[i+1]
			i += 2
		case "to-zone":
			if i+1 >= len(parts) {
				return "", "", fmt.Errorf("to-zone requires a zone name")
			}
			to = parts[i+1]
			i += 2
		default:
			return "", "", fmt.Errorf("unrecognized filter token %q (expected from-zone/to-zone)", parts[i])
		}
	}
	return from, to, nil
}

// policySchedulerStateProvider is the optional dataplane capability the
// gRPC policy-detail text surface uses to learn the live per-scheduler
// active-state map (#3062). The userspace dataplane adapter implements
// it; when it is unavailable the surface renders every policy enabled
// (bit-identical to the pre-#3062 output).
type policySchedulerStateProvider interface {
	PolicySchedulerActiveState() map[string]bool
}

// policySchedulerActiveState returns the live scheduler active-state map
// and whether it could be queried. ok=false means the runtime state is
// unknown and the caller must not claim any policy is scheduler-inactive.
func (s *Server) policySchedulerActiveState() (state map[string]bool, ok bool) {
	if s == nil || s.dp == nil {
		return nil, false
	}
	p, isProvider := s.dpProbe().(policySchedulerStateProvider)
	if !isProvider {
		return nil, false
	}
	return p.PolicySchedulerActiveState(), true
}

// policyInactiveFn returns a per-policy scheduler-inactivity predicate bound to
// the live active-state snapshot for use as policymatch.Query.PolicyInactiveFn
// (#3104). It always returns a non-nil predicate so the simulator agrees with
// the dataplane in BOTH directions (#3414): when the runtime scheduler state
// cannot be queried (no provider / early boot), state is nil, and
// PolicyInactiveFn(nil) marks every scheduler-bound policy inactive — exactly
// what the snapshot builder does (policyRuleInactive: nil map => dropped) until
// live state arrives, so the diagnostic never certifies a verdict for a
// scheduled policy the dataplane is currently skipping. A NON-scheduled policy
// (empty scheduler name) is always active regardless of the (possibly nil)
// state map, so its verdict is unchanged.
func (s *Server) policyInactiveFn() func(string) bool {
	state, _ := s.policySchedulerActiveState()
	return dpuserspace.PolicyInactiveFn(state)
}

// policyDetailStateSuffix returns the per-policy detail header suffix for
// a scheduler-inactive policy (", State: inactive, Scheduler: <name>"),
// or "" otherwise. haveSched gates the lookup so that when the runtime
// state cannot be queried the suffix is empty and the header stays
// bit-identical to the pre-#3062 output for active/non-scheduled
// policies (#3062).
func policyDetailStateSuffix(schedulerName string, activeState map[string]bool, haveSched bool) string {
	if haveSched && dpuserspace.PolicyInactive(schedulerName, activeState) {
		return fmt.Sprintf(", State: inactive, Scheduler: %s", schedulerName)
	}
	return ""
}

// showPoliciesHitCount renders the per-policy packet/byte hit counters
// with a fixed-width tabular format. `filter` is parsed for
// `from-zone X to-zone Y` selectors.
func (s *Server) showPoliciesHitCount(filter string, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	// Parse optional zone filter from filter: "from-zone X to-zone Y".
	// An unrecognized token is rejected rather than silently widening the
	// view to all zones (#5557).
	filterFrom, filterTo, err := parseZoneFilter(filter)
	if err != nil {
		fmt.Fprintf(buf, "invalid filter: %v\n", err)
		return
	}
	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): Junos maintains and displays per-policy hit counters only
	// when policy-stats is enabled system-wide (default off). The
	// Prometheus collector (metrics_counters.go) already gates on this
	// knob; gate the text/structured display surfaces identically so all
	// four surfaces (Prometheus, gRPC text hit-count, gRPC text detail,
	// structured gRPC GetPolicies, local CLI) report the SAME values.
	// When the knob is off, the per-rule counter columns read 0 (we skip
	// the dataplane read) rather than surfacing live counts the operator
	// did not enable.
	statsEnabled := cfg.Security.PolicyStatsEnabled
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	quarantinedZones := config.ZoneQuarantineExclusions(zoneNames)
	isQuarantined := func(name string) bool {
		_, ok := quarantinedZones[name]
		return ok
	}
	qualifyZone := func(name string) string {
		if isQuarantined(name) {
			return name + " " + config.ZoneQuarantinePoliciesQualifier
		}
		return name
	}
	qualifyScopeLabel := func(zones []string, placeholder string) string {
		label := config.ScopeLabelOr(zones, placeholder)
		if len(zones) == 0 || config.IsWildcardZoneSet(zones) {
			return label
		}
		parts := strings.Fields(label)
		for i, name := range parts {
			parts[i] = qualifyZone(name)
		}
		return strings.Join(parts, " ")
	}
	scopeQuarantined := func(from, to []string) bool {
		for _, name := range append(append([]string{}, from...), to...) {
			if isQuarantined(name) {
				return true
			}
		}
		return false
	}
	// #3408: surface a per-policy counter read failure as a warning AFTER all
	// reads rather than printing clean-zero hit counts.
	var readErr error
	// #7016: an UNPUBLISHED per-rule counter is not a read failure -- the
	// helper has published nothing for that rule id yet (warm-up before the
	// first status poll, or config skew after a non-abort-class apply failure).
	// Render it "n/a" with a trailing note rather than an authoritative 0 under
	// a warning naming a fault that does not exist.
	var unpublished int
	// #7776: rows whose counter was NOT read because policy-stats is disabled
	// system-wide and the rule carries no per-rule `count`. Guarded on that
	// cause explicitly rather than with a bare `else`, because the read
	// condition also carries `readPolicy != nil` -- a bare else would count a
	// not-loaded dataplane as a disabled-stats row and the note would lie.
	var statsDisabled int
	// #4344: read the whole policy set from ONE snapshot (O(P+C), one brief
	// dataplane lock) via the #3965 bulk reader instead of a per-policy
	// ReadPolicyCounters loop. Built only when the dataplane is loaded; falls
	// back to the per-policy read for dataplanes without the bulk snapshot
	// (test fakes / retired eBPF), so the displayed counts are identical. cfg
	// is the config walked below, so the snapshot's handles line up.
	var readPolicy func(uint32) (dataplane.CounterValue, error)
	if s.dp != nil && s.dp.IsLoaded() {
		readPolicy = dpuserspace.NewPolicyCounterReader(s.dp, cfg, s.dp.ReadPolicyCounters)
	}
	fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
		"From zone", "To zone", "Policy", "Action", "Packets", "Bytes")
	fmt.Fprintln(buf, strings.Repeat("-", 88))
	policySetID := uint32(0)
	var totalPkts, totalBytes uint64
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker.
		if zpp == nil {
			policySetID++
			continue
		}
		if (filterFrom != "" && zpp.FromZone != filterFrom) ||
			(filterTo != "" && zpp.ToZone != filterTo) {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if pol == nil {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleQuarantined := isQuarantined(zpp.FromZone) || isQuarantined(zpp.ToZone)
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var pkts, bytes uint64
			published := true
			if !ruleQuarantined && (statsEnabled || pol.Count) && readPolicy != nil {
				counters, err := readPolicy(ruleID)
				switch {
				case err == nil:
					pkts = counters.Packets
					bytes = counters.Bytes
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					published = false // #7016
					unpublished++
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else if !ruleQuarantined && !statsEnabled && !pol.Count {
				statsDisabled++
			}
			totalPkts += pkts
			totalBytes += bytes
			fromDisplay := qualifyZone(zpp.FromZone)
			toDisplay := qualifyZone(zpp.ToZone)
			packetDisplay := policyCounterCell(pkts, published)
			byteDisplay := policyCounterCell(bytes, published)
			if ruleQuarantined {
				packetDisplay = config.ZoneQuarantineLiveCountersUnavailable
				byteDisplay = config.ZoneQuarantineLiveCountersUnavailable
			}
			fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
				fromDisplay, toDisplay, pol.Name, action,
				packetDisplay, byteDisplay)
		}
		policySetID++
	}
	// Global policies (#3059): the runtime evaluates global policies after
	// the exact zone-pair policies, and the gRPC detail view, CLI,
	// Prometheus collector, and structured GetPolicies all expose them.
	// The hit-count text surface must too — otherwise an operator using
	// the exact command meant to prove which policy is catching traffic
	// sees zero evidence for a global emergency deny/permit. Render globals
	// with from/to zone "*" (matching the other surfaces). Counter IDs
	// continue from the zone-pair loop: policySetID*MaxRulesPerPolicy + i,
	// keeping the global slots aligned with the dataplane (#3045/#3050 did
	// the same for the REST inventory).
	//
	// #3357: a from/to-zone filter no longer suppresses the whole global
	// block. An unscoped global is enforced for every zone pair and a scoped
	// global (#3148) may target exactly the filtered pair, so the filtered
	// hit-count surface must show the globals that govern it.
	// GlobalPolicyAppliesToZonePair selects per-rule scope against the filter.
	if len(cfg.Security.GlobalPolicies) > 0 {
		for i, pol := range cfg.Security.GlobalPolicies {
			if pol == nil {
				continue
			}
			// #3357: drop a scoped global that targets a different zone pair.
			if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZones, pol.Match.ToZones, filterFrom, filterTo) {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleQuarantined := scopeQuarantined(pol.Match.FromZones, pol.Match.ToZones)
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var pkts, bytes uint64
			published := true
			if !ruleQuarantined && (statsEnabled || pol.Count) && readPolicy != nil {
				counters, err := readPolicy(ruleID)
				switch {
				case err == nil:
					pkts = counters.Packets
					bytes = counters.Bytes
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					published = false // #7016
					unpublished++
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else if !ruleQuarantined && !statsEnabled && !pol.Count {
				statsDisabled++
			}
			totalPkts += pkts
			totalBytes += bytes
			// #3286/#4626: a scoped global (#3148) reports its zone SET in the
			// From/To columns so the hit-count row is not ambiguous; an
			// unscoped global keeps "*"/"*".
			hcFrom := qualifyScopeLabel(pol.Match.FromZones, "*")
			hcTo := qualifyScopeLabel(pol.Match.ToZones, "*")
			packetDisplay := policyCounterCell(pkts, published)
			byteDisplay := policyCounterCell(bytes, published)
			if ruleQuarantined {
				packetDisplay = config.ZoneQuarantineLiveCountersUnavailable
				byteDisplay = config.ZoneQuarantineLiveCountersUnavailable
			}
			fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
				hcFrom, hcTo, pol.Name, action,
				packetDisplay, byteDisplay)
		}
	}
	// #3363: the IMPLICIT default-policy catch-all has a reserved hit counter
	// (read via the DefaultPolicySentinelID handle). Surface it as a final row
	// — separated from the configured-rule totals — in the unfiltered view so
	// the operator can see default-deny/permit hits across every zone pair.
	// Gated on policy-stats like every other row for cross-surface consistency.
	if filterFrom == "" && filterTo == "" {
		defAction := "permit"
		switch cfg.Security.DefaultPolicy {
		case config.PolicyDeny:
			defAction = "deny"
		case config.PolicyReject:
			defAction = "reject"
		}
		var pkts, bytes uint64
		published := true
		if statsEnabled && readPolicy != nil {
			counters, err := readPolicy(dataplane.DefaultPolicySentinelID)
			switch {
			case err == nil:
				pkts = counters.Packets
				bytes = counters.Bytes
			case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
				published = false // #7016
				unpublished++
			default:
				if readErr == nil {
					readErr = err
				}
			}
		} else if !statsEnabled {
			statsDisabled++
		}
		totalPkts += pkts
		totalBytes += bytes
		fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
			"-", "-", dataplane.DefaultPolicyName, defAction,
			policyCounterCell(pkts, published), policyCounterCell(bytes, published))
	}
	fmt.Fprintln(buf, strings.Repeat("-", 88))
	fmt.Fprintf(buf, "%-48s %8s %12d %16d\n", "Total", "", totalPkts, totalBytes)
	if readErr != nil {
		fmt.Fprintf(buf, "warning: policy counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
	if unpublished > 0 {
		fmt.Fprintf(buf, "note: %d policy counter(s) not yet published by the dataplane "+
			"(shown as n/a; the helper has not reported these rules yet)\n", unpublished)
	}
	// #7776: without this the table renders a well-formed "0" for every row and
	// an operator reads "this policy has not matched" when the surface was
	// never asked to look -- an instrument answering "nothing" when it means
	// "I cannot see". Wording is kept byte-identical to the pkg/cli twin so the
	// two renderers cannot drift into saying different things.
	if statsDisabled > 0 {
		fmt.Fprintf(buf, "note: %d policy count(s) read 0 because policy-stats is disabled "+
			"system-wide, not because no traffic matched (enable with "+
			"`set security policy-stats system-wide enable`, or add `count` to an "+
			"individual policy)\n", statsDisabled)
	}
}

// showPoliciesDetail renders per-policy detail (match conditions,
// then-actions, session statistics) plus the global-policies block.
// `filter` is parsed for `from-zone X to-zone Y` selectors.
func (s *Server) showPoliciesDetail(filter string, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	// Reject an unrecognized filter token rather than silently widening
	// the view to all zones — same rule as showPoliciesHitCount (#5557).
	filterFrom, filterTo, err := parseZoneFilter(filter)
	if err != nil {
		fmt.Fprintf(buf, "invalid filter: %v\n", err)
		return
	}
	// Same policy-stats gate as showPoliciesHitCount (#2008 M4 / #2118):
	// the "Session statistics" block is per-policy hit-count display, so
	// it must honor the knob for cross-surface consistency.
	statsEnabled := cfg.Security.PolicyStatsEnabled
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	quarantinedZones := config.ZoneQuarantineExclusions(zoneNames)
	isQuarantined := func(name string) bool {
		_, ok := quarantinedZones[name]
		return ok
	}
	qualifyZone := func(name string) string {
		if isQuarantined(name) {
			return name + " " + config.ZoneQuarantinePoliciesQualifier
		}
		return name
	}
	qualifyScopeLabel := func(zones []string, placeholder string) string {
		label := config.ScopeLabelOr(zones, placeholder)
		if len(zones) == 0 || config.IsWildcardZoneSet(zones) {
			return label
		}
		parts := strings.Fields(label)
		for i, name := range parts {
			parts[i] = qualifyZone(name)
		}
		return strings.Join(parts, " ")
	}
	scopeQuarantined := func(from, to []string) bool {
		for _, name := range from {
			if isQuarantined(name) {
				return true
			}
		}
		for _, name := range to {
			if isQuarantined(name) {
				return true
			}
		}
		return false
	}
	// #8177: policies whose "Session statistics" block was OMITTED because the
	// knob is off and the rule carries no `count`. This surface had no trailing
	// note of any kind — its #7016 sibling case prints "not available (not yet
	// published)", and the comment there says outright that omitting the block
	// silently is indistinguishable from policy-stats being off. That is the
	// state this counts: the block is simply absent, so the reader cannot tell
	// "no counter for this rule" from "nobody looked at any rule".
	var statsDisabledDetail int
	// #4344: same #3965 bulk-reader migration as showPoliciesHitCount — read the
	// policy set from ONE snapshot instead of a per-policy ReadPolicyCounters
	// loop for the "Session statistics" block. Built only when the dataplane is
	// loaded; falls back to the per-policy read for non-bulk dataplanes, so the
	// rendered values are identical. cfg is the config walked below.
	var readPolicy func(uint32) (dataplane.CounterValue, error)
	if s.dp != nil && s.dp.IsLoaded() {
		readPolicy = dpuserspace.NewPolicyCounterReader(s.dp, cfg, s.dp.ReadPolicyCounters)
	}
	schedActive, haveSched := s.policySchedulerActiveState()
	// #3667 (H05): the displayed Index must equal the runtime/RT_FLOW policy ID
	// so a remote operator can map a policy-deny/RT_FLOW log line (which carries
	// the numeric policy ID) back to the detail row. RuntimePolicyIDs is the same
	// SSOT the local CLI detail + REST/gRPC structured inventory key off.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	// #3667 (H01, correctness): shared source/destination address renderer.
	// When the match sense is inverted (source-address-excluded /
	// destination-address-excluded) the header is annotated "(except)" so the
	// gRPC text detail shows the SAME security meaning as the rule and the local
	// CLI — the rule matches every address EXCEPT those listed. Printing the
	// listed addresses under a plain header showed the OPPOSITE meaning.
	printAddrs := func(label string, addrs []string, excluded bool) {
		if excluded {
			fmt.Fprintf(buf, "      %s (except):\n", label)
		} else {
			fmt.Fprintf(buf, "      %s:\n", label)
		}
		for _, addr := range addrs {
			resolved := grpcResolveAddress(cfg, addr)
			// #3358: unqualify a synthetic zone-local key (#3061,
			// zone-local/<zone>/<name>) to the authored book name so the
			// internal compiler token never leaks; resolution still keys off
			// the qualified token (it is the global-book key).
			fmt.Fprintf(buf, "        %s%s\n", config.DisplayAddressName(addr), resolved)
		}
	}
	// #3408: surface a per-policy counter read failure as a warning AFTER all
	// reads rather than silently omitting the session-statistics block.
	var readErr error
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker.
		if zpp == nil {
			policySetID++
			continue
		}
		if (filterFrom != "" && zpp.FromZone != filterFrom) ||
			(filterTo != "" && zpp.ToZone != filterTo) {
			policySetID++
			continue
		}
		fmt.Fprintf(buf, "Policy: %s -> %s, State: enabled\n",
			qualifyZone(zpp.FromZone), qualifyZone(zpp.ToZone))
		for i, pol := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if pol == nil {
				continue
			}
			ruleQuarantined := isQuarantined(zpp.FromZone) || isQuarantined(zpp.ToZone)
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			capAction := strings.ToUpper(action[:1]) + action[1:]
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			// #3062: a scheduler-inactive policy appends State: inactive +
			// the scheduler name. Active/non-scheduled policies stay
			// bit-identical (no suffix), keeping the gRPC text plane in
			// agreement with the CLI detail surface.
			fmt.Fprintf(buf, "\n  Policy: %s, action-type: %s%s, Index: %d\n", pol.Name, capAction,
				policyDetailStateSuffix(pol.SchedulerName, schedActive, haveSched),
				dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)))
			if pol.Description != "" {
				fmt.Fprintf(buf, "    Description: %s\n", pol.Description)
			}
			fmt.Fprintf(buf, "    Match:\n")
			fmt.Fprintf(buf, "      Source zone: %s\n", qualifyZone(zpp.FromZone))
			fmt.Fprintf(buf, "      Destination zone: %s\n", qualifyZone(zpp.ToZone))
			printAddrs("Source addresses", pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded)
			printAddrs("Destination addresses", pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded)
			fmt.Fprintf(buf, "      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Fprintf(buf, "        %s\n", app)
			}
			fmt.Fprintf(buf, "    Then:\n")
			fmt.Fprintf(buf, "      %s\n", action)
			// #3667 (H04): surface the independent at-create/at-close session-log
			// modes instead of a bare "log" so a remote operator can tell whether
			// session starts, closes, or both are logged (different cost + audit
			// meaning). SessionLogModes is the SSOT shared with the local CLI.
			if modes := pol.Log.SessionLogModes(); len(modes) > 0 {
				fmt.Fprintf(buf, "      Session log: %s\n", strings.Join(modes, ", "))
			}
			if pol.Count {
				fmt.Fprintf(buf, "      count\n")
			}
			if ruleQuarantined {
				fmt.Fprintf(buf, "    Session statistics: %s\n", config.ZoneQuarantineLiveCountersUnavailable)
			} else if (statsEnabled || pol.Count) && readPolicy != nil {
				counters, err := readPolicy(ruleID)
				switch {
				case err == nil:
					fmt.Fprintf(buf, "    Session statistics:\n")
					fmt.Fprintf(buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					// #7016: say so explicitly. Omitting the block silently is
					// indistinguishable from `policy-stats` being off.
					fmt.Fprintf(buf, "    Session statistics: not available "+
						"(not yet published by the dataplane)\n")
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else if !statsEnabled && !pol.Count {
				// #8177: counted, not printed per-rule. A per-rule line would
				// repeat one system-wide fact on every policy; one trailing
				// note states it once and names how many rows it covers.
				statsDisabledDetail++
			}
		}
		policySetID++
		fmt.Fprintln(buf)
	}
	// Global policies. #3357: a from/to-zone filter no longer suppresses the
	// global block — the filtered detail surface must still show an unscoped
	// global (enforced for every pair) and a scoped global (#3148) targeting
	// the filtered pair. The "Global policies:" header prints lazily so a
	// filter that selects no global leaves no dangling empty header.
	if len(cfg.Security.GlobalPolicies) > 0 {
		globalHeaderPrinted := false
		for i, pol := range cfg.Security.GlobalPolicies {
			// #3476: skip a nil global rule like the runtime walker does.
			if pol == nil {
				continue
			}
			// #3357: drop a scoped global that targets a different zone pair.
			if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZones, pol.Match.ToZones, filterFrom, filterTo) {
				continue
			}
			if !globalHeaderPrinted {
				fmt.Fprintf(buf, "Global policies:\n")
				globalHeaderPrinted = true
			}
			ruleQuarantined := scopeQuarantined(pol.Match.FromZones, pol.Match.ToZones)
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			capAction := strings.ToUpper(action[:1]) + action[1:]
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			// #3062: scheduler-inactive global policy appends State: inactive.
			fmt.Fprintf(buf, "\n  Policy: %s, action-type: %s%s, Index: %d\n", pol.Name, capAction,
				policyDetailStateSuffix(pol.SchedulerName, schedActive, haveSched),
				dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)))
			if pol.Description != "" {
				fmt.Fprintf(buf, "    Description: %s\n", pol.Description)
			}
			fmt.Fprintf(buf, "    Match:\n")
			// #3286/#4626: a scoped global (#3148) narrows itself to a zone
			// SET; surface the configured scope so the detail view does not
			// read as all-zones. Omitted for an unscoped global (no regression).
			if len(pol.Match.FromZones) > 0 {
				fmt.Fprintf(buf, "      Source zone: %s\n",
					qualifyScopeLabel(pol.Match.FromZones, ""))
			}
			if len(pol.Match.ToZones) > 0 {
				fmt.Fprintf(buf, "      Destination zone: %s\n",
					qualifyScopeLabel(pol.Match.ToZones, ""))
			}
			printAddrs("Source addresses", pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded)
			printAddrs("Destination addresses", pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded)
			fmt.Fprintf(buf, "      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Fprintf(buf, "        %s\n", app)
			}
			fmt.Fprintf(buf, "    Then:\n")
			fmt.Fprintf(buf, "      %s\n", action)
			// #3667 (H04): surface the independent at-create/at-close session-log
			// modes instead of a bare "log" so a remote operator can tell whether
			// session starts, closes, or both are logged (different cost + audit
			// meaning). SessionLogModes is the SSOT shared with the local CLI.
			if modes := pol.Log.SessionLogModes(); len(modes) > 0 {
				fmt.Fprintf(buf, "      Session log: %s\n", strings.Join(modes, ", "))
			}
			if pol.Count {
				fmt.Fprintf(buf, "      count\n")
			}
			if ruleQuarantined {
				fmt.Fprintf(buf, "    Session statistics: %s\n", config.ZoneQuarantineLiveCountersUnavailable)
			} else if (statsEnabled || pol.Count) && readPolicy != nil {
				counters, err := readPolicy(ruleID)
				switch {
				case err == nil:
					fmt.Fprintf(buf, "    Session statistics:\n")
					fmt.Fprintf(buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					// #7016: say so explicitly. Omitting the block silently is
					// indistinguishable from `policy-stats` being off.
					fmt.Fprintf(buf, "    Session statistics: not available "+
						"(not yet published by the dataplane)\n")
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else if !statsEnabled && !pol.Count {
				// #8177: counted, not printed per-rule. A per-rule line would
				// repeat one system-wide fact on every policy; one trailing
				// note states it once and names how many rows it covers.
				statsDisabledDetail++
			}
		}
		fmt.Fprintln(buf)
	}
	if readErr != nil {
		fmt.Fprintf(buf, "warning: policy counter read failed (session statistics may be incomplete): %v\n", readErr)
	}
	// #8177: the note mechanism this surface was missing. Wording is
	// byte-identical to the three sibling renderers, with "read 0" true here in
	// the sense that the block was omitted rather than a zero printed — the
	// operator-facing fact is the same one, and four different sentences about
	// one state is what #7776 was written to stop.
	if statsDisabledDetail > 0 {
		fmt.Fprintf(buf, "note: %d policy count(s) read 0 because policy-stats is disabled "+
			"system-wide, not because no traffic matched (enable with "+
			"`set security policy-stats system-wide enable`, or add `count` to an "+
			"individual policy)\n", statsDisabledDetail)
	}
}

// showPolicyOptions renders prefix-lists and policy-statement terms
// from `policy-options { ... }` configuration.
func (s *Server) showPolicyOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	po := &cfg.PolicyOptions
	if len(po.PrefixLists) > 0 {
		buf.WriteString("Prefix lists:\n")
		for name, pl := range po.PrefixLists {
			fmt.Fprintf(buf, "  %-30s %d prefixes\n", name, len(pl.Prefixes))
			for _, p := range pl.Prefixes {
				fmt.Fprintf(buf, "    %s\n", p)
			}
		}
	}
	if len(po.PolicyStatements) > 0 {
		if len(po.PrefixLists) > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString("Policy statements:\n")
		for name, ps := range po.PolicyStatements {
			fmt.Fprintf(buf, "  %s", name)
			if ps.DefaultAction != "" {
				fmt.Fprintf(buf, " (default: %s)", ps.DefaultAction)
			}
			buf.WriteString("\n")
			for _, t := range ps.Terms {
				fmt.Fprintf(buf, "    term %s:\n", t.Name)
				if len(t.FromProtocols) == 1 {
					fmt.Fprintf(buf, "      from protocol %s\n", t.FromProtocols[0])
				} else if len(t.FromProtocols) > 1 {
					fmt.Fprintf(buf, "      from protocol [ %s ]\n", strings.Join(t.FromProtocols, " "))
				}
				for _, pl := range t.PrefixList {
					fmt.Fprintf(buf, "      from prefix-list %s\n", pl)
				}
				for _, c := range t.FromCommunity {
					fmt.Fprintf(buf, "      from community %s\n", c)
				}
				for _, ap := range t.FromASPath {
					fmt.Fprintf(buf, "      from as-path %s\n", ap)
				}
				for _, rf := range t.RouteFilters {
					match := rf.MatchType
					if rf.MatchType == "upto" && rf.UptoLen > 0 {
						match = fmt.Sprintf("upto /%d", rf.UptoLen)
					}
					fmt.Fprintf(buf, "      from route-filter %s %s\n", rf.Prefix, match)
				}
				if t.Action != "" {
					fmt.Fprintf(buf, "      then %s\n", t.Action)
				}
				if t.NextHop != "" {
					fmt.Fprintf(buf, "      then next-hop %s\n", t.NextHop)
				}
				if t.LoadBalance != "" {
					fmt.Fprintf(buf, "      then load-balance %s\n", t.LoadBalance)
				}
			}
		}
	}
	if len(po.PrefixLists) == 0 && len(po.PolicyStatements) == 0 {
		buf.WriteString("No policy-options configured\n")
	}
}

// policyCounterCell renders one packets/bytes cell of the hit-count text
// table. A published counter renders as its decimal value, byte-identical to
// the previous %d formatting; an UNPUBLISHED counter (#7016) renders "n/a"
// rather than a 0 an operator would read as "this rule matched no traffic".
func policyCounterCell(v uint64, published bool) string {
	if !published {
		return "n/a"
	}
	return strconv.FormatUint(v, 10)
}
