package cli

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// runtimePolicyIndex returns the span-accumulated runtime/RT_FLOW policy ID for
// the policy at (policySetID, sliceIndex), used as the displayed detail `Index`
// so it matches the numeric policy ID the RT_FLOW/event path logs (#3063). It
// delegates to dpuserspace.RuntimePolicyIndex — the SSOT shared with the gRPC
// text detail renderer (#3667) — which falls back to the raw ordinal
// policySetID*MaxRulesPerPolicy + sliceIndex when the lookup has no entry.
// This is a DISPLAY identity only — it is NOT the counter handle passed to
// ReadPolicyCounters (that stays the raw ordinal; see policyRuleIDForCounter).
func runtimePolicyIndex(ids map[[2]uint32]uint32, policySetID, sliceIndex uint32) uint32 {
	return dpuserspace.RuntimePolicyIndex(ids, policySetID, sliceIndex)
}

// policyCountCell renders one "Policy count" cell of the hit-count table.
// A published counter renders as its decimal packet count, byte-identical to
// the previous %d formatting. An UNPUBLISHED counter (#7016) renders "n/a"
// rather than a "0" an operator would read as "this rule matched no traffic" --
// the #3345 counter-unavailable-is-not-zero contract, applied per rule.
func policyCountCell(count uint64, published bool) string {
	if !published {
		return "n/a"
	}
	return strconv.FormatUint(count, 10)
}

func (c *CLI) showPoliciesHitCount(cfg *config.Config, fromZone, toZone string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}

	// #4344: read the whole policy set from ONE snapshot (O(P+C), one brief
	// dataplane lock) via the #3965 bulk reader instead of a per-policy
	// ReadPolicyCounters loop that rebuilt the ruleID->counter index and
	// rescanned the config under the policy mutex on every rule. The reader
	// falls back to the per-policy read for dataplanes without the bulk
	// snapshot (test fakes / retired eBPF), so the displayed values are
	// identical. cfg is the config walked below, so the snapshot's handles
	// line up with the handles computed here.
	readPolicy := dpuserspace.NewPolicyCounterReader(c.dp, cfg, c.dp.ReadPolicyCounters)

	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): per-policy hit counters are maintained and displayed only
	// when policy-stats is enabled system-wide (default off). The
	// Prometheus collector already gates on this knob; gate the CLI
	// hit-count table identically so the CLI, gRPC text, structured
	// gRPC, and Prometheus surfaces all report the SAME values. When the
	// knob is off the "Policy count" column reads 0 (we skip the
	// dataplane read).
	statsEnabled := cfg.Security.PolicyStatsEnabled

	fmt.Println("Logical system: root-logical-system")
	fmt.Printf("%-8s%-17s%-18s%-24s%-14s%s\n",
		"Index", "From zone", "To zone", "Name", "Policy count", "Action")

	// #3408: surface a per-policy counter read failure as a warning AFTER
	// all reads, rather than printing clean-zero hit counts.
	var readErr error
	// #7016: an UNPUBLISHED per-rule counter is NOT a read failure. The helper
	// has simply published nothing for that rule id yet -- the window before
	// the first 1 Hz status poll lands, or config skew after a non-abort-class
	// apply failure (#5679). Rendering it as an authoritative "0" under a
	// "policy counter read failed" warning sent the operator hunting a fault
	// that does not exist, so it gets its own disposition: the count cell reads
	// "n/a" and a trailing note says why. Same not-populated-vs-failed split
	// `show security zones` makes for dataplane.ErrCounterNotPopulated (#6843).
	var unpublished int
	// #7776: rows whose counter was NOT read because policy-stats is disabled
	// system-wide and the rule carries no per-rule `count`. Those cells render
	// an authoritative-looking "0" that an operator reads as "this policy has
	// not matched", when the truth is "this view was never asked to look".
	// Counted rather than inferred from `!statsEnabled`, because a rule with
	// `count` IS read even when the system-wide knob is off, so a blanket
	// "every count reads 0" would be false for a mixed config.
	var statsDisabled int
	index := uint32(1)
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker.
		if zpp == nil {
			policySetID++
			continue
		}
		if fromZone != "" && zpp.FromZone != fromZone {
			policySetID++
			continue
		}
		if toZone != "" && zpp.ToZone != toZone {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if pol == nil {
				continue
			}
			action := "Permit"
			switch pol.Action {
			case 1:
				action = "Deny"
			case 2:
				action = "Reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var count uint64
			published := true
			if statsEnabled || pol.Count {
				counters, err := readPolicy(ruleID)
				switch {
				case err == nil:
					count = counters.Packets
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					published = false
					unpublished++
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else {
				// Reached ONLY when policy-stats is off and the rule carries no
				// `count`: this function early-returns unless the dataplane is
				// loaded, so there is no third way in. Written bare rather than
				// re-testing `!statsEnabled && !pol.Count`, which is tautological
				// here -- a guard that cannot fail reads as protection and is not.
				// The gRPC twin DOES need the explicit form; its read condition
				// also carries `readPolicy != nil`.
				statsDisabled++
			}
			fmt.Printf("%-8d%-17s%-18s%-24s%-14s%s\n",
				index, zpp.FromZone, zpp.ToZone, pol.Name,
				policyCountCell(count, published), action)
			index++
		}
		policySetID++
	}
	// Global policies. #3357: a from/to-zone filter no longer suppresses the
	// global block — an unscoped global is enforced for every zone pair and a
	// scoped global (#3148) may target exactly the filtered pair, so the
	// filtered hit-count table must show the globals that govern it. Per-rule
	// scope is matched against the filter via GlobalPolicyAppliesToZonePair;
	// the ruleID is the loop index so skipped rows keep counter alignment.
	if len(cfg.Security.GlobalPolicies) > 0 {
		for i, pol := range cfg.Security.GlobalPolicies {
			// #3476: skip a nil global rule like the runtime walker does.
			if pol == nil {
				continue
			}
			// #3357: drop a scoped global that targets a different zone pair.
			if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZones, pol.Match.ToZones, fromZone, toZone) {
				continue
			}
			action := "Permit"
			switch pol.Action {
			case 1:
				action = "Deny"
			case 2:
				action = "Reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var count uint64
			published := true
			if statsEnabled || pol.Count {
				counters, err := readPolicy(ruleID)
				switch {
				case err == nil:
					count = counters.Packets
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					published = false
					unpublished++
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else {
				// Reached ONLY when policy-stats is off and the rule carries no
				// `count`: this function early-returns unless the dataplane is
				// loaded, so there is no third way in. Written bare rather than
				// re-testing `!statsEnabled && !pol.Count`, which is tautological
				// here -- a guard that cannot fail reads as protection and is not.
				// The gRPC twin DOES need the explicit form; its read condition
				// also carries `readPolicy != nil`.
				statsDisabled++
			}
			// #3286/#4626: a scoped global (#3148) shows its zone SET in the
			// From/To columns so counter-based validation is unambiguous;
			// an unscoped global keeps junos-global/junos-global.
			hcFrom := config.ScopeLabelOr(pol.Match.FromZones, "junos-global")
			hcTo := config.ScopeLabelOr(pol.Match.ToZones, "junos-global")
			fmt.Printf("%-8d%-17s%-18s%-24s%-14s%s\n",
				index, hcFrom, hcTo, pol.Name,
				policyCountCell(count, published), action)
			index++
		}
	}
	// #3363: the IMPLICIT default-policy is the catch-all every flow matching
	// no configured rule rides. It now has a reserved hit counter (read via the
	// DefaultPolicySentinelID handle), surfaced here as a final row separated
	// from the configured-rule totals so an operator can answer "how many
	// packets are hitting the default deny?". Shown only in the unfiltered view
	// (it spans every zone pair, like the globals). Gated on policy-stats like
	// every other row so all surfaces report the same value.
	if fromZone == "" && toZone == "" {
		defAction := "Permit"
		switch cfg.Security.DefaultPolicy {
		case config.PolicyDeny:
			defAction = "Deny"
		case config.PolicyReject:
			defAction = "Reject"
		}
		var defCount uint64
		defPublished := true
		if statsEnabled {
			counters, err := readPolicy(dataplane.DefaultPolicySentinelID)
			switch {
			case err == nil:
				defCount = counters.Packets
			case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
				defPublished = false
				unpublished++
			default:
				if readErr == nil {
					readErr = err
				}
			}
		} else {
			statsDisabled++
		}
		fmt.Printf("%-8s%-17s%-18s%-24s%-14s%s\n",
			"-", "-", "-", dataplane.DefaultPolicyName,
			policyCountCell(defCount, defPublished), defAction)
	}
	if readErr != nil {
		fmt.Printf("warning: policy counter read failed (counts may be incomplete): %v\n", readErr)
	}
	if unpublished > 0 {
		fmt.Printf("note: %d policy counter(s) not yet published by the dataplane "+
			"(shown as n/a; the helper has not reported these rules yet)\n", unpublished)
	}
	// #7776: without this the table renders a well-formed "0" for every row and
	// an operator reads "this policy has not matched" when the surface was
	// never asked to look -- an instrument answering "nothing" when it means
	// "I cannot see".
	if statsDisabled > 0 {
		fmt.Printf("note: %d policy count(s) read 0 because policy-stats is disabled "+
			"system-wide, not because no traffic matched (enable with "+
			"`set security policy-stats system-wide enable`, or add `count` to an "+
			"individual policy)\n", statsDisabled)
	}
	return nil
}

// showPoliciesDetail displays an expanded Junos-style detail view of security policies.

// printPolicyMatchAddresses renders a policy's Source/Destination addresses in
// the detail view. #3336: when `source-address-excluded` /
// `destination-address-excluded` is set the match sense is INVERTED — the rule
// matches every address EXCEPT those listed — so the header is annotated
// "(except)". Without this an operator reading the detail saw the rule's
// meaning backwards. An un-inverted policy renders bit-identically to before.
func printPolicyMatchAddresses(cfg *config.Config, pol *config.Policy) {
	printAddrs := func(label string, addrs []string, excluded bool) {
		if excluded {
			fmt.Printf("  %s (except):\n", label)
		} else {
			fmt.Printf("  %s:\n", label)
		}
		for _, addr := range addrs {
			if addr == "any" {
				fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
				fmt.Printf("    any-ipv6(global): ::/0\n")
			} else if config.IsPolicyAddressWildcardKeyword(addr) {
				// #9574: the compiled config keeps `any-ipv4` / `any-ipv6`; render
				// the family line the `any` arm renders, not the keyword as a name.
				fmt.Printf("    %s(global): %s\n", addr, config.PolicyAddressKeywordLiteral(addr))
			} else {
				resolved := resolveAddressDetail(cfg, addr)
				// #3358: a zone-local address book (#3061) is folded into the
				// global book under the synthetic key zone-local/<zone>/<name>.
				// Render the authored name + zone scope ("web(zone trust)")
				// instead of leaking the internal token mislabelled "(global)" —
				// the address is zone-scoped, not global. Resolution still keys
				// off the qualified token (it is the global-book key).
				if zone, name, ok := config.ZoneLocalUnqualify(addr); ok {
					fmt.Printf("    %s(zone %s): %s\n", name, zone, resolved)
				} else {
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
		}
	}
	printAddrs("Source addresses", pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded)
	printAddrs("Destination addresses", pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded)
}

func (c *CLI) showPoliciesDetail(cfg *config.Config, fromZone, toZone string) error {
	schedActive, haveSched := c.policySchedulerActiveState()
	// #3063: the displayed Index must equal the runtime/RT_FLOW policy ID,
	// which advances by application-set expansion. RuntimePolicyIDs mirrors the
	// snapshot's PolicyID assignment so an operator cross-referencing a
	// policy-deny log lands on the correct detail row even after a multi-app
	// policy shifts the ID namespace.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	policySetID := uint32(0)
	seqNum := 1
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker.
		if zpp == nil {
			policySetID++
			continue
		}
		if fromZone != "" && zpp.FromZone != fromZone {
			policySetID++
			continue
		}
		if toZone != "" && zpp.ToZone != toZone {
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
			ruleID := runtimePolicyIndex(runtimeIDs, policySetID, uint32(i))
			// #3062: reflect runtime scheduler state — a policy bound to a
			// currently-inactive scheduler reports State: inactive (the
			// dataplane is dropping its rule). Active/non-scheduled policies
			// stay bit-identical (State: enabled, no Scheduler line).
			state := policyDetailState(pol.SchedulerName, schedActive, haveSched)
			fmt.Printf("Policy: %s, action-type: %s, State: %s, Index: %d, Scope Policy: 0\n",
				pol.Name, action, state, ruleID)
			fmt.Printf("  Policy Type: Configured\n")
			if state == "inactive" {
				fmt.Printf("  Scheduler: %s (inactive)\n", pol.SchedulerName)
			}
			fmt.Printf("  Sequence number: %d\n", seqNum)
			fmt.Printf("  From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
			if pol.Description != "" {
				fmt.Printf("  Description: %s\n", pol.Description)
			}
			printPolicyMatchAddresses(cfg, pol)
			for _, app := range pol.Match.Applications {
				fmt.Printf("  Application: %s\n", app)
				c.printAppDetail(cfg, app)
			}
			if modes := pol.Log.SessionLogModes(); len(modes) > 0 {
				fmt.Printf("  Session log: %s\n", strings.Join(modes, ", "))
			}
			seqNum++
		}
		policySetID++
		fmt.Println()
	}

	// Global policies. #3357: a from/to-zone filter no longer suppresses the
	// global block — the filtered detail view must still show an unscoped
	// global (enforced for every pair) and a scoped global (#3148) targeting
	// the filtered pair. GlobalPolicyAppliesToZonePair selects per-rule scope.
	if len(cfg.Security.GlobalPolicies) > 0 {
		for i, pol := range cfg.Security.GlobalPolicies {
			// #3476: skip a nil global rule like the runtime walker does.
			if pol == nil {
				continue
			}
			// #3357: drop a scoped global that targets a different zone pair.
			if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZones, pol.Match.ToZones, fromZone, toZone) {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := runtimePolicyIndex(runtimeIDs, policySetID, uint32(i))
			// #3062: scheduler-inactive global policy reports State: inactive.
			state := policyDetailState(pol.SchedulerName, schedActive, haveSched)
			fmt.Printf("Policy: %s, action-type: %s, State: %s, Index: %d, Scope Policy: 0\n",
				pol.Name, action, state, ruleID)
			fmt.Printf("  Policy Type: Configured\n")
			if state == "inactive" {
				fmt.Printf("  Scheduler: %s (inactive)\n", pol.SchedulerName)
			}
			fmt.Printf("  Sequence number: %d\n", seqNum)
			// #3286/#4626: a scoped global policy (#3148) narrows itself to a
			// zone SET via `match from-zone/to-zone`. Show the configured
			// scope instead of the all-zones "junos-global" placeholder so
			// an operator can tell which zones a global rule applies to.
			// An unscoped global keeps junos-global/junos-global.
			globalFromZone := config.ScopeLabelOr(pol.Match.FromZones, "junos-global")
			globalToZone := config.ScopeLabelOr(pol.Match.ToZones, "junos-global")
			fmt.Printf("  From zone: %s, To zone: %s\n", globalFromZone, globalToZone)
			if pol.Description != "" {
				fmt.Printf("  Description: %s\n", pol.Description)
			}
			printPolicyMatchAddresses(cfg, pol)
			for _, app := range pol.Match.Applications {
				fmt.Printf("  Application: %s\n", app)
				c.printAppDetail(cfg, app)
			}
			if modes := pol.Log.SessionLogModes(); len(modes) > 0 {
				fmt.Printf("  Session log: %s\n", strings.Join(modes, ", "))
			}
			seqNum++

			_ = ruleID
		}
		fmt.Println()
	}
	return nil
}

// resolveAddressDetail returns the CIDR for an address name, or the name itself if not found.

// showMatchPolicies performs a 5-tuple policy lookup and shows matching rules.

func (c *CLI) showMatchPolicies(cfg *config.Config, args []string) error {
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// #3696: parse the selector grammar through the single strict SSOT parser
	// (policymatch.ParseSelectorArgs) shared by all four CLI surfaces + the gRPC
	// test-policy bridge. A value-taking selector present WITHOUT a value, an
	// UNKNOWN selector token, an explicit-empty typed value, and a malformed
	// IP / port / protocol / icmp value are all HARD ERRORS instead of silently
	// degrading to the wildcard — a firewall policy simulator must answer the
	// query the operator typed, not a broader one. The per-value validation
	// (ParsePort / ParseICMPValue / ValidateProtocol / net.ParseIP, #3116 /
	// #3108 / #3284 / #1711) is folded into the parser, so the redundant
	// per-surface checks are gone.
	sel, err := policymatch.ParseSelectorArgs(args)
	if err != nil {
		return err
	}
	fromZone, toZone, srcIP, dstIP, proto := sel.FromZone, sel.ToZone, sel.SrcIP, sel.DstIP, sel.Protocol
	srcPort, dstPort := sel.SrcPort, sel.DstPort
	icmpType, icmpCode := sel.ICMPType, sel.ICMPCode
	nonFirstFrag := sel.NonFirstFragment

	if fromZone == "" || toZone == "" {
		// #3628: the selector list is the shared SSOT in policymatch so all four
		// match-policies / test-policy surfaces advertise the same selectors the
		// parser accepts (source-port, icmp-type/icmp-code, protocol by name or
		// number), not the stale tcp|udp-only subset.
		fmt.Println(policymatch.MatchPoliciesUsage)
		return nil
	}

	parsedSrc := net.ParseIP(srcIP)
	parsedDst := net.ParseIP(dstIP)

	// #5579: validate the optional ingress-interface selector against the live
	// config (zone membership + lifeline reject) so the host-inbound classifier is
	// scoped only to a real interface of the queried zone, failing closed on an
	// unknown / zone-mismatched / lifeline ref exactly like the REST/gRPC surfaces.
	if err := dpuserspace.ResolveHostInboundIngressInterface(cfg, fromZone, sel.IngressInterface); err != nil {
		return err
	}

	// #3042: delegate to the single shared simulator so the CLI agrees with
	// the runtime evaluator. The pre-#3042 loop scanned only zone-pair
	// policies (never globals), hard-coded "default deny" (ignoring
	// default-policy permit-all), and used a narrow address/app matcher that
	// missed predefined apps, nested application-sets, literal CIDRs,
	// any-ipv4/any-ipv6, and source/destination exclusion.
	// #3105: pass the live dynamic-address feed-prefix overlay so a feed-backed
	// address-name resolves to its live CIDRs on-box, matching the REST/gRPC
	// simulators and the AF_XDP helper. Nil (CLI outside the daemon) keeps the
	// pre-#3105 static-only behavior.
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone: fromZone,
		ToZone:   toZone,
		SrcIP:    parsedSrc,
		DstIP:    parsedDst,
		// #6377: colon-strict text family from the RAW operator string so the
		// unsupported-tuple gate does not fold an IPv4-mapped IPv6 source to v4.
		SrcFamily: config.NATAddrFamily(srcIP),
		DstFamily: config.NATAddrFamily(dstIP),
		Protocol:  proto,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		ICMPType:  icmpType,
		ICMPCode:  icmpCode,
		// #5572: a non-first IP fragment (no L4 header) reproduces the #4569
		// fragment-associated deny; false is a normal L4-present packet.
		NonFirstFragment: nonFirstFrag,
		// #5579: scope the host-inbound classifier to this ingress interface's
		// effective view (validated above). "" = zone-scoped, unchanged.
		IngressInterface: sel.IngressInterface,
		FeedOverlay:      c.feedOverlay(),
		// #3104: skip scheduler-inactive policies like the runtime does, so the
		// simulator falls through to the next active rule / default-policy.
		PolicyInactiveFn: c.policyInactiveFn(),
	})
	if res.ContentRejected {
		// #3727: the dataplane fails this config closed (unexpandable
		// application-set) and enforces none of its policies — do NOT print a
		// fabricated permit/deny/default verdict.
		fmt.Printf("Policy content rejected for %s -> %s\n", fromZone, toZone)
		fmt.Printf("  %s\n", policymatch.ContentRejectedShowLine)
		for _, reason := range res.ContentRejectionReasons {
			fmt.Printf("    %s\n", reason)
		}
		return nil
	}
	if res.HostInboundUnmatched {
		// #3285: host-bound traffic — no transit global/default fallback.
		fmt.Printf("No matching to-zone junos-host policy for %s -> junos-host\n", fromZone)
		fmt.Printf("  %s\n", policymatch.HostInboundShowLine)
		// #3627 B1a: name the admitting host-inbound-traffic token (or report
		// deny / global-accept / indeterminate) so the operator sees WHICH
		// system-service/protocol governs local delivery for this tuple, not just
		// that host-inbound-traffic governs it.
		if res.HostInbound != nil {
			if line := res.HostInbound.Describe(); line != "" {
				fmt.Printf("  host-inbound-traffic (zone %s): %s\n", fromZone, line)
			}
		}
		return nil
	}
	// #4373 (E4/H2/H7): if the destination is multicast/broadcast/unspecified/
	// loopback the forwarding path drops it at route lookup before policy runs,
	// so the verdict below (and a `then accept; then log` filter for the same
	// tuple) does not describe real forwarding. Print the advisory ahead of the
	// verdict so the operator reads the caveat, not just the permit/deny.
	if note := res.RouteDropNote(); note != "" {
		fmt.Printf("  %s\n", note)
	}
	// #5572: a non-first fragment whose permit was overridden to an overlapping
	// port-bearing deny — print the advisory ahead of the verdict so the deny is
	// not read as a first-fragment / exact-port match.
	if note := res.FragmentDenyNote(); note != "" {
		fmt.Printf("  %s\n", note)
	}
	if res.UnsupportedTupleFamily {
		// #5720 (codex-182 C-TOOLS): an IPv4 source with an IPv6 destination is
		// an impossible tuple (NAT46 is unimplemented); the forwarding path never
		// produces it and the runtime matcher fails closed. Surface the dedicated
		// verdict instead of a fabricated "No matching policy … (default deny)",
		// which would send an operator to add a permit that can never take
		// effect. Mirrors the REST / gRPC MatchPolicies DisplayAction() render.
		fmt.Printf("%s\n", res.DisplayAction())
		return nil
	}
	if !res.Matched {
		fmt.Printf("No matching policy found for %s -> %s (default %s)\n",
			fromZone, toZone, policymatch.ActionString(res.Action))
		return nil
	}
	if res.Global {
		fmt.Printf("Matching policy (global):\n")
	} else {
		fmt.Printf("Matching policy:\n")
	}
	fmt.Printf("  From zone: %s, To zone: %s\n", fromZone, toZone)
	fmt.Printf("  Policy: %s\n", res.PolicyName)
	// #3331: identify WHICH scoped/global policy matched so a verdict maps back
	// to the runtime policy / session-table ID / audit record when names repeat.
	fmt.Printf("    Policy ID: %d\n", res.PolicyID)
	// #3668: also print the stable rule identity so a hit joins to the inventory /
	// logs / tests even after a policy reorder shifts the numeric Policy ID.
	if res.RuleID != "" {
		fmt.Printf("    Rule ID: %s\n", res.RuleID)
	}
	if res.Global {
		fmt.Printf("    Scope: global (match from-zone: %s, to-zone: %s)\n",
			matchScopeZone(res.FromZone), matchScopeZone(res.ToZone))
	} else {
		fmt.Printf("    Scope: zone-pair (from-zone: %s, to-zone: %s)\n", res.FromZone, res.ToZone)
	}
	// #5649 (C181-C20): a MATCHED to-zone junos-host fine policy still needs
	// the coarse host-inbound-traffic admission gate (LocalDelivery evaluates
	// BOTH — the fine policy action never overrides a coarse deny). Without
	// this line an operator reading a matched permit could believe the fine
	// action alone governs the flow; mirrors the HostInboundUnmatched branch's
	// Describe() call above, which already names the gate for the no-match
	// case (#3627 B1a). res.HostInbound is populated only for to-zone
	// junos-host queries (matchJunosHost), so this is a no-op for transit.
	if res.HostInbound != nil {
		if line := res.HostInbound.Describe(); line != "" {
			fmt.Printf("    host-inbound-traffic (zone %s): %s\n", fromZone, line)
		}
	}
	if res.Description != "" {
		fmt.Printf("    Description: %s\n", res.Description)
	}
	// #3668: annotate "(except)" when the matched rule carries
	// source-address-excluded / destination-address-excluded — the shared matcher
	// inverts correctly, but without the label a positive verdict against a
	// source OUTSIDE an excluded set reads as if the excluded list caused it.
	fmt.Printf("    Source addresses%s: %v\n", policymatch.ExceptSuffix(res.SourceAddressExcluded), res.SrcAddresses)
	fmt.Printf("    Destination addresses%s: %v\n", policymatch.ExceptSuffix(res.DestinationAddressExcluded), res.DstAddresses)
	fmt.Printf("    Applications: %v\n", res.Applications)
	fmt.Printf("    Action: %s\n", policymatch.ActionString(res.Action))
	return nil
}

// matchScopeZone renders a global policy's match from-zone/to-zone scope for the
// match-policies output (#3331). An empty scope means the global policy applies
// to every zone, shown as "any" to match the Junos / `show policies` convention.
func matchScopeZone(z string) string {
	if z == "" {
		return "any"
	}
	return z
}
