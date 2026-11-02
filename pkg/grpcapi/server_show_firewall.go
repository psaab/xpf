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
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/firewallshow"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/policymatch"
)

// readLo0CountersGRPC is the kernel lo0 counter source for the RAW show
// views, a package var so tests can inject a fixture without netlink
// (#16457), mirroring pkg/api's readLo0Counters seam.
var readLo0CountersGRPC = xnft.ReadLo0Counters

// resetLo0CountersGRPC is the `clear firewall all` kernel lo0 reset seam
// (#16457).
var resetLo0CountersGRPC = xnft.ResetLo0Counters

// writeThreeColorPolicerStatus renders the per-color (green/yellow/red)
// conform/exceed and treatment-drop counters for a `then policer <name>` term,
// mirroring the inline per-term `Hit count:` surfacing (#4372). The counters
// come from the userspace dataplane's three_color_policer_counters wire status;
// legacy single-rate `firewall policer` definitions are lowered into the same
// three-color runtime (#4514), so this renders both policer namespaces. Junos
// terms are green=conform (in committed rate), yellow=exceed (above committed,
// within peak/excess), red=violate.
func writeThreeColorPolicerStatus(buf *strings.Builder, ps dpuserspace.ThreeColorPolicerStatus) {
	mode := ps.Mode
	if mode == "" {
		mode = "unknown"
	}
	colorMode := "color-aware"
	if ps.ColorBlind {
		colorMode = "color-blind"
	}
	fmt.Fprintf(buf, "    Policer %s (%s, %s):\n", ps.Name, mode, colorMode)
	fmt.Fprintf(buf, "      green (conform):  %d packets, %d bytes\n", ps.GreenPackets, ps.GreenBytes)
	fmt.Fprintf(buf, "      yellow (exceed):  %d packets, %d bytes\n", ps.YellowPackets, ps.YellowBytes)
	fmt.Fprintf(buf, "      red (violate):    %d packets, %d bytes\n", ps.RedPackets, ps.RedBytes)
	fmt.Fprintf(buf, "      dropped:          %d packets, %d bytes\n", ps.DropPackets, ps.DropBytes)
}

// firewallCountersStaleGRPC reports whether counters printed beside the
// active config's terms on the gRPC raw views belong to a previous
// generation (#16451): the active config is not the applied one and a
// userspace helper status was obtained (so counters are being attributed).
// Undetermined (no helper status) carries no liveness claim, mirroring the
// local CLI raw views.
func (s *Server) firewallCountersStaleGRPC() bool {
	if s == nil || s.store == nil || firewallshow.Applied(s.store) {
		return false
	}
	if _, err := s.userspaceDataplaneStatus(); err != nil {
		return false
	}
	return true
}

// writeFirewallStaleCounterWarning prepends the shared #16451 raw warning.
func (s *Server) writeFirewallStaleCounterWarning(buf *strings.Builder) {
	if s.firewallCountersStaleGRPC() {
		buf.WriteString(firewallshow.StaleCounterWarning)
	}
}

// writeFirewallNotEnforcingWarning prepends the shared #16451 effective-view
// warning when the active config is not the applied one. Unlike the raw
// views it fires even when helper status is unavailable: the effective view
// certifies compiled content as the dataplane's, so an unstamped active
// config must never be presented without the warning (fail-closed).
func (s *Server) writeFirewallNotEnforcingWarning(buf *strings.Builder) {
	if s == nil || s.store == nil || firewallshow.Applied(s.store) {
		return
	}
	buf.WriteString(firewallshow.NotEnforcingWarning)
}

// showFirewall renders the `cli show firewall` output. Writes to
// `buf`. Returns no error — the original case body had no error
// returns; counters that fail to load are silently skipped (same
// as the original).
func (s *Server) showFirewall(cfg *config.Config, buf *strings.Builder) {
	s.writeFirewallStaleCounterWarning(buf)
	hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
	if !hasFilters {
		buf.WriteString("No firewall filters configured\n")
		return
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := s.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndexForConfig(userspaceStatus, cfg)
	policerStatuses := dpuserspace.BuildThreeColorPolicerStatusIndexForConfig(userspaceStatus, cfg)
	// Resolve filter IDs for counter display
	var filterIDs map[string]uint32
	if s.dp != nil && s.dp.IsLoaded() {
		if cr := s.applyResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}

	// #3408: surface a filter counter read failure as a warning AFTER all
	// filters rather than printing clean-zero / omitted hit counts.
	var readErr error
	// #16457: kernel lo0 counters for lo0-referenced filters.
	var lo0Err error
	lo0For := func(family, name string) []xnft.Lo0Count {
		counts, err := firewallshow.Lo0CountersForFilter(cfg, family, name, readLo0CountersGRPC)
		if err != nil && lo0Err == nil {
			lo0Err = err
		}
		return counts
	}
	cloneFold16464 := dpuserspace.BuildCloneCounterFold16464(cfg)
	printFilters := func(family string, filters map[string]*config.FirewallFilter) {
		// #15173: same sorted / nil-safe / suppressed-clone-hidden name
		// set as CLI and REST (shared firewallshow.SortedFilterNames).
		for _, name := range firewallshow.SortedFilterNames(filters) {
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
					} else if readErr == nil {
						readErr = err
					}
				}
			}
			cloneRuleStart16464 := make(map[string]uint32)
			cloneHas16464 := make(map[string]bool)
			if filterIDs != nil {
				for cloneName, source := range cloneFold16464[family] {
					if source != name {
						continue
					}
					if fid, ok := filterIDs[family+":"+cloneName]; ok {
						if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
							cloneRuleStart16464[cloneName] = fcfg.RuleStart
							cloneHas16464[cloneName] = true
						} else if readErr == nil {
							readErr = err
						}
					}
				}
			}
			ruleOffset := ruleStart

			// #16460: the per-instance ordinal counts non-nil instances
			// in order; a nil slot owns no runtime counter.
			termOrdinal := uint32(0)
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				firewallshow.WriteTerm(buf, term, false)

				numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						} else if readErr == nil {
							readErr = err
						}
					}
					ruleOffset += numRules
				}
				for cloneName := range cloneHas16464 {
					cloneFilter := filters[cloneName]
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
								if ctrs, err := s.dp.ReadFilterCounters(cloneOffset + i); err == nil {
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
					fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
				if term.Policer != "" {
					key := dpuserspace.ThreeColorPolicerStatusKey{
						Family: family, FilterName: name, TermName: term.Name, Policer: term.Policer,
					}
					if ps, ok := policerStatuses[key]; ok {
						writeThreeColorPolicerStatus(buf, ps)
					}
				}
			}
			// #18728: the synthetic implicit-discard term the dataplane
			// appends to a filter with no terminal catch-all.
			implicit, implicitOk := dpuserspace.ImplicitDiscardCounterForFilter(userspaceCounters, family, name, filter)
			firewallshow.WriteImplicitDiscard(buf, filter, firewallshow.ImplicitDiscardCounter{
				Packets: implicit.Packets, Bytes: implicit.Bytes, Have: implicitOk,
			}, false)
			lo0Counts := lo0For(family, name)
			firewallshow.WriteLo0KernelCounters(buf, filter, lo0Counts)
			firewallshow.WriteLo0ImplicitDiscardCounter(buf, filter, family, lo0Counts)
			buf.WriteString("\n")
		}
	}
	printFilters("inet", cfg.Firewall.FiltersInet)
	printFilters("inet6", cfg.Firewall.FiltersInet6)
	if readErr != nil {
		fmt.Fprintf(buf, "warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
	if lo0Err != nil {
		fmt.Fprintf(buf, "warning: kernel lo0 counter read failed (lo0 kernel counts may be incomplete): %v\n", lo0Err)
	}
}

// --- #1700: residual ShowText branches ---

func (s *Server) showTestPolicy(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	params := strings.TrimPrefix(req.Topic, "test-policy:")
	var fromZone, toZone, srcIP, dstIP, proto, ingressIface string
	var srcPort, dstPort *uint16
	var icmpType, icmpCode *uint8
	var nonFirstFrag bool
	var srcPortErr, portErr, protoErr, icmpTypeErr, icmpCodeErr, fragErr, parseErr error
	// #3696: fail CLOSED on malformed selector grammar, the server-boundary
	// sibling of the strict CLI parser (policymatch.ParseSelectorArgs). The old
	// `if len(parts) != 2 { continue }` silently DROPPED any comma segment
	// lacking a `key=value` — `...,port` left the query port unspecified; a
	// constrained term would not match, while an unconstrained term may still
	// match. An unknown key (`prot=tcp`) likewise left protocol unspecified; a
	// constrained term would not match, but `application any` could still match,
	// so a skipped deny could let a later permit match.
	// An explicit-empty typed value (`port=`) was likewise treated as omitted
	// because ParsePort("") returns (nil, nil), so the handler could not tell
	// "key absent" (unspecified; constrained terms do not match) from "key
	// present, empty value" (malformed).
	// A malformed segment, an unknown key, or an empty value is now a reported
	// error, distinguishing key-absent from key-empty (M01). An entirely empty
	// param string (bare `test-policy:`) still falls through to the
	// missing-from/to-zone diagnostic below rather than reading as malformed.
	// #3709: reject a DUPLICATE selector key (e.g. `from=trust,from=dmz`). The
	// switch below re-assigns fromZone/dstPort/... on a repeated key, silently
	// LAST-WINning, so the gRPC-text simulator answered for a DIFFERENT packet
	// than the operator typed — and it disagreed with REST (first-win) on WHICH
	// value survived. There is no correct silent pick, so a repeat is a reported
	// error, matching the strict CLI parser (policymatch.ParseSelectorArgs).
	seen := make(map[string]bool)
	if params != "" {
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				if parseErr == nil {
					parseErr = fmt.Errorf("malformed selector segment %q (expected key=value)", kv)
				}
				continue
			}
			if seen[parts[0]] {
				// A duplicate KNOWN key last-wins below; a duplicate UNKNOWN key
				// already recorded an "unknown selector" error on its first
				// occurrence (parseErr is set-once), so this only overrides when
				// no earlier grammar error was captured.
				if parseErr == nil {
					parseErr = fmt.Errorf("selector %q specified more than once", parts[0])
				}
				continue
			}
			seen[parts[0]] = true
			switch parts[0] {
			case "from":
				fromZone = parts[1]
			case "to":
				toZone = parts[1]
			case "src":
				srcIP = parts[1]
			case "dst":
				dstIP = parts[1]
			case "srcport":
				// #3107: a source-port constraint must thread into the shared
				// matcher's Query.SrcPort term (previously inexpressible from the
				// CLI `test policy` topic, overmatching source-port-constrained
				// applications). Validate via the shared helper (#3116) so a
				// malformed/out-of-range value reports an error instead of
				// silently becoming the 0 unspecified value.
				srcPort, srcPortErr = policymatch.ParsePort(parts[1])
			case "port":
				// #3116: a malformed/out-of-range port must NOT silently become 0
				// (the unspecified value). A constrained term would then never
				// match, while an unconstrained term could still match and produce
				// a misleading verdict. Validate via the shared helper and report
				// the error the way a bad src/dst is reported below.
				dstPort, portErr = policymatch.ParsePort(parts[1])
			case "proto":
				// #3108: reject an unknown/out-of-range protocol token rather than
				// treating it as unspecified: constrained terms would never match,
				// but `application any` could still match and conceal invalid input.
				// Validate via the shared helper and report the error the way a bad
				// port/src is reported below.
				proto = parts[1]
				protoErr = policymatch.ValidateProtocol(proto)
			case "ictype":
				// #3284: ICMP/ICMPv6 type so a type-constrained application term
				// (junos-icmp-ping = type 8) is honored. Empty is unspecified (the
				// term never matches); a malformed/out-of-range value errors.
				icmpType, icmpTypeErr = policymatch.ParseICMPValue(parts[1])
			case "iccode":
				icmpCode, icmpCodeErr = policymatch.ParseICMPValue(parts[1])
			case "frag":
				// #5572: non-first-fragment flag (l4_present == false). The remote
				// CLI `test policy` emits `frag=1` for the `non-first-fragment`
				// selector. Parse as a bool; a malformed value errors like a bad
				// port rather than silently degrading to a normal-packet query.
				nonFirstFrag, fragErr = strconv.ParseBool(parts[1])
			case "iif":
				// #5579: ingress-interface selector — the remote CLI `test policy`
				// emits `iif=<ref>` for the `ingress-interface` selector. The ref is
				// validated against the live config (zone membership + lifeline
				// reject) below, before evaluation.
				ingressIface = parts[1]
			default:
				// #3696: an unknown selector key (e.g. `prot=tcp`, a plausible
				// operator abbreviation of `proto`) must not be silently ignored,
				// leaving that dimension at the wildcard.
				if parseErr == nil {
					parseErr = fmt.Errorf("unknown selector %q", parts[0])
				}
			}
		}
	}
	// #18240: validateErr feeds the ordered text switch below so the
	// deliberate cfg==nil-before-grammar ordering is preserved: the switch
	// checks cfg==nil first, so a no-config query still prints "No active
	// configuration" even when Validate would error. With a live config,
	// shared Validate re-checks the IP (#1711) and — config-dependent —
	// the ingress interface (#5579; cfg==nil returns nil there); the
	// per-field text errors captured above stay first in the switch.
	req17198 := policymatch.Request{FromZone: fromZone, ToZone: toZone, SrcIP: srcIP, DstIP: dstIP, Protocol: proto, SrcPort: srcPort, DstPort: dstPort, ICMPType: icmpType, ICMPCode: icmpCode, NonFirstFragment: nonFirstFrag, IngressInterface: ingressIface}
	validateErr := req17198.Validate(cfg)
	switch {
	case cfg == nil:
		buf.WriteString("No active configuration\n")
	case parseErr != nil:
		// #3696: report malformed grammar (a segment lacking key=value, an
		// unknown key, or an explicit-empty typed value) before evaluating, so a
		// typo cannot silently become an omitted (unspecified) selector. Checked
		// before the from/to-zone diagnostic so malformed input is not masked by
		// a legit-looking missing-zone message.
		fmt.Fprintf(buf, "%v\n", parseErr)
	case fromZone == "" || toZone == "":
		buf.WriteString("Missing from/to zone parameters\n")
	case srcPortErr != nil:
		fmt.Fprintf(buf, "invalid source-port: %v\n", srcPortErr)
	case portErr != nil:
		fmt.Fprintf(buf, "invalid port: %v\n", portErr)
	case protoErr != nil:
		fmt.Fprintf(buf, "%v\n", protoErr)
	case icmpTypeErr != nil:
		fmt.Fprintf(buf, "invalid icmp-type: %v\n", icmpTypeErr)
	case icmpCodeErr != nil:
		fmt.Fprintf(buf, "invalid icmp-code: %v\n", icmpCodeErr)
	case fragErr != nil:
		fmt.Fprintf(buf, "invalid frag: %v\n", fragErr)
	case srcIP != "" && net.ParseIP(srcIP) == nil:
		// A non-empty but malformed src would otherwise parse to nil and be
		// treated as a wildcard, yielding a false-positive policy match
		// (#1711). Report it instead. Empty still means any.
		fmt.Fprintf(buf, "invalid src %q\n", srcIP)
	case dstIP != "" && net.ParseIP(dstIP) == nil:
		fmt.Fprintf(buf, "invalid dst %q\n", dstIP)
	case validateErr != nil:
		// #18240/#5579: the shared Validate ingress-interface leg (its only
		// arm that can fire here — zones/IPs/protocol/ports/ICMP/frag were
		// discharged by the branches above or the transport parsers): an
		// unknown / zone-mismatched / lifeline / bare-physical ref fails the
		// query closed (parity with the REST/gRPC/local surfaces).
		fmt.Fprintf(buf, "%v\n", validateErr)
	default:
		// #3103: route the gRPC `test policy` diagnostic through the single
		// shared simulator (pkg/policymatch) so it agrees with the runtime
		// policy evaluator — exact zone-pair -> wildcard-zone tiers (#3090) ->
		// scoped global (#3148) -> configured default-policy,
		// with predefined/nested-app-set applications, literal-CIDR /
		// any-ipv4 / any-ipv6 / address-exclusion / feed-overlay address
		// matching, and source/destination-port terms. The pre-#3103 bespoke
		// matchShowPolicy* helpers skipped the configured default-policy
		// (hard-coded "Default deny"), missed predefined apps and literal
		// CIDRs, and ignored the feed overlay — exactly the operator-lie class
		// #3042 removed from the REST/gRPC MatchPolicies and CLI
		// match-policies surfaces. This was the one surface #3042 missed.
		// #18240: via shared Evaluate (Validate already passed above), whose
		// Verdict this text renderer reads from Result directly.
		res, err := policymatch.Evaluate(cfg, req17198, s.matchLive(cfg))
		if err != nil {
			fmt.Fprintf(buf, "%v\n", err)
			break
		}
		if res.PostNATInputNote != "" {
			fmt.Fprintf(buf, "NOTE: %s\n", res.PostNATInputNote)
		}
		switch {
		case res.FeedPublicationDebt:
			fmt.Fprintf(buf, "%s\n", res.FeedPublicationDebtNote())
		case res.ContentRejected:
			// #3727: the dataplane fails this config closed (unexpandable
			// application-set) and enforces none of its policies. Report the
			// fail-closed retention + the offending content, NOT a fabricated
			// permit/deny/default verdict.
			fmt.Fprintf(buf, "Policy content rejected (no verdict enforced for %s -> %s)\n", fromZone, toZone)
			fmt.Fprintf(buf, "  %s\n", policymatch.ContentRejectedShowLine)
			for _, reason := range res.ContentRejectionReasons {
				fmt.Fprintf(buf, "    %s\n", reason)
			}
		case res.HostOriginated:
			// #16805: from-zone junos-host is host-ORIGINATED — the traffic
			// egresses via the kernel TX path and no security policy is
			// consulted. Reporting it through the UnzonedIngress arm below
			// would falsely name an unknown-zone unconditional deny.
			fmt.Fprintf(buf, "Host-originated (from-zone junos-host -> %s): not evaluated by security policy\n", toZone)
			fmt.Fprintf(buf, "  %s\n", policymatch.HostOriginatedShowLine)
		case res.UnzonedIngress:
			// #8318: the runtime denies an unzoned ingress unconditionally
			// (#6682). Reporting it through the default: arm below would print
			// "Default deny ..." — naming the operator's default-policy as the
			// cause, which is actively wrong on a permit-all box.
			fmt.Fprintf(buf, "Ingress zone unknown (%s -> %s): transit denied\n", fromZone, toZone)
			fmt.Fprintf(buf, "  %s\n", policymatch.UnzonedIngressShowLine)
		case res.UnzonedEgress:
			fmt.Fprintf(buf, "Egress zone unknown (%s -> %s): transit denied\n", fromZone, toZone)
			fmt.Fprintf(buf, "  %s\n", policymatch.UnzonedEgressShowLine)
		case res.HostInboundUnmatched:
			// #3285: host-bound traffic — the dataplane host gate returns None
			// (local delivery; no transit global/default fallback). Do NOT
			// report a default-policy verdict here.
			fmt.Fprintf(buf, "No matching to-zone junos-host policy for %s -> junos-host\n", fromZone)
			fmt.Fprintf(buf, "  %s\n", policymatch.HostInboundShowLine)
			// #14362 (#3627 B1a parity): name the admitting token / deny, as
			// the local CLI does — the generic line alone hides WHICH verdict
			// the coarse gate returns for this tuple.
			if res.HostInbound != nil {
				if line := res.HostInbound.Describe(); line != "" {
					fmt.Fprintf(buf, "  host-inbound-traffic (zone %s): %s\n", fromZone, line)
				}
			}
		case res.Matched && res.Global:
			fmt.Fprintf(buf, "Policy match (global):\n")
			fmt.Fprintf(buf, "  Policy:    %s\n", res.PolicyName)
			// #3685 M04: identify WHICH global policy matched (ID + match scope
			// + description), mirroring `show security match-policies`, so this
			// gRPC-text `test policy` global verdict is not sparser than the
			// show path over the SAME policymatch.Result. Before #3685 the
			// global branch printed only name + action, dropping the policy ID
			// (session-table / audit join key when global names collide with
			// zone-pair names), the global match scope, and the description
			// (ticket / change context).
			fmt.Fprintf(buf, "  Policy ID: %d\n", res.PolicyID)
			fmt.Fprintf(buf, "  Scope:     global (match from-zone: %s, to-zone: %s)\n",
				policymatch.ZoneScopeLabel(res.FromZone), policymatch.ZoneScopeLabel(res.ToZone))
			if res.Description != "" {
				fmt.Fprintf(buf, "  Description: %s\n", res.Description)
			}
			fmt.Fprintf(buf, "  Action:    %s\n", policymatch.ActionString(res.Action))
			// #14362: a matched junos-host policy (global scope can still be
			// host-bound) still needs the coarse gate named; Describe() is
			// empty off-host, so this is a no-op for transit globals.
			if res.HostInbound != nil {
				if line := res.HostInbound.Describe(); line != "" {
					fmt.Fprintf(buf, "  host-inbound-traffic (zone %s): %s\n", fromZone, line)
				}
			}
			// #5572: a non-first fragment whose permit was overridden to this
			// overlapping port-bearing deny — explain the over-drop.
			if note := res.FragmentDenyNote(); note != "" {
				fmt.Fprintf(buf, "  %s\n", note)
			}
		case res.Matched:
			fmt.Fprintf(buf, "Policy match:\n")
			fmt.Fprintf(buf, "  From zone: %s\n  To zone:   %s\n", fromZone, toZone)
			fmt.Fprintf(buf, "  Policy:    %s\n", res.PolicyName)
			fmt.Fprintf(buf, "  Action:    %s\n", policymatch.ActionString(res.Action))
			// #14362 (#5649 parity): a MATCHED to-zone junos-host fine policy
			// still needs the coarse host-inbound-traffic admission gate named
			// — LocalDelivery evaluates BOTH and the fine action never
			// overrides a coarse deny. Without this line a permit whose gate
			// denies read as an unqualified permit.
			if res.HostInbound != nil {
				if line := res.HostInbound.Describe(); line != "" {
					fmt.Fprintf(buf, "  host-inbound-traffic (zone %s): %s\n", fromZone, line)
				}
			}
			// #5572: fragment-associated deny advisory (see global arm).
			if note := res.FragmentDenyNote(); note != "" {
				fmt.Fprintf(buf, "  %s\n", note)
			}
		case res.UnsupportedTupleFamily:
			// #5720 (codex-182 C-TOOLS): an IPv4 source with an IPv6 destination
			// is an impossible tuple (NAT46 is unimplemented); the forwarding
			// path never produces it and the runtime matcher fails closed.
			// Surface the dedicated verdict instead of a fabricated "Default deny
			// (no matching policy)", which would send an operator to add a permit
			// that can never take effect. Mirrors the REST / gRPC MatchPolicies
			// DisplayAction() render.
			fmt.Fprintf(buf, "%s\n", res.DisplayAction())
		case res.V4MappedCompatIngressDrop:
			// #16803: a v4-mapped/compatible IPv6 tuple is dropped at
			// ingress before policy (#10686); surface the dedicated
			// verdict instead of a fabricated default line.
			fmt.Fprintf(buf, "%s\n", res.DisplayAction())
		default:
			// No zone-pair or global policy matched: report the configured
			// default-policy, NOT a hard-coded "deny" (#3103). When the
			// default-policy is deny this still reads "Default deny (...)",
			// preserving the pre-#3103 wording for that case.
			fmt.Fprintf(buf, "Default %s (no matching policy for %s -> %s)\n",
				policymatch.ActionString(res.Action), fromZone, toZone)
		}
		// #14362 (#4373 parity): a multicast/broadcast/unspecified/loopback
		// destination is dropped at route lookup before policy runs — print
		// the advisory after the verdict, as the local surfaces do, so it is
		// not read as real forwarding. Host-bound results carry no route
		// advisory, so this is a no-op there.
		if note := res.RouteDropNote(); note != "" {
			fmt.Fprintf(buf, "  %s\n", note)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showFirewallFilter(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	filterTopic := strings.TrimPrefix(req.Topic, "firewall-filter:")
	filterName := filterTopic
	requestedFamily := ""
	if idx := strings.LastIndex(filterTopic, ":"); idx > 0 {
		filterName = filterTopic[:idx]
		requestedFamily = filterTopic[idx+1:]
	}
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		var filter *config.FirewallFilter
		var family string
		switch requestedFamily {
		case "":
			if f, ok := cfg.Firewall.FiltersInet[filterName]; ok {
				filter = f
				family = "inet"
			} else if f, ok := cfg.Firewall.FiltersInet6[filterName]; ok {
				filter = f
				family = "inet6"
			}
		case "inet":
			filter = cfg.Firewall.FiltersInet[filterName]
			family = "inet"
		case "inet6":
			filter = cfg.Firewall.FiltersInet6[filterName]
			family = "inet6"
		default:
			fmt.Fprintf(buf, "invalid family: %s\n", requestedFamily)
			return &pb.ShowTextResponse{Output: buf.String()}, nil
		}
		if filter == nil {
			if requestedFamily != "" {
				fmt.Fprintf(buf, "Filter not found: %s (family %s)\n", filterName, requestedFamily)
			} else {
				fmt.Fprintf(buf, "Filter not found: %s\n", filterName)
			}
		} else {
			s.writeFirewallStaleCounterWarning(buf)
			var userspaceStatus *dpuserspace.ProcessStatus
			if status, err := s.userspaceDataplaneStatus(); err == nil {
				userspaceStatus = &status
			}
			userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndexForConfig(userspaceStatus, cfg)
			policerStatuses := dpuserspace.BuildThreeColorPolicerStatusIndexForConfig(userspaceStatus, cfg)
			var filterIDs map[string]uint32
			if s.dp != nil && s.dp.IsLoaded() {
				if cr := s.applyResult(); cr != nil {
					filterIDs = cr.FilterIDs
				}
			}
			// #3408: surface a filter counter read failure as a warning AFTER
			// all terms rather than printing clean-zero / omitted hit counts.
			var readErr error
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+filterName]; ok {
					if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					} else if readErr == nil {
						readErr = err
					}
				}
			}
			cloneFold16464 := dpuserspace.BuildCloneCounterFold16464(cfg)
			cloneRuleStart16464 := make(map[string]uint32)
			cloneHas16464 := make(map[string]bool)
			if filterIDs != nil {
				for cloneName, source := range cloneFold16464[family] {
					if source != filterName {
						continue
					}
					if fid, ok := filterIDs[family+":"+cloneName]; ok {
						if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
							cloneRuleStart16464[cloneName] = fcfg.RuleStart
							cloneHas16464[cloneName] = true
						} else if readErr == nil {
							readErr = err
						}
					}
				}
			}
			fmt.Fprintf(buf, "Filter: %s (family %s)\n", filterName, family)
			ruleOffset := ruleStart
			// #16460: per-instance ordinal among non-nil instances.
			termOrdinal := uint32(0)
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				firewallshow.WriteTerm(buf, term, true)
				numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
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
								if ctrs, err := s.dp.ReadFilterCounters(cloneOffset + i); err == nil {
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
					Family: family, FilterName: filterName, TermOrdinal: termOrdinal,
				}]
				termOrdinal++
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				// #16454 + #16464: uncounted terms render no numeric Hit
				// count; clone map slots only gate a counted term.
				if term.Count != "" && (hasCounters || len(cloneHas16464) > 0 || userspaceOk) {
					fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
				if term.Policer != "" {
					key := dpuserspace.ThreeColorPolicerStatusKey{
						Family: family, FilterName: filterName, TermName: term.Name, Policer: term.Policer,
					}
					if ps, ok := policerStatuses[key]; ok {
						writeThreeColorPolicerStatus(buf, ps)
					}
				}
			}
			// #18728: the synthetic implicit-discard term.
			implicit, implicitOk := dpuserspace.ImplicitDiscardCounterForFilter(userspaceCounters, family, filterName, filter)
			firewallshow.WriteImplicitDiscard(buf, filter, firewallshow.ImplicitDiscardCounter{
				Packets: implicit.Packets, Bytes: implicit.Bytes, Have: implicitOk,
			}, true)
			// #16457: kernel lo0 chain counts beside the helper counts.
			lo0Counts, lo0Err := firewallshow.Lo0CountersForFilter(cfg, family, filterName, readLo0CountersGRPC)
			firewallshow.WriteLo0KernelCounters(buf, filter, lo0Counts)
			firewallshow.WriteLo0ImplicitDiscardCounter(buf, filter, family, lo0Counts)
			buf.WriteString("\n")
			if readErr != nil {
				fmt.Fprintf(buf, "warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
			}
			if lo0Err != nil {
				fmt.Fprintf(buf, "warning: kernel lo0 counter read failed (lo0 kernel counts may be incomplete): %v\n", lo0Err)
			}
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// showEffectiveFirewallFilters renders every compiled firewall-filter snapshot
// (optionally filtered to one family) for `show firewall effective [family
// <f>]` — the #4967 remote-CLI parity handler. It reuses the shared SSOT
// renderer dpuserspace.RenderFirewallFilterSnapshot so its output matches the
// local CLI byte-for-byte. Topic encoding:
//
//	firewall-effective            -> all families
//	firewall-effective:<family>   -> one family (inet|inet6)
func (s *Server) showEffectiveFirewallFilters(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	family := strings.TrimPrefix(req.Topic, "firewall-effective")
	family = strings.TrimPrefix(family, ":")
	s.writeFirewallNotEnforcingWarning(buf)
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}
	if family != "" && family != "inet" && family != "inet6" {
		fmt.Fprintf(buf, "invalid family: %s\n", family)
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}
	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	rendered := 0
	for i := range snaps {
		if family != "" && snaps[i].Family != family {
			continue
		}
		buf.WriteString(dpuserspace.RenderFirewallFilterSnapshot(&snaps[i]))
		rendered++
	}
	if rendered == 0 {
		if family != "" {
			fmt.Fprintf(buf, "No firewall filters configured (family %s)\n", family)
		} else {
			buf.WriteString("No firewall filters configured\n")
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// showEffectiveFirewallFilter renders one named compiled firewall-filter
// snapshot for `show firewall filter <name> effective [family <f>]` (#4967).
// Topic encoding (mirrors the firewall-filter: name:family scheme):
//
//	firewall-effective-filter:<name>            -> auto family (inet then inet6)
//	firewall-effective-filter:<name>:<family>
func (s *Server) showEffectiveFirewallFilter(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	rest := strings.TrimPrefix(req.Topic, "firewall-effective-filter:")
	name := rest
	family := ""
	if idx := strings.LastIndex(rest, ":"); idx > 0 {
		name = rest[:idx]
		family = rest[idx+1:]
	}
	s.writeFirewallNotEnforcingWarning(buf)
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}
	if family != "" && family != "inet" && family != "inet6" {
		fmt.Fprintf(buf, "invalid family: %s\n", family)
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}
	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	found := false
	for i := range snaps {
		if snaps[i].Name != name {
			continue
		}
		if family != "" && snaps[i].Family != family {
			continue
		}
		buf.WriteString(dpuserspace.RenderFirewallFilterSnapshot(&snaps[i]))
		found = true
	}
	if !found {
		if family != "" {
			fmt.Fprintf(buf, "Filter not found: %s (family %s)\n", name, family)
		} else {
			fmt.Fprintf(buf, "Filter not found: %s\n", name)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}
