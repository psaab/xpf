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
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

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
	policerStatuses := dpuserspace.BuildThreeColorPolicerStatusIndex(userspaceStatus)
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
					} else if readErr == nil {
						readErr = err
					}
				}
			}
			ruleOffset := ruleStart

			for _, term := range filter.Terms {
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
				for _, t := range term.ICMPTypes {
					fmt.Fprintf(buf, "    from icmp-type %d\n", t)
				}
				for _, c := range term.ICMPCodes {
					fmt.Fprintf(buf, "    from icmp-code %d\n", c)
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
				if term.Policer != "" {
					fmt.Fprintf(buf, "    then policer %s\n", term.Policer)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				fmt.Fprintf(buf, "    then %s\n", action)

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
				if term.Policer != "" {
					if ps, ok := policerStatuses[term.Policer]; ok {
						writeThreeColorPolicerStatus(buf, ps)
					}
				}
			}
			buf.WriteString("\n")
		}
	}
	printFilters("inet", cfg.Firewall.FiltersInet)
	printFilters("inet6", cfg.Firewall.FiltersInet6)
	if readErr != nil {
		fmt.Fprintf(buf, "warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
}

// --- #1700: residual ShowText branches ---

func (s *Server) showTestPolicy(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	params := strings.TrimPrefix(req.Topic, "test-policy:")
	var fromZone, toZone, srcIP, dstIP, proto, ingressIface string
	var srcPort, dstPort int
	var icmpType, icmpCode *uint8
	var nonFirstFrag bool
	var srcPortErr, portErr, protoErr, icmpTypeErr, icmpCodeErr, fragErr, parseErr error
	// #3696: fail CLOSED on malformed selector grammar, the server-boundary
	// sibling of the strict CLI parser (policymatch.ParseSelectorArgs). The old
	// `if len(parts) != 2 { continue }` silently DROPPED any comma segment
	// lacking a `key=value` — `...,port` left dstPort at the 0 wildcard and the
	// simulator evaluated ALL ports — and the switch had no default arm, so an
	// unknown key (`prot=tcp`) was ignored, leaving proto empty (any protocol).
	// An explicit-empty typed value (`port=`) was likewise treated as omitted
	// because ParsePort("") returns (0, nil), so the handler could not tell
	// "key absent" (legit wildcard) from "key present, empty value" (malformed).
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
				// silently coercing to the 0 "any port" wildcard.
				srcPort, srcPortErr = policymatch.ParsePort(parts[1])
			case "port":
				// #3116: a malformed/out-of-range port must NOT silently coerce to
				// the 0 "any port" wildcard (the shared matcher gates the port term
				// on dstPort > 0), which would yield a verdict for a packet that
				// cannot exist. Route through the shared validator and report the
				// error the way a bad src/dst is reported below.
				dstPort, portErr = policymatch.ParsePort(parts[1])
			case "proto":
				// #3108: a non-empty but unknown/out-of-range protocol token must
				// NOT silently coerce to the empty "any protocol" wildcard (the
				// shared matcher's matchApp short-circuits to match-any for an
				// unresolvable protocol), which would yield a verdict for traffic
				// that cannot exist. Validate via the shared helper and report the
				// error the way a bad port/src is reported below.
				proto = parts[1]
				protoErr = policymatch.ValidateProtocol(proto)
			case "ictype":
				// #3284: ICMP/ICMPv6 type so a type-constrained application term
				// (junos-icmp-ping = type 8) is honored. Empty is unspecified (the
				// term fails closed); a malformed/out-of-range value errors.
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
	// #5579: resolve the ingress-interface validation once (cfg==nil returns nil,
	// so this is safe before the cfg==nil case; the switch surfaces it only after
	// the cfg / grammar / zone checks below).
	ingressErr := dpuserspace.ResolveHostInboundIngressInterface(cfg, fromZone, ingressIface)
	switch {
	case cfg == nil:
		buf.WriteString("No active configuration\n")
	case parseErr != nil:
		// #3696: report malformed grammar (a segment lacking key=value, an
		// unknown key, or an explicit-empty typed value) before evaluating, so a
		// typo cannot silently widen the query. Checked before the from/to-zone
		// diagnostic so a malformed selector is not masked by a legit-looking
		// missing-zone message.
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
	case ingressErr != nil:
		// #5579: an unknown / zone-mismatched / lifeline / bare-physical
		// ingress-interface fails the query closed, so the host-inbound classifier
		// is only scoped to a real logical-unit interface of the queried zone
		// (parity with the REST/gRPC/local surfaces).
		fmt.Fprintf(buf, "%v\n", ingressErr)
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
		var overlay map[string][]string
		if s.feedOverlayFn != nil {
			overlay = s.feedOverlayFn()
		}
		var publicationDebt map[string]bool
		if s.feedsFn != nil {
			for name, info := range s.feedsFn() {
				if info.PublicationDebt {
					if publicationDebt == nil {
						publicationDebt = make(map[string]bool)
					}
					publicationDebt[name] = true
				}
			}
		}
		res := policymatch.Match(cfg, policymatch.Query{
			FromZone: fromZone,
			ToZone:   toZone,
			SrcIP:    net.ParseIP(srcIP),
			DstIP:    net.ParseIP(dstIP),
			// #6377: colon-strict text family from the RAW operator string so
			// the unsupported-tuple gate does not fold an IPv4-mapped IPv6
			// source to v4 (net.ParseIP has discarded the ':' above).
			SrcFamily: config.NATAddrFamily(srcIP),
			DstFamily: config.NATAddrFamily(dstIP),
			Protocol:  proto,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			ICMPType:  icmpType,
			ICMPCode:  icmpCode,
			// #5572: non-first-fragment (l4_present == false) reproduces the
			// #4569 fragment-associated deny; false is a normal L4 packet.
			NonFirstFragment: nonFirstFrag,
			// #5579: scope the host-inbound classifier to this ingress interface's
			// effective view (validated above). "" = zone-scoped, unchanged.
			IngressInterface:    ingressIface,
			FeedOverlay:         overlay,
			FeedPublicationDebt: publicationDebt,
			// #3104: skip scheduler-inactive policies like the runtime does, so
			// the `test policy` diagnostic falls through to the next active rule
			// / default-policy, agreeing with the dataplane.
			PolicyInactiveFn: s.policyInactiveFn(),
		})
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
		default:
			// No zone-pair or global policy matched: report the configured
			// default-policy, NOT a hard-coded "deny" (#3103). When the
			// default-policy is deny this still reads "Default deny (...)",
			// preserving the pre-#3103 wording for that case.
			fmt.Fprintf(buf, "Default %s (no matching policy for %s -> %s)\n",
				policymatch.ActionString(res.Action), fromZone, toZone)
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
			var userspaceStatus *dpuserspace.ProcessStatus
			if status, err := s.userspaceDataplaneStatus(); err == nil {
				userspaceStatus = &status
			}
			userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)
			policerStatuses := dpuserspace.BuildThreeColorPolicerStatusIndex(userspaceStatus)
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
			fmt.Fprintf(buf, "Filter: %s (family %s)\n", filterName, family)
			ruleOffset := ruleStart
			for _, term := range filter.Terms {
				fmt.Fprintf(buf, "\n  Term: %s\n", term.Name)
				for _, d := range term.DSCPs {
					fmt.Fprintf(buf, "    from dscp %s\n", d)
				}
				for _, p := range term.Protocols {
					fmt.Fprintf(buf, "    from protocol %s\n", p)
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
				for _, t := range term.ICMPTypes {
					fmt.Fprintf(buf, "    from icmp-type %d\n", t)
				}
				for _, c := range term.ICMPCodes {
					fmt.Fprintf(buf, "    from icmp-code %d\n", c)
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
				if term.Log {
					buf.WriteString("    then log\n")
				}
				if term.Count != "" {
					fmt.Fprintf(buf, "    then count %s\n", term.Count)
				}
				if term.Policer != "" {
					fmt.Fprintf(buf, "    then policer %s\n", term.Policer)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				fmt.Fprintf(buf, "    then %s\n", action)
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
				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: filterName, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				if hasCounters || userspaceOk {
					fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
				if term.Policer != "" {
					if ps, ok := policerStatuses[term.Policer]; ok {
						writeThreeColorPolicerStatus(buf, ps)
					}
				}
			}
			buf.WriteString("\n")
			if readErr != nil {
				fmt.Fprintf(buf, "warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
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
