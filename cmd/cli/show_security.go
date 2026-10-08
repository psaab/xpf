package main

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/zonecounters"
)

// isPolicyFilterKeyword reports whether tok is a leading `show security
// policies` subcommand keyword (brief/detail/hit-count/global) rather than a
// zone filter. These carry no value and are not from-zone/to-zone selectors, so
// the selector validator permits them while still rejecting a genuinely
// unrecognized token.
func isPolicyFilterKeyword(tok string) bool {
	switch tok {
	case "brief", "detail", "hit-count", "global":
		return true
	}
	return false
}

// validatePolicyZoneSelectors rejects BOTH a from-zone/to-zone selector missing
// its zone value (e.g. "... from-zone trust to-zone") AND an unrecognized filter
// token (e.g. a typo'd `from-zonee`, or a stray word). The remote `show security
// policies` wrappers below build the forwarded filter by copying ONLY
// from-zone/to-zone pairs and silently DROP everything else, so a mistyped
// selector key (`from-zonee trust`) left that filter dimension empty and WIDENED
// the view to every zone — an operator could read a narrow policy set as the
// whole table (#4908 / #5557). Rejecting the unknown key here makes that failure
// reach the operator surface, mirroring the daemon-side gRPC parseZoneFilter's
// default-error rule (pkg/grpcapi/server_show_policies_text.go), which the CLI
// otherwise never exercised because it stripped the bad token before forwarding.
// A leading subcommand keyword is permitted; the token following from-zone/
// to-zone is consumed as its value unconditionally.
func validatePolicyZoneSelectors(args []string) error {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone", "to-zone":
			if i+1 >= len(args) || args[i+1] == "from-zone" || args[i+1] == "to-zone" {
				return fmt.Errorf("missing zone name after %q", args[i])
			}
			i++ // skip the consumed value
		default:
			if isPolicyFilterKeyword(args[i]) {
				continue
			}
			return fmt.Errorf("unrecognized filter token %q (expected from-zone/to-zone)", args[i])
		}
	}
	return nil
}

func (c *ctl) handleShowSecurity(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show security:", "show", "security")
		return nil
	}

	switch args[0] {
	case "zones":
		// #9065: this was `args[1] == "detail"`, so `show security zones trust
		// detail` matched neither arm and fell through to the unfiltered,
		// non-detail inventory — BOTH the zone name and the modifier silently
		// discarded. The local console has bound a zone selector here since it
		// was written (cli_show_security_dispatch.go `filterZone = args[1]`)
		// and pkg/cmdtree offers zone NAMES as the completion set at this node
		// (tree.go:407), so the tree offered a selector two of its three
		// consumers honoured. Position-independent split, from the tree.
		zsplit := cmdtree.SplitModifiers(
			cmdtree.OperationalTree["show"].Children["security"].Children["zones"].Children,
			args[1:])
		if len(zsplit.Ambiguous) > 0 {
			return fmt.Errorf("ambiguous keyword %q after `show security zones`",
				zsplit.Ambiguous[0])
		}
		if len(zsplit.Extra) > 0 {
			return fmt.Errorf("unexpected argument %q: `show security zones` takes at "+
				"most one zone name", zsplit.Extra[0])
		}
		switch {
		case zsplit.Has("detail"):
			return c.showTextFiltered("zones-detail", zsplit.Selector)
		}
		return c.showZones(zsplit.Selector)
	case "policies":
		// #4908 (C175-HC-126): reject a from-zone/to-zone selector missing its
		// zone value (e.g. "... from-zone trust to-zone"). The loose parse below
		// silently dropped the dangling predicate and returned a broader/
		// one-sided inventory.
		if err := validatePolicyZoneSelectors(args[1:]); err != nil {
			return err
		}
		if len(args) >= 2 && args[1] == "brief" {
			return c.showPoliciesBrief()
		}
		if len(args) >= 2 && args[1] == "detail" {
			var filterParts []string
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "from-zone" || args[i] == "to-zone" {
					filterParts = append(filterParts, args[i], args[i+1])
					i++
				}
			}
			return c.showTextFiltered("policies-detail", strings.Join(filterParts, " "))
		}
		if len(args) >= 2 && args[1] == "hit-count" {
			var filterParts []string
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "from-zone" || args[i] == "to-zone" {
					filterParts = append(filterParts, args[i], args[i+1])
					i++
				}
			}
			return c.showTextFiltered("policies-hit-count", strings.Join(filterParts, " "))
		}
		var fromZone, toZone string
		for i := 1; i+1 < len(args); i++ {
			switch args[i] {
			case "from-zone":
				i++
				fromZone = args[i]
			case "to-zone":
				i++
				toZone = args[i]
			}
		}
		// #8321 finding 10: honour `global` instead of silently widening.
		return c.showPoliciesFiltered(fromZone, toZone, len(args) >= 2 && args[1] == "global")
	case "screen":
		if len(args) >= 2 && args[1] == "ids-option" && len(args) >= 3 {
			if len(args) >= 4 && args[3] == "detail" {
				return c.showText("screen-ids-option-detail:" + args[2])
			}
			return c.showText("screen-ids-option:" + args[2])
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if len(args) >= 4 && args[2] == "zone" {
				return c.showText("screen-statistics:" + args[3])
			}
			return c.showCommand("show security screen statistics")
		}
		return c.showScreen()
	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		if len(args) >= 2 && args[1] == "traceoptions" {
			return c.showCommand("show security flow traceoptions")
		}
		if len(args) >= 2 && args[1] == "statistics" {
			return c.showCommand("show security flow statistics")
		}
		if len(args) == 1 {
			return c.showCommand("show security flow")
		}
		return fmt.Errorf("usage: show security flow {session|statistics|traceoptions}")
	case "nat":
		return c.handleShowNAT(args[1:])
	case "log":
		return c.showEvents(args[1:])
	case "statistics":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showStatistics(detail)
	case "ipsec":
		return c.showIPsec(args[1:])
	case "ike":
		return c.showIKE(args[1:])
	case "match-policies":
		return c.showMatchPolicies(args[1:])
	case "vrrp":
		return c.showVRRP()
	case "wireguard":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show security wireguard detail")
		}
		if len(args) >= 2 && args[1] == "public-key" {
			return c.showCommand("show security wireguard public-key")
		}
		return c.showCommand("show security wireguard")
	case "alarms":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show security alarms detail")
		}
		return c.showCommand("show security alarms")
	case "alg":
		return c.showCommand("show security alg")
	case "dynamic-address":
		return c.showCommand("show security dynamic-address")
	case "address-book":
		return c.showCommand("show security address-book")
	case "applications":
		return c.showCommand("show security applications")
	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

// zoneHostInboundView projects a gRPC ZoneInfo onto the shared host-inbound
// presenter (#3654). The structured response already carries the split
// system-services / protocols set and the per-interface overrides (#3328), so
// the remote CLI renders exactly what the local and gRPC-text surfaces do. The
// wire response cannot distinguish a no-stanza zone from an explicit empty
// stanza (both are deny-all with empty lists post-#3405), so ZoneConfigured is
// left false and the posture line reads "(no stanza)".
func zoneHostInboundView(z *pb.ZoneInfo) config.HostInboundView {
	v := config.HostInboundView{
		ZoneSystemServices: z.GetHostInboundSystemServices(),
		ZoneProtocols:      z.GetHostInboundProtocols(),
		// #3682: carry the lifeline-exempt interface list from the structured
		// response so the remote CLI renders the same "excluded from
		// host-inbound deny" line as the local and gRPC-text surfaces.
		LifelineInterfaces: z.GetLifelineInterfaces(),
	}
	// #6515: an interface that declares a host-inbound-traffic stanza REPLACES the
	// zone-level set, so the effective set for each of these rows is the row's own
	// tokens. Every element of InterfaceHostInbound is by construction a ref that
	// declares one (the server projects SortedInterfaceHostInboundRefs), which is
	// why `overridden` is unconditionally true here.
	for _, ih := range z.GetInterfaceHostInbound() {
		v.Interfaces = append(v.Interfaces, config.InterfaceHostInboundView{
			Interface:               ih.GetInterface(),
			SystemServices:          ih.GetSystemServices(),
			Protocols:               ih.GetProtocols(),
			EffectiveSystemServices: config.EffectiveHostInboundTokens(z.GetHostInboundSystemServices(), ih.GetSystemServices(), true),
			EffectiveProtocols:      config.EffectiveHostInboundTokens(z.GetHostInboundProtocols(), ih.GetProtocols(), true),
		})
	}
	return v
}

// showZones renders the zone inventory, optionally narrowed to one zone.
//
// #9065: the filter is applied CLIENT-SIDE because this view is assembled
// client-side from GetZones + GetPolicies — there is no selector to send. What
// matters is that a zone name the operator typed reaches SOMETHING; before
// this it reached nothing at all and the operator was shown every zone with no
// indication their selector had been dropped.
func (c *ctl) showZones(filter string) error {
	resp, err := c.client.GetZones(c.ctx(), &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// #3669: do NOT swallow the GetPolicies error. GetZones succeeded, so the
	// zone bodies are valid and worth printing, but if the policy inventory RPC
	// failed the per-zone "Policies:" references are silently omitted — which
	// reads identically to "these zones have no policies". On a firewall a
	// partial policy view must fail loud: an operator (or automation scraping
	// exit status) must be able to tell a control-plane degradation apart from
	// genuinely policy-free zones. We render the zones, then surface the error so
	// the command exits non-zero (see main.go dispatch) and the degraded state
	// is visible rather than reported as success.
	polResp, polErr := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})

	matched := false
	for _, z := range resp.Zones {
		if filter != "" && z.Name != filter {
			continue
		}
		matched = true
		if z.Id > 0 {
			fmt.Printf("Zone: %s (id: %d)\n", z.Name, z.Id)
		} else {
			fmt.Printf("Zone: %s\n", z.Name)
		}
		if z.Description != "" {
			fmt.Printf("  Description: %s\n", z.Description)
		}
		fmt.Printf("  Interfaces: %s\n", strings.Join(z.Interfaces, ", "))
		if z.TcpRst {
			fmt.Println("  TCP RST: enabled")
		}
		if z.ScreenProfile != "" {
			fmt.Printf("  Screen: %s\n", z.ScreenProfile)
		}
		// #3654 (H09/M03/M06): consume the structured split system-services /
		// protocols and per-interface overrides from the gRPC response and
		// render them through the SAME shared presenter the local/gRPC-text
		// surfaces use, instead of collapsing everything into one legacy
		// "Host-inbound services" line that dropped the service-vs-protocol
		// split, the per-interface overrides, and the default-deny posture.
		for _, line := range zoneHostInboundView(z).Render(config.HostInboundLabels{
			Indent:         "  ",
			Sep:            ", ",
			ServicesLabel:  "Host-inbound system-services",
			ProtocolsLabel: "Host-inbound protocols",
		}) {
			fmt.Println(line)
		}
		renderZoneTraffic6895(z)

		// #3683 (M01): render all THREE policy tiers the runtime evaluates, in
		// order — zone-pair, applicable global, then the effective
		// default-policy catch-all — mirroring the local zone-detail summary
		// (pkg/cli/cli_show_security_zones.go) and gRPC text
		// (pkg/grpcapi/server_show_zones_text.go), both from #3658. The old
		// remote summary listed ONLY zone-pair groups whose group-level zones
		// matched the zone, so the "*"/"*" global group and the synthetic
		// default-policy row (#3363) were both hidden — an operator scraping the
		// ctl binary could miss a global or default-policy rule that governs the
		// zone's transit.
		if polResp != nil {
			fmt.Println("  Policy summary (evaluation order: zone-pair, global, default-policy):")
			zonePairPolicies := 0
			globalPolicies := 0
			var defaultName, defaultAction string
			for _, pi := range polResp.Policies {
				switch {
				case pi.FromZone == "-" && pi.ToZone == "-":
					// #3363 synthetic default-policy row: from/to zone "-" with a
					// single rule named dataplane.DefaultPolicyName. Captured here
					// and printed last so it always closes the summary (M05),
					// independent of its position in the response.
					if len(pi.Rules) > 0 {
						defaultName = pi.Rules[0].Name
						defaultAction = pi.Rules[0].Action
					}
				case pi.FromZone == "*" && pi.ToZone == "*":
					// #3357 global group: filter PER-RULE by the rule's scope
					// (#3148 MatchFromZone/MatchToZone). A scoped global narrows
					// the all-zones group to a zone pair; an unscoped or
					// explicit-"any" scope is the all-zones wildcard
					// (config.IsWildcardZone), so the global is listed whenever
					// the zone can appear on either side of a pair it matches
					// (config.GlobalPolicyAppliesToZone — the same predicate the
					// local/gRPC-text tier renderers use).
					for _, rule := range pi.Rules {
						if !config.GlobalPolicyAppliesToZone(config.PolicyMatch{
							FromZones: effectiveMatchFromZones(rule),
							ToZones:   effectiveMatchToZones(rule),
						}, z.Name) {
							continue
						}
						fmt.Printf("    [global] %s -> %s: %s (%s)\n",
							config.ZoneScopeSetLabel(effectiveMatchFromZones(rule)),
							config.ZoneScopeSetLabel(effectiveMatchToZones(rule)),
							rule.Name, rule.Action)
						globalPolicies++
					}
				case pi.FromZone == z.Name || pi.ToZone == z.Name:
					for _, rule := range pi.Rules {
						fmt.Printf("    [zone-pair] %s -> %s: %s (%s)\n",
							pi.FromZone, pi.ToZone, rule.Name, rule.Action)
						zonePairPolicies++
					}
				}
			}
			if zonePairPolicies == 0 && globalPolicies == 0 {
				fmt.Println("    (no zone-pair or global policies affecting this zone)")
			}
			// M05: always surface the effective default-policy catch-all when the
			// inventory carries it, so unmatched-transit disposition is never
			// hidden behind an absent "(no policies)" line.
			if defaultName != "" {
				fmt.Printf("    [default] %s: %s\n", defaultName, defaultAction)
			}
		}

		fmt.Println()
	}
	// A selector that matched nothing must FAIL, not print an empty inventory.
	// Silence is what the pre-#9065 dropped selector already looked like, and
	// an operator cannot tell "no such zone" from "this zone is empty" — the
	// same reasoning as the #3669 policy-error branch below.
	if filter != "" && !matched {
		return fmt.Errorf("zone %q not found", filter)
	}
	if polErr != nil {
		return fmt.Errorf("policy inventory unavailable (zone policy references omitted): %w", polErr)
	}
	return nil
}

// showPoliciesFiltered renders the policy inventory, optionally narrowed.
//
// #8321 finding 10: `globalOnly` exists because `show security policies global`
// was VALIDATED as a keyword by isPolicyFilterKeyword and then had no branch —
// so the remote CLI accepted it, dropped it, and returned the ENTIRE policy
// database. An operator asking which global policies exist got every zone-pair
// policy too, with nothing saying the filter had been ignored.
//
// The local CLI has handled it since #3357 (`globalOnly := args[1] == "global"`,
// cli_show_security_dispatch.go), so this was a local/remote divergence rather
// than a missing feature — the discriminator was already here, in the
// `FromZone == "*" && ToZone == "*"` branch below.
func (c *ctl) showPoliciesFiltered(fromZone, toZone string, globalOnly bool) error {
	resp, err := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	renderRule := func(rule *pb.PolicyRule) {
		fmt.Printf("  Rule: %s\n", rule.Name)
		if rule.Description != "" {
			fmt.Printf("    Description: %s\n", rule.Description)
		}
		// #3672 (M01): annotate "(except)" when the match sense is inverted
		// (source-address-excluded / destination-address-excluded). Without it
		// an exclusive ("all EXCEPT these") match reads identical to an
		// inclusive one, inverting the rule's reachability meaning. Mirrors the
		// local CLI detail "(except)" annotation and the gRPC/REST inventory
		// booleans.
		src := fmt.Sprintf("%v", rule.SrcAddresses)
		if rule.SourceAddressExcluded {
			src += " (except)"
		}
		dst := fmt.Sprintf("%v", rule.DstAddresses)
		if rule.DestinationAddressExcluded {
			dst += " (except)"
		}
		fmt.Printf("    Match: src=%s dst=%s app=%v\n", src, dst, rule.Applications)
		fmt.Printf("    Action: %s\n", rule.Action)
		// #3672 (M02): surface per-rule session logging. The wire carries the
		// independent init/close modes (#3336); the collapsed `log` bool alone
		// made a logged permit indistinguishable from an unlogged one and hid
		// init-only vs close-only. Mirrors the local CLI "Session log:
		// at-create, at-close".
		if rule.Log || rule.LogSessionInit || rule.LogSessionClose {
			var modes []string
			if rule.LogSessionInit {
				modes = append(modes, "at-create")
			}
			if rule.LogSessionClose {
				modes = append(modes, "at-close")
			}
			if len(modes) > 0 {
				fmt.Printf("    Log: %s\n", strings.Join(modes, ", "))
			} else {
				fmt.Printf("    Log: enabled\n")
			}
		}
		// #3672 (M03): surface scheduler binding and runtime-inactive state
		// (#3624). A scheduled rule outside its active window prints
		// "Action: permit" while the dataplane skips/denies it (scheduler
		// fail-closed) — the inactive annotation makes that visible.
		switch {
		case rule.SchedulerName != "" && rule.Inactive:
			fmt.Printf("    Scheduler: %s (inactive)\n", rule.SchedulerName)
		case rule.SchedulerName != "":
			fmt.Printf("    Scheduler: %s\n", rule.SchedulerName)
		case rule.Inactive:
			fmt.Printf("    Inactive: true\n")
		}
		// #3672 (M04): a "then count" rule prints its hit count even at zero, so
		// counted-but-idle is distinguishable from not-counted. A rule with hits
		// prints them regardless (unchanged); an uncounted idle rule prints
		// nothing (unchanged).
		switch {
		case rule.HitCountersUnavailable:
			// #7016: the rule is counter-eligible but no runtime counter source
			// answered for it (dataplane unloaded, or the helper has published
			// nothing for this rule id yet -- warm-up / config skew). Say so
			// rather than printing an authoritative-looking "0 packets, 0
			// bytes" an operator would read as "this rule matched no traffic".
			fmt.Printf("    Hit count: not available (no counter published for this rule)\n")
		case rule.Count || rule.HitPackets > 0 || rule.HitBytes > 0:
			fmt.Printf("    Hit count: %d packets, %d bytes\n", rule.HitPackets, rule.HitBytes)
		}
	}
	renderGlobalGroup := func(pi *pb.PolicyInfo) {
		for _, rule := range pi.Rules {
			if !policymatch.GlobalPolicyAppliesToZonePair(effectiveMatchFromZones(rule), effectiveMatchToZones(rule), fromZone, toZone) {
				continue
			}
			// #3683 (M02) / #4626: render the effective zone SET through
			// config.ZoneScopeSetLabel (empty -> "any") so an unscoped global
			// prints "From zone: any, To zone: any".
			fmt.Printf("From zone: %s, To zone: %s\n",
				config.ZoneScopeSetLabel(effectiveMatchFromZones(rule)), config.ZoneScopeSetLabel(effectiveMatchToZones(rule)))
			renderRule(rule)
			fmt.Println()
		}
	}
	renderZonePairGroup := func(pi *pb.PolicyInfo) {
		fmt.Printf("From zone: %s, To zone: %s\n", pi.FromZone, pi.ToZone)
		for _, rule := range pi.Rules {
			renderRule(rule)
		}
		fmt.Println()
	}
	filtered := fromZone != "" || toZone != ""
	if filtered && !globalOnly {
		// Zone-pair rule inventory follows runtime precedence, not config-group
		// placement: exact, single-wildcard, then both-wildcard. Globals render
		// after this loop below.
		for tier := range 3 {
			for _, pi := range resp.Policies {
				if pi.FromZone == "*" && pi.ToZone == "*" {
					continue
				}
				if !policymatch.ZonePairPolicyAppliesToFilterPair(pi.FromZone, pi.ToZone, fromZone, toZone) ||
					policymatch.ZonePairPolicyFilterTier(pi.FromZone, pi.ToZone) != tier {
					continue
				}
				renderZonePairGroup(pi)
			}
		}
	}
	for _, pi := range resp.Policies {
		// #3357: the global group is exposed by GetPolicies with the group-level
		// zones "*"/"*"; its per-rule scope is carried in MatchFromZone/ToZone.
		// Process it after filtered zone-pair groups so it remains the final tier.
		if pi.FromZone == "*" && pi.ToZone == "*" {
			renderGlobalGroup(pi)
			continue
		}
		// #8321 finding 10: `global` excludes zone-pair groups. A filtered
		// request already rendered those groups in runtime tier order above.
		if globalOnly || filtered {
			continue
		}
		renderZonePairGroup(pi)
	}
	return nil
}

func (c *ctl) showScreen() error {
	return c.showCommand("show security screen")
}

func (c *ctl) showMatchPolicies(args []string) error {
	// #3696: parse the selector grammar through the single strict SSOT parser
	// (policymatch.ParseSelectorArgs) shared by the local CLI, the remote CLI,
	// and the gRPC test-policy bridge. A value-taking selector present WITHOUT a
	// value, an UNKNOWN selector token, an explicit-empty typed value, and a
	// malformed IP / port / protocol / icmp value are all HARD ERRORS — the
	// remote CLI no longer forwards a silently-widened query to the typed
	// MatchPolicies RPC. Per-value validation (#3354 / #3108 / #3284 / #1711)
	// now lives in the parser, so this surface fails closed before any RPC.
	sel, err := policymatch.ParseSelectorArgs(args)
	if err != nil {
		return err
	}

	if sel.FromZone == "" || sel.ToZone == "" {
		// #3628: shared SSOT selector list (policymatch) — advertise every
		// selector the request parser accepts, including icmp-type/icmp-code and
		// protocol by name or number.
		fmt.Println(policymatch.MatchPoliciesUsage)
		return nil
	}

	req := &pb.MatchPoliciesRequest{
		FromZone:        sel.FromZone,
		ToZone:          sel.ToZone,
		SourceIp:        sel.SrcIP,
		DestinationIp:   sel.DstIP,
		Protocol:        sel.Protocol,
		SourcePort:      int32(sel.SrcPort),
		DestinationPort: int32(sel.DstPort),
		// #5572: forward the non-first-fragment (l4_present == false)
		// discriminator so the typed MatchPolicies RPC reproduces the #4569
		// fragment-associated deny; false is a normal L4 packet.
		NonFirstFragment: sel.NonFirstFragment,
		// #5579: forward the ingress-interface selector so the daemon scopes the
		// host-inbound classifier to one interface's effective view (the server
		// validates zone membership + lifeline reject). "" = zone-scoped.
		IngressInterface: sel.IngressInterface,
	}
	if sel.ICMPType != nil {
		u := uint32(*sel.ICMPType)
		req.IcmpType = &u
	}
	if sel.ICMPCode != nil {
		u := uint32(*sel.ICMPCode)
		req.IcmpCode = &u
	}

	resp, err := c.client.MatchPolicies(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if resp.FeedPublicationDebt {
		fmt.Println(resp.FeedPublicationDebtNote)
		return nil
	}

	if resp.Matched {
		if resp.Global {
			fmt.Printf("Matching policy (global):\n")
		} else {
			fmt.Printf("Matching policy:\n")
		}
		fmt.Printf("  From zone: %s, To zone: %s\n", req.FromZone, req.ToZone)
		fmt.Printf("  Policy: %s\n", resp.PolicyName)
		// #3331: identify WHICH scoped/global policy matched so a verdict maps
		// back to the runtime policy / session-table ID / audit record when the
		// same policy name repeats across zone pairs or global scope.
		fmt.Printf("    Policy ID: %d\n", resp.GetPolicyId())
		// #3668: also print the stable rule identity so a hit joins to the
		// inventory / logs / tests even after a policy reorder shifts Policy ID.
		if resp.GetRuleId() != "" {
			fmt.Printf("    Rule ID: %s\n", resp.GetRuleId())
		}
		if resp.Global {
			fmt.Printf("    Scope: global (match from-zone: %s, to-zone: %s)\n",
				matchScopeZone(resp.FromZone), matchScopeZone(resp.ToZone))
		} else {
			fmt.Printf("    Scope: zone-pair (from-zone: %s, to-zone: %s)\n", resp.FromZone, resp.ToZone)
		}
		// #3668: annotate "(except)" for a source/destination-address-excluded
		// rule so a positive verdict conveys the negation instead of reading as
		// if the printed address list caused the match. Same SSOT suffix helper
		// the local CLI uses, so the two surfaces cannot drift.
		fmt.Printf("    Source addresses%s: %v\n", policymatch.ExceptSuffix(resp.GetSourceAddressExcluded()), resp.SrcAddresses)
		fmt.Printf("    Destination addresses%s: %v\n", policymatch.ExceptSuffix(resp.GetDestinationAddressExcluded()), resp.DstAddresses)
		fmt.Printf("    Applications: %v\n", resp.Applications)
		fmt.Printf("    Action: %s\n", resp.Action)
		// #5572: a non-first fragment whose permit was overridden to this
		// overlapping port-bearing deny — explain the over-drop, mirroring the
		// local CLI + REST surfaces.
		if note := resp.GetFragmentDenyNote(); note != "" {
			fmt.Printf("    %s\n", note)
		}
	} else if resp.HostInboundUnmatched {
		// #3285: host-bound traffic — no transit global/default fallback.
		// #3655: render the SSOT policymatch.HostInboundShowLine (as the local
		// CLI / REST / gRPC surfaces already do post-#3647) instead of the old
		// hard-coded "local delivery proceeds" wording. That literal read as an
		// unconditional admit even though a no-stanza zone now default-DENIES
		// host-inbound (#3405); the shared const states delivery is subject to
		// host-inbound-traffic service admission so remote clients see the same
		// accurate verdict as every other transport.
		fmt.Printf("No matching to-zone junos-host policy for %s -> junos-host\n", req.FromZone)
		fmt.Printf("  %s\n", policymatch.HostInboundShowLine)
	} else {
		// #3283: render the SERVER-provided default verdict (resp.Action carries
		// "<action> (default)" from the configured default-policy), NOT a
		// hard-coded "default deny". Under `default-policy permit-all` the old
		// literal reported the OPPOSITE of the dataplane — the same simulator
		// drift class #3283 fixes — and diverged from the local CLI / gRPC text
		// surfaces, which already report resp.Action.
		fmt.Printf("No matching policy found for %s -> %s (%s)\n", req.FromZone, req.ToZone, resp.Action)
	}
	// #4373 (E4/H2/H7): the server flags a multicast/broadcast/unspecified/
	// loopback destination that the forwarding path drops at route lookup before
	// policy runs. Print the SSOT advisory it carries so a remote-CLI verdict is
	// not read as real forwarding — parity with the local CLI + REST surfaces
	// over the same policymatch.RouteDropNote wording.
	if note := resp.GetRouteDropNote(); note != "" {
		fmt.Printf("  %s\n", note)
	}
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

// effectiveMatchFromZones / effectiveMatchToZones resolve a scoped-global zone
// SET (#4626 M03) from a gRPC PolicyRule, preferring the plural
// match_*_zones field and falling back to the singular match_*_zone for an
// older daemon that only emits the singular value (additive-wire safety).
func effectiveMatchFromZones(rule *pb.PolicyRule) []string {
	if z := rule.GetMatchFromZones(); len(z) > 0 {
		return z
	}
	if s := rule.GetMatchFromZone(); s != "" {
		return []string{s}
	}
	return nil
}

func effectiveMatchToZones(rule *pb.PolicyRule) []string {
	if z := rule.GetMatchToZones(); len(z) > 0 {
		return z
	}
	if s := rule.GetMatchToZone(); s != "" {
		return []string{s}
	}
	return nil
}

func (c *ctl) showVRRP() error {
	resp, err := c.client.GetVRRPStatus(c.ctx(), &pb.GetVRRPStatusRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if len(resp.Instances) == 0 {
		fmt.Println("No VRRP groups configured")
		return nil
	}

	if resp.ServiceStatus != "" {
		fmt.Println(resp.ServiceStatus)
	}

	fmt.Printf("%-14s %-6s %-8s %-10s %-16s %-8s\n",
		"Interface", "Group", "State", "Priority", "VIP", "Preempt")
	for _, inst := range resp.Instances {
		preempt := "no"
		if inst.Preempt {
			preempt = "yes"
		}
		vip := strings.Join(inst.VirtualAddresses, ",")
		fmt.Printf("%-14s %-6d %-8s %-10d %-16s %-8s\n",
			inst.Interface, inst.GroupId, inst.State, inst.Priority, vip, preempt)
	}
	return nil
}

func (c *ctl) showEvents(args []string) error {
	// Forward the FULL argument string — count AND any zone/protocol/action
	// selector — to the daemon, which parses it through the shared
	// logging.ParseEventFilterArgs (#3547). Before #3547 this only picked out
	// a numeric count and dropped every other token, so `show security log
	// zone <name>` (including the unknown/none/0 zone-0 selector #3338) was a
	// silent no-op on the remote `cli`: the daemon saw an empty filter and
	// dumped every event, never isolating the requested zone the way the
	// local CLI does.
	return c.showTextFiltered("security-log", strings.Join(args, " "))
}

func (c *ctl) showStatistics(detail bool) error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println("Global statistics:")
	fmt.Printf("  %-25s %d\n", "RX packets:", resp.RxPackets)
	fmt.Printf("  %-25s %d\n", "TX packets:", resp.TxPackets)
	fmt.Printf("  %-25s %d\n", "Drops:", resp.Drops)
	fmt.Printf("  %-25s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-25s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Printf("  %-25s %d\n", "Screen drops:", resp.ScreenDrops)
	fmt.Printf("  %-25s %d\n", "Policy denies:", resp.PolicyDenies)
	fmt.Printf("  %-25s %d\n", "NAT alloc failures:", resp.NatAllocFailures)
	fmt.Printf("  %-25s %d\n", "Host-inbound denies:", resp.HostInboundDenies)
	fmt.Printf("  %-25s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-25s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Printf("  %-25s %d\n", "NAT64 translations:", resp.Nat64Translations)

	if !detail {
		return nil
	}

	if resp.ScreenDrops > 0 {
		fmt.Printf("\nScreen drop details:\n")
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("  %-25s %d\n", name+":", count)
		}
	}

	// #5328 (A10-b1-F4): propagate the supplemental buffers RPC error instead
	// of swallowing it in the success predicate. Reading the error only inside
	// `if err == nil && ...` and returning nil meant a degraded buffers read
	// silently omitted the buffer section and still exited 0 — the base
	// GetGlobalStats error above is surfaced, so this must be too.
	text, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{Topic: "buffers"})
	if err != nil {
		return err
	}
	if text.Output != "" {
		fmt.Printf("\n%s", text.Output)
	}
	return nil
}

func (c *ctl) showIKE(args []string) error {
	if len(args) > 0 && args[0] == "security-associations" {
		resp, err := c.client.GetIPsecSA(c.ctx(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if resp.Output == "" {
			fmt.Println("No IKE security associations")
		} else {
			fmt.Print(resp.Output)
		}
		return nil
	}
	return c.showCommand("show security ike")
}

func (c *ctl) showIPsec(args []string) error {
	if len(args) > 0 && args[0] == "security-associations" {
		resp, err := c.client.GetIPsecSA(c.ctx(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}
	if len(args) > 0 && args[0] == "statistics" {
		return c.showCommand("show security ipsec statistics")
	}
	printRemoteTreeHelp("show security ipsec:", "show", "security", "ipsec")
	return nil
}

func (c *ctl) showPoliciesBrief() error {
	resp, err := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
		"From", "To", "Name", "Action", "Hits")
	for _, pi := range resp.Policies {
		for _, rule := range pi.Rules {
			hits := "-"
			switch {
			case rule.HitCountersUnavailable:
				hits = "n/a" // #7016: no counter published for this rule
			case rule.HitPackets > 0:
				hits = fmt.Sprintf("%d", rule.HitPackets)
			}
			// #3357: a scoped global (#3148) is exposed under the global group
			// (pi.FromZone/ToZone == "*"), but its real zone scope is carried
			// per-rule in MatchFromZone/MatchToZone. Render the effective scope
			// so the brief view does not regress a scoped global to "*"/"*",
			// matching the local-CLI #3286 display. Zone-pair rules and the
			// default-policy row leave the match-scope empty and fall back to the
			// group zones (real zones / "-"), so they are unchanged.
			from, to := pi.FromZone, pi.ToZone
			// #4626: prefer the full scoped-global zone SET; empty falls back
			// to the group zones (zone-pair / default rows leave the scope empty).
			if zs := effectiveMatchFromZones(rule); len(zs) > 0 {
				from = config.ZoneScopeSetLabel(zs)
			}
			if zs := effectiveMatchToZones(rule); len(zs) > 0 {
				to = config.ZoneScopeSetLabel(zs)
			}
			fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
				from, to, rule.Name, rule.Action, hits)
		}
	}
	return nil
}

// renderZoneTraffic6895 prints a zone's traffic section from the structured
// GetZones reply (#6895).
//
// WHAT WAS WRONG. The old body was `if z.IngressPackets > 0 || z.EgressPackets
// > 0`, so the section was omitted whenever both counts were zero — and the
// wire carried no way to tell a real zero from the absence of a reading. A zone
// whose counters are unavailable therefore rendered identically to an idle one:
// SILENCE, which an operator reads as "this zone has no traffic". That is a
// wrong answer, not a missing one, and it is the surface an operator is most
// likely holding. With 64+ zones, slot exhaustion means the overflowed zones are
// exactly the ones that render as idle.
//
// WHAT THIS DOES AND DOES NOT FIX. It converts that wrong answer into an honest
// one. It does NOT distinguish an idle zone from an unavailable one, and no
// surface does: the helper's status snapshot is sparse and omits all-zero rows,
// so a pre-#3651 helper, a zone past hot-path slot capacity and a merely idle
// zone are indistinguishable at the source. The ambiguity is INHERITED, and the
// shared line says so in as many words rather than naming a cause it cannot
// know. The one case that IS knowable and actionable — the helper reporting
// slot overflow — gets its own line via the same shared helper the local CLI
// and the gRPC text renderer use.
//
// UNKNOWN RENDERS EXACTLY AS BEFORE #6895. An old server omits the field, which
// decodes to UNKNOWN, and this falls back to the historical
// omit-when-both-zero. That is the whole reason the wire field is a three-state
// enum instead of a bool: a bool has no absence to observe, so either polarity
// would make a version-skewed pair produce a NEW wrong answer — every zone
// reported unavailable, or an unpopulated zone reported as a real 0.
func renderZoneTraffic6895(z *pb.ZoneInfo) {
	if z == nil {
		return
	}
	switch z.PerZoneCounterAvailability {
	case pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE:
		// The server told us it had no reading. Say so, with the same wording
		// every other surface uses. The overflow specialisation is decided
		// server-side in the text renderer; here the generic line is correct,
		// because this reply carries no overflow bit.
		fmt.Println(zonecounters.UnavailableLine(false))
	case pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE:
		// A real reading, INCLUDING a zero one — print it rather than omitting,
		// so "the server measured zero" is visibly different from "the server
		// had nothing to measure".
		fmt.Println("  Traffic statistics:")
		fmt.Printf("    Input:  %d packets, %d bytes\n", z.IngressPackets, z.IngressBytes)
		fmt.Printf("    Output: %d packets, %d bytes\n", z.EgressPackets, z.EgressBytes)
	default:
		// UNKNOWN: an old server. Historical behaviour, byte for byte.
		if z.IngressPackets > 0 || z.EgressPackets > 0 {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input:  %d packets, %d bytes\n", z.IngressPackets, z.IngressBytes)
			fmt.Printf("    Output: %d packets, %d bytes\n", z.EgressPackets, z.EgressBytes)
		}
	}
}
