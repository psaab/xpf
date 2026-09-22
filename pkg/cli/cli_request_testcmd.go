package cli

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/routing"
)

// handleTest dispatches test sub-commands (policy, routing, security-zone).
func (c *CLI) handleTest(args []string) error {
	if len(args) == 0 {
		fmt.Println("test: specify a test command")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["test"].Children))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(operationalTree["test"].Children))
	if err != nil {
		return err
	}

	switch resolved {
	case "policy":
		return c.testPolicy(args[1:])
	case "routing":
		return c.testRouting(args[1:])
	case "security-zone":
		return c.testSecurityZone(args[1:])
	default:
		return fmt.Errorf("unknown test command: %s", resolved)
	}
}

// testPolicy performs a 5-tuple policy lookup similar to Junos "test policy".
func (c *CLI) testPolicy(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// #3696: parse through the single strict SSOT selector parser shared by all
	// four CLI surfaces + the gRPC test-policy bridge. A value-taking selector
	// with no value, an unknown selector token, an explicit-empty typed value,
	// and a malformed IP / port / protocol / icmp value are HARD ERRORS instead
	// of silently degrading to the wildcard — the simulator answers the query
	// the operator typed, not a broader one. Per-value validation (#3116 /
	// #3108 / #3284 / #1711) now lives in the parser.
	sel, err := policymatch.ParseSelectorArgs(args)
	if err != nil {
		return err
	}
	fromZone, toZone, srcIP, dstIP, proto := sel.FromZone, sel.ToZone, sel.SrcIP, sel.DstIP, sel.Protocol
	srcPort, dstPort := sel.SrcPort, sel.DstPort
	icmpType, icmpCode := sel.ICMPType, sel.ICMPCode
	nonFirstFrag := sel.NonFirstFragment

	if fromZone == "" || toZone == "" {
		// #3628: shared SSOT selector list (policymatch) so the advertised
		// selectors match what the parser accepts, including icmp-type/icmp-code
		// and protocol by name or number.
		fmt.Println(policymatch.TestPolicyUsage)
		return nil
	}

	parsedSrc := net.ParseIP(srcIP)
	parsedDst := net.ParseIP(dstIP)

	// #5579: validate the optional ingress-interface selector against the live
	// config (zone membership + lifeline reject) so the host-inbound classifier is
	// scoped only to a real interface of the queried zone, failing closed on an
	// unknown / zone-mismatched / lifeline ref exactly like the other surfaces.
	if err := dpuserspace.ResolveHostInboundIngressInterface(cfg, fromZone, sel.IngressInterface); err != nil {
		return err
	}

	// #3042: delegate to the single shared simulator (exact zone-pair ->
	// wildcard-zone tiers (#3090) -> scoped global (#3148) -> default-policy).
	// The pre-#3042 loop hard-coded "Default deny" (ignoring default-policy
	// permit-all) and used a narrow address/app matcher that missed predefined
	// apps, nested application-sets, literal CIDRs, any-ipv4/any-ipv6, and
	// source/destination exclusion.
	// #3105: pass the live dynamic-address feed-prefix overlay so a feed-backed
	// address-name resolves to its live CIDRs on-box, matching the REST/gRPC
	// simulators and the AF_XDP helper. Nil (CLI outside the daemon) keeps the
	// pre-#3105 static-only behavior.
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone: fromZone,
		ToZone:   toZone,
		SrcIP:    parsedSrc,
		DstIP:    parsedDst,
		// #6377: thread the colon-strict text family from the RAW operator
		// string so the unsupported-tuple gate does not fold an IPv4-mapped
		// IPv6 source (::ffff:1.2.3.4) to v4. net.ParseIP has already discarded
		// the ':' by the time Match sees parsedSrc/parsedDst.
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
		fmt.Printf("Policy content rejected (no verdict enforced for %s -> %s)\n", fromZone, toZone)
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
		// #5649 (C181-C20): name the admitting host-inbound-traffic token (or
		// report deny/global-accept/indeterminate), mirroring the local `show
		// security match-policies` renderer (#3627 B1a) — this remote/`request`
		// path was missing it entirely.
		if res.HostInbound != nil {
			if line := res.HostInbound.Describe(); line != "" {
				fmt.Printf("  host-inbound-traffic (zone %s): %s\n", fromZone, line)
			}
		}
		return nil
	}
	// #4373 (E4/H2/H7): a multicast/broadcast/unspecified/loopback destination is
	// dropped at route lookup before policy runs — surface the advisory so the
	// `test policy` verdict below is not read as real forwarding.
	if note := res.RouteDropNote(); note != "" {
		fmt.Printf("  %s\n", note)
	}
	// #5572: a non-first fragment whose permit was overridden to an overlapping
	// port-bearing deny — surface the advisory so the verdict below is not read
	// as a first-fragment / exact-port match.
	if note := res.FragmentDenyNote(); note != "" {
		fmt.Printf("  %s\n", note)
	}
	if res.UnsupportedTupleFamily {
		// #5720 (codex-182 C-TOOLS): an IPv4 source with an IPv6 destination is
		// an impossible tuple (NAT46 is unimplemented); the forwarding path never
		// produces it and the runtime matcher fails closed. Surface the dedicated
		// verdict instead of a fabricated "Default deny (no matching policy)",
		// which would send an operator to add a permit that can never take
		// effect. Mirrors the REST / gRPC MatchPolicies DisplayAction() render.
		fmt.Printf("%s\n", res.DisplayAction())
		return nil
	}
	if !res.Matched {
		fmt.Printf("Default %s (no matching policy for %s -> %s)\n",
			policymatch.ActionString(res.Action), fromZone, toZone)
		return nil
	}
	if res.Global {
		fmt.Printf("Policy match (global):\n")
		fmt.Printf("  Policy:    %s\n", res.PolicyName)
		printPolicyMatchIdentity(res)
		fmt.Printf("  Action:    %s\n", policymatch.ActionString(res.Action))
		return nil
	}
	fmt.Printf("Policy match:\n")
	fmt.Printf("  From zone: %s\n  To zone:   %s\n", fromZone, toZone)
	fmt.Printf("  Policy:    %s\n", res.PolicyName)
	printPolicyMatchIdentity(res)
	fmt.Printf("  Action:    %s\n", policymatch.ActionString(res.Action))
	// #5649 (C181-C20): a MATCHED to-zone junos-host fine policy still needs
	// the coarse host-inbound-traffic admission gate named — LocalDelivery
	// evaluates BOTH and the fine action alone does not govern the flow.
	// res.HostInbound is populated only for to-zone junos-host queries
	// (matchJunosHost), so this is a no-op for an ordinary transit match.
	if res.HostInbound != nil {
		if line := res.HostInbound.Describe(); line != "" {
			fmt.Printf("  Host-inbound: %s\n", line)
		}
	}
	if srcIP != "" {
		fmt.Printf("  Source:    %s -> ", srcIP)
	} else {
		fmt.Printf("  Source:    any -> ")
	}
	if dstIP != "" {
		fmt.Printf("%s", dstIP)
	} else {
		fmt.Printf("any")
	}
	if dstPort > 0 {
		fmt.Printf(":%d", dstPort)
	}
	// #4497 (avo-001 F3): echo the queried ICMP/ICMPv6 type and code alongside
	// the protocol so the `test policy` verdict names the FULL tuple the
	// simulator matched, not just the protocol. A
	// `protocol icmp icmp-type 8 icmp-code 0` query is answered against the
	// declared type/code (junos-ping = type 8, #3284); dropping the type/code
	// from the echo hid WHICH ICMP packet was tested. A non-ICMP query (no
	// type/code) prints the bare `[proto]` exactly as before.
	if tail := formatQueryProtoTail(proto, icmpType, icmpCode); tail != "" {
		fmt.Printf(" %s", tail)
	}
	fmt.Println()
	return nil
}

// formatQueryProtoTail renders the trailing `[proto ...]` annotation for the
// `test policy` query echo (#4497, avo-001 F3). It surfaces the queried
// ICMP/ICMPv6 type and code so the operator reads the exact tuple the simulator
// matched, not just the protocol name. A nil type/code is omitted; an empty
// protocol with no type/code yields "" (nothing to annotate).
func formatQueryProtoTail(proto string, icmpType, icmpCode *uint8) string {
	if proto == "" && icmpType == nil && icmpCode == nil {
		return ""
	}
	var b strings.Builder
	b.WriteByte('[')
	sep := ""
	if proto != "" {
		b.WriteString(proto)
		sep = " "
	}
	if icmpType != nil {
		fmt.Fprintf(&b, "%stype %d", sep, *icmpType)
		sep = " "
	}
	if icmpCode != nil {
		fmt.Fprintf(&b, "%scode %d", sep, *icmpCode)
	}
	b.WriteByte(']')
	return b.String()
}

// printPolicyMatchIdentity renders the shared PolicyID / RuleID / scope /
// description block for the local `test policy` simulator (#3674). Before this,
// the request-path output printed only the policy name + action (and for a
// global match, nothing but name + action), while `show security match-policies`
// over the SAME policymatch.Result already printed these identity fields. That
// made `test policy` the poorest of the match-policies surfaces: an operator
// could not correlate a verdict with the RT_FLOW / session-table policy ID or
// tell whether a global vs zone-pair rule fired.
//
// All fields come straight off policymatch.Result (populated by the #3667
// RuntimePolicyIDs SSOT), and the scope line reuses the shared matchScopeZone
// helper (#3331), so this surface stays in lock-step with showMatchPolicies with
// no duplicated logic. The 2-space aligned label style matches the surrounding
// `test policy` output rather than the show path's 4-space sub-indent.
func printPolicyMatchIdentity(res policymatch.Result) {
	fmt.Printf("  Policy ID: %d\n", res.PolicyID)
	// #3668: the stable rule identity joins a hit to the inventory / logs /
	// tests even after a reorder shifts the numeric Policy ID.
	if res.RuleID != "" {
		fmt.Printf("  Rule ID:   %s\n", res.RuleID)
	}
	if res.Global {
		fmt.Printf("  Scope:     global (match from-zone: %s, to-zone: %s)\n",
			matchScopeZone(res.FromZone), matchScopeZone(res.ToZone))
	} else {
		fmt.Printf("  Scope:     zone-pair (from-zone: %s, to-zone: %s)\n",
			res.FromZone, res.ToZone)
	}
	if res.Description != "" {
		fmt.Printf("  Description: %s\n", res.Description)
	}
}

// testRouting looks up a destination in the routing table.
func (c *CLI) testRouting(args []string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	var dest, instance string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "destination":
			if i+1 < len(args) {
				i++
				dest = args[i]
			}
		case "instance":
			if i+1 < len(args) {
				i++
				instance = args[i]
			}
		}
	}

	if dest == "" {
		fmt.Println("usage: test routing destination <ip-or-prefix> [instance <name>]")
		return nil
	}

	var entries []routing.RouteEntry
	var err error
	if instance != "" {
		entries, err = c.routing.GetVRFRoutes(instance)
	} else {
		entries, err = c.routing.GetRoutes()
	}
	if err != nil {
		// A total failure (no entries: e.g. VRF not found, or every family's
		// dump failed) stays fatal. A partial per-family failure still has a
		// usable table — warn and continue the lookup rather than dropping it
		// (#5125).
		if len(entries) == 0 {
			return fmt.Errorf("get routes: %w", err)
		}
		fmt.Printf("warning: partial route data (some address families unavailable): %v\n", err)
	}

	// Normalize dest to CIDR for matching
	filterCIDR := dest
	if !strings.Contains(filterCIDR, "/") {
		if strings.Contains(filterCIDR, ":") {
			filterCIDR += "/128"
		} else {
			filterCIDR += "/32"
		}
	}
	filterIP, _, filterErr := net.ParseCIDR(filterCIDR)
	if filterErr != nil {
		filterIP = net.ParseIP(dest)
	}

	// Find the best (longest prefix) match
	var best *routing.RouteEntry
	bestLen := -1
	for i := range entries {
		_, rNet, err := net.ParseCIDR(entries[i].Destination)
		if err != nil {
			continue
		}
		if filterIP != nil && rNet.Contains(filterIP) {
			ones, _ := rNet.Mask.Size()
			if ones > bestLen {
				bestLen = ones
				best = &entries[i]
			}
		}
	}

	if instance != "" {
		fmt.Printf("Routing lookup in instance %s for %s:\n", instance, dest)
	} else {
		fmt.Printf("Routing lookup for %s:\n", dest)
	}
	if best == nil {
		fmt.Println("  No matching route found")
	} else {
		fmt.Printf("  Destination: %s\n", best.Destination)
		fmt.Printf("  Next-hop:    %s\n", best.NextHop)
		fmt.Printf("  Interface:   %s\n", best.Interface)
		fmt.Printf("  Protocol:    %s\n", best.Protocol)
		fmt.Printf("  Preference:  %d\n", best.Preference)
	}
	return nil
}

// testSecurityZone looks up which zone an interface belongs to.
func (c *CLI) testSecurityZone(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	var ifName string
	for i := 0; i < len(args); i++ {
		if args[i] == "interface" && i+1 < len(args) {
			i++
			ifName = args[i]
		}
	}

	if ifName == "" {
		fmt.Println("usage: test security-zone interface <name>")
		return nil
	}
	allZoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		allZoneNames = append(allZoneNames, name)
	}

	sort.Strings(allZoneNames)
	for _, zoneName := range allZoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == ifName {
				fmt.Printf("Interface %s belongs to zone: %s\n", ifName, zoneName)
				if reason := config.ZoneQuarantineExcludedReason(zoneName, cfg); reason != "" {
					id := config.StableZoneID(zoneName)
					survivor := config.StableZoneIDOwner(allZoneNames, id)
					fmt.Printf("  %s\n", config.ZoneQuarantineTestZoneQualifierFor(id, survivor))
				}
				if zone.Description != "" {
					fmt.Printf("  Description: %s\n", zone.Description)
				}
				if zone.ScreenProfile != "" {
					fmt.Printf("  Screen:      %s\n", zone.ScreenProfile)
				}
				// #3654 (H06/M03): this DIAGNOSTIC is supposed to explain
				// per-interface admission, so report the EFFECTIVE (zone UNION
				// interface) set for THIS interface, flag an interface-local
				// override, and print an explicit default-deny posture line.
				// #3682: also flag when THIS interface is a management /
				// cluster-control lifeline excluded from host-inbound deny.
				lifeline := config.HostInboundLifelineInterface(
					ifName, config.HostInboundLifelineSet(cfg))
				for _, line := range zone.RenderInterfaceHostInbound(ifName, lifeline,
					config.HostInboundLabels{
						Indent:         "  ",
						Sep:            ", ",
						ServicesLabel:  "Host-inbound services",
						ProtocolsLabel: "Host-inbound protocols",
					}) {
					fmt.Println(line)
				}
				return nil
			}
		}
	}

	fmt.Printf("Interface %s is not assigned to any security zone\n", ifName)
	return nil
}
