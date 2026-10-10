package config

import (
	"fmt"
	"sort"
)

// validateFilterLossPriorityWarnings emits a WARN-only commit-time message for
// each firewall-filter term carrying `then loss-priority`. The action is parsed
// and stored but has no runtime consumer in the userspace dataplane (#2507), so
// it is accepted-but-inert. It is never an error: loss-priority is valid Junos
// and a hard reject would brick a boot on a previously-inert committed value.
func validateFilterLossPriorityWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	emit := func(family string, filters map[string]*FirewallFilter) {
		// Stable order: iterate by sorted filter name so warnings are
		// deterministic across commits (map iteration is randomized).
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.LossPriority == "" {
					continue
				}
				warnings = append(warnings, fmt.Sprintf(
					"firewall family %s filter %q term %q `then loss-priority %s` is "+
						"accepted for compatibility but is inert in the userspace "+
						"dataplane (no per-packet loss-priority action is enforced)",
					family, name, term.Name, term.LossPriority))
			}
		}
	}
	emit("inet", cfg.Firewall.FiltersInet)
	emit("inet6", cfg.Firewall.FiltersInet6)
	return warnings
}

// validateThreeColorPolicerMarkingWarnings emits a WARN-only commit-time message
// for each three-color policer whose `then` is a marking action (#9503). The
// userspace dataplane meters such a policer (green/yellow/red counters) but
// neither drops the excess nor marks it: only `then discard` enforces the rate.
// Before #9503 the same config disarmed forwarding on every binding; now it
// applies, and this is how the operator learns the marking is inert. Mirrors
// validateFilterLossPriorityWarnings. Never an error, because the #8445 commit
// gate's own text recommends marking alone as the meter-only spelling.
func validateThreeColorPolicerMarkingWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.ThreeColorPolicers))
	for name, pol := range cfg.Firewall.ThreeColorPolicers {
		if pol != nil && pol.ThenAction != "" && pol.ThenAction != "discard" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	warnings := make([]string, 0, len(names))
	for _, name := range names {
		warnings = append(warnings, fmt.Sprintf(
			"firewall three-color-policer %q `then %s` meters only in the userspace "+
				"dataplane: excess traffic is counted green/yellow/red but is neither "+
				"dropped nor marked (only `then discard` enforces the rate)",
			name, cfg.Firewall.ThreeColorPolicers[name].ThenAction))
	}
	return warnings
}

// validateSingleRatePolicerMarkingWarnings keeps the accepted single-rate
// policer's marking action visible to the operator (#11812). The userspace
// runtime meters non-discard policers but does not apply loss-priority marking or
// forwarding-class selection; excess traffic remains forwarded. This is an
// advisory, not a rejection: #9882's meter-only behavior is intentional.
func validateSingleRatePolicerMarkingWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.Policers))
	for name, pol := range cfg.Firewall.Policers {
		if pol != nil && pol.ThenAction != "" && pol.ThenAction != "discard" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	warnings := make([]string, 0, len(names))
	for _, name := range names {
		warnings = append(warnings, fmt.Sprintf(
			"firewall policer %q `then %s` is retained but not applied by the "+
				"userspace dataplane: the policer meters, but the requested loss-priority "+
				"marking or forwarding-class selection is not applied and excess traffic remains forwarded",
			name, cfg.Firewall.Policers[name].ThenAction))
	}
	return warnings
}

// validateLogicalInterfacePolicerWarnings reports that the accepted sharing
// flag survives compilation but has no runtime consumer (#11812). Userspace
// creates policer state per (family, filter, term), not one instance shared
// across protocol families on an interface.
func validateLogicalInterfacePolicerWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.Policers))
	for name, pol := range cfg.Firewall.Policers {
		if pol != nil && pol.LogicalInterfacePolicer {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	warnings := make([]string, 0, len(names))
	for _, name := range names {
		warnings = append(warnings, fmt.Sprintf(
			"firewall policer %q `logical-interface-policer` is retained but not "+
				"applied: userspace policer state is scoped per (family, filter, term), "+
				"not shared across protocol families on the interface",
			name))
	}
	return warnings
}

// validateThreeColorPolicerDisarmWarnings emits a WARN-only commit-time
// message for every color-aware three-color policer (#10502).
//
// The userspace capability gate cannot represent inherited packet color, so
// ColorBlind=false disarms forwarding for the whole dataplane. That is a
// deliberate fail-closed runtime decision, but without this warning a clean
// commit can still stop all transit with no configuration-level explanation.
// Keep this definition-wide (rather than reference-scoped): the capability
// gate currently walks every definition, and this warning must name every
// definition that can trigger that gate.
func validateThreeColorPolicerDisarmWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.ThreeColorPolicers))
	for name, pol := range cfg.Firewall.ThreeColorPolicers {
		if pol != nil && !pol.ColorBlind {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	warnings := make([]string, 0, len(names))
	for _, name := range names {
		warnings = append(warnings, fmt.Sprintf(
			"firewall three-color-policer %q uses color-aware mode, which the "+
				"userspace dataplane cannot represent; userspace forwarding will "+
				"be disarmed and transit will STOP until the policer is changed "+
				"to color-blind",
			name))
	}
	return warnings
}

// validateFirewallInterfaceSpecificWarnings emits a WARN-only commit-time
// message for each firewall filter carrying `interface-specific` (fable-167
// F-3a, #4316). Junos instantiates a distinct counter/policer instance per
// interface the filter is attached to; xpf keeps a single shared counter, so
// `show firewall` aggregates across interfaces. The flag is accepted (never a
// hard reject — it is valid Junos) but its per-interface-instance semantics
// are not honored. WARN once per filter, naming it.
func validateFirewallInterfaceSpecificWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	seen := make(map[string]struct{})
	emit := func(family string, filters map[string]*FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil || !filter.InterfaceSpecific {
				continue
			}
			// A `family any` filter is folded into both pools; dedup by name
			// so it is not double-reported.
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			warnings = append(warnings, fmt.Sprintf(
				"firewall filter %q interface-specific is accepted for compatibility "+
					"but inert: xpf keeps a single shared counter/policer instance "+
					"(not a distinct per-interface instance), so `show firewall` "+
					"aggregates counts across every interface the filter is attached to",
				name))
			_ = family
		}
	}
	emit("inet", cfg.Firewall.FiltersInet)
	emit("inet6", cfg.Firewall.FiltersInet6)
	return warnings
}

// validateLo0FilterKernelMirrorWarnings emits a WARN-only commit-time message
// for each term in an lo0 INPUT filter (`interfaces lo0 unit 0 family inet[6]
// filter input <name>`) that carries a `then` modifier the kernel nftables lo0
// mirror cannot faithfully honor (#3445).
//
// Ordinary host-bound traffic to a firewall interface IP / VRRP VIP is shunted
// to the Linux kernel by the XDP shim before it reaches userspace-dp, so the
// `inet xpf_lo0` nftables chain (pkg/daemon/daemon_nft.go) is the PRIMARY
// enforcement of the lo0 input filter for that traffic. That chain honors the
// match predicates plus `then log`/`then syslog` (nft `log`) and `then count`
// (a named nft counter), but a `hook input` chain has no faithful expression for
// these CoS / rate-control modifiers:
//   - then policer <name>: a Junos policer is a bandwidth+burst token bucket
//     with a configurable then-action (discard / loss-priority); nft `limit`
//     cannot reproduce the bandwidth/burst mapping or the loss-priority action,
//     so mirroring it would silently rate-limit host-bound traffic by a
//     DIFFERENT rule than userspace. The kernel mirror does not enforce it.
//   - then dscp <v> (traffic-class rewrite) / then forwarding-class <fc>: these
//     select egress CoS, which is meaningless for traffic the kernel delivers
//     LOCALLY (there is no egress queue for host-bound packets), so the kernel
//     input mirror performs no rewrite / class selection.
//
// loss-priority is intentionally NOT repeated here: validateFilterLossPriority
// Warnings (#2507) already reports it as globally inert (no per-packet consumer
// in EITHER dataplane), which subsumes the kernel-mirror gap.
//
// It is never an error: these modifiers are valid Junos and a hard reject would
// brick a boot on a previously-committed config; userspace remains authoritative
// for whatever lo0-filtered traffic actually reaches the XSK. The warning names
// the family, filter, term, and modifier so the operator knows the kernel
// host-bound path will not enforce them.
func validateLo0FilterKernelMirrorWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	emit := func(family, filterName string, filter *FirewallFilter) {
		if filterName == "" || filter == nil {
			return
		}
		for _, term := range filter.Terms {
			if term == nil {
				continue
			}
			// Stable, deterministic per-term modifier order.
			type mod struct{ kind, val string }
			var mods []mod
			if term.Policer != "" {
				mods = append(mods, mod{"policer", term.Policer})
			}
			if term.DSCPRewrite != "" {
				mods = append(mods, mod{"dscp (traffic-class rewrite)", term.DSCPRewrite})
			}
			if term.ForwardingClass != "" {
				mods = append(mods, mod{"forwarding-class", term.ForwardingClass})
			}
			for _, m := range mods {
				warnings = append(warnings, fmt.Sprintf(
					"firewall family %s filter %q term %q `then %s %s` is accepted but "+
						"the kernel lo0 input mirror (nftables xpf_lo0, the PRIMARY "+
						"enforcement for host-bound traffic) cannot honor it; the modifier "+
						"applies only to lo0-filtered traffic that reaches the userspace "+
						"dataplane",
					family, filterName, term.Name, m.kind, m.val))
			}
			// #3724 M04: a routing-instance (policy-based routing) term terminates
			// as ACCEPT on the kernel lo0 input mirror (daemon_nft.go
			// terminate-as-accept, #3427). The accept VERDICT is honored, but the
			// kernel `hook input` chain cannot perform the route-selection the term
			// requests. Warn so the operator knows the PBR route selection is
			// silently NOT performed on the primary host-bound path; userspace-dp
			// remains authoritative for lo0-filtered traffic that reaches the XSK.
			// Not folded into the mods loop above because that loop's message says
			// the modifier "cannot be honored", whereas here the verdict IS honored
			// and only the route selection is dropped.
			if term.RoutingInstance != "" {
				warnings = append(warnings, fmt.Sprintf(
					"firewall family %s filter %q term %q `then routing-instance %s` "+
						"terminates as accept on the kernel lo0 input mirror (nftables "+
						"xpf_lo0, the PRIMARY enforcement for host-bound traffic): the "+
						"verdict is honored but the kernel input hook cannot perform the "+
						"route selection; policy-based routing applies only to "+
						"lo0-filtered traffic that reaches the userspace dataplane",
					family, filterName, term.Name, term.RoutingInstance))
			}
		}
	}
	emit("inet", cfg.System.Lo0FilterInputV4, cfg.Firewall.FiltersInet[cfg.System.Lo0FilterInputV4])
	emit("inet6", cfg.System.Lo0FilterInputV6, cfg.Firewall.FiltersInet6[cfg.System.Lo0FilterInputV6])
	return warnings
}

// lo0FilterHookEnforced reports whether the (unit, direction) lo0 hook is
// consumed by a host plane (#12091). Unit 0 input is the supported host-filter
// binding. Any other hook is inert unless its effective tunnel — the bound
// unit's tunnel when present, otherwise the interface tunnel — has usable
// endpoints (TunnelHasUsableEndpoints, #9156), so it creates the device needed
// for per-ifindex filtering. A bare `tunnel` stanza without endpoints creates
// no device, so the hook stays inert and keeps warning.
func lo0FilterHookEnforced(lo0 *InterfaceConfig, number int, unit *InterfaceUnit, input bool) bool {
	if lo0 == nil {
		return false
	}
	if number == 0 && input {
		return true
	}
	if unit != nil && unit.Tunnel != nil {
		return TunnelHasUsableEndpoints(unit.Tunnel)
	}
	return TunnelHasUsableEndpoints(lo0.Tunnel)
}

// validateLo0UnsupportedFilterBindingsWarnings reports lo0 filter bindings the
// host planes accept in the interface model but do not consume (#12091). The
// host-filter contract is limited to unit 0 input in inet and inet6, plus any
// hook backed by a usable effective lo0 tunnel (unit-level when present,
// otherwise interface-level); preserve those supported bindings and name every
// other non-empty lo0 hook.
func validateLo0UnsupportedFilterBindingsWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	lo0 := cfg.Interfaces.Interfaces["lo0"]
	if lo0 == nil {
		return nil
	}
	unitNumbers := make([]int, 0, len(lo0.Units))
	for number := range lo0.Units {
		unitNumbers = append(unitNumbers, number)
	}
	sort.Ints(unitNumbers)

	var warnings []string
	for _, number := range unitNumbers {
		unit := lo0.Units[number]
		if unit == nil {
			continue
		}
		for _, family := range []struct {
			name, input, output string
		}{
			{"inet", unit.FilterInputV4, unit.FilterOutputV4},
			{"inet6", unit.FilterInputV6, unit.FilterOutputV6},
		} {
			if family.input != "" && !lo0FilterHookEnforced(lo0, number, unit, true) {
				warnings = append(warnings, fmt.Sprintf(
					"interfaces lo0 unit %d family %s filter input %q is accepted but NOT enforced by either host plane; only lo0 unit 0 family inet/inet6 filter input is enforced (#12091)",
					number, family.name, family.input))
			}
			if family.output != "" && !lo0FilterHookEnforced(lo0, number, unit, false) {
				warnings = append(warnings, fmt.Sprintf(
					"interfaces lo0 unit %d family %s filter output %q is accepted but NOT enforced by either host plane; only lo0 unit 0 family inet/inet6 filter input is enforced (#12091)",
					number, family.name, family.output))
			}
		}
	}
	return warnings
}

// validateFilterNoCatchAllWarnings emits a WARN-only commit-time message when a
// firewall filter ATTACHED to an interface (or lo0) input/output hook has no
// terminal catch-all term — i.e. it relies on xpf's implicit-accept of any
// packet that matches no term.
//
// Junos stateless firewall filters carry an implicit final DISCARD: a packet
// matching no explicit term is silently dropped. xpf instead falls through to
// an implicit ACCEPT (userspace-dp/src/filter/engine/eval.rs: a no-match
// evaluation returns FilterResult::default(), whose action is Accept). So an
// imported SRX/Junos allowlist filter (terms that accept specific traffic, no
// final discard) PERMITS everything it did not explicitly match under xpf,
// where it would deny under Junos.
//
// This divergence is DELIBERATE and is not changed at runtime (#3295). A global
// flip of the no-match default to discard would blackhole the classify-and-pass
// OUTPUT filter idiom that rides the implicit accept — concretely the CoS
// `bandwidth-output` filters attached as `interfaces reth0 unit 80 family
// inet/inet6 filter output` (a pure dest-port allowlist with no final
// catch-all), whose unmatched egress would be dropped at TX selection
// (afxdp/tx/cos_classify.rs gates drop on action != Accept). That violates the
// project "keep GOOD" doctrine (#2124/#3261). The research record is
// docs/research/3295-filter-failopen/plan.md; the runtime contract is in
// userspace-dp/src/filter/README.md.
//
// The warning is the operator-visibility mitigation: it surfaces the divergence
// at commit so an operator who WANTS Junos stateless-discard parity can append
// an explicit final `term <last> { then discard; }` (the inverse of Junos's
// "write a final accept"). It is never an error — implicit-accept is the
// documented, intentional default, and a hard reject would brick a boot on a
// previously-accepted committed config.
//
// Scope: only filters actually attached to an input/output hook are checked
// (library/unused filters are skipped to avoid noise). lo0 is stored as an
// ordinary interface unit under cfg.Interfaces.Interfaces["lo0"], but hooks
// that #12091 classifies as unenforced are excluded from this advice.
func validateFilterNoCatchAllWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	// Stable order: sorted interface names, then sorted unit numbers, so the
	// warning set is deterministic across commits (map iteration is randomized).
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil { // #3494: tolerant/HA-sync path may carry a nil interface
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil { // #3494: tolerant/HA-sync path may carry a nil unit
				continue
			}
			// (direction label, input flag, referenced filter name, resolved
			// filter). The label mirrors the existing missing-reference warn
			// loop above (input / input-v6 / output / output-v6). A filter that
			// does not resolve is left to that loop (missing-reference warning);
			// this pass only judges a filter that EXISTS and is attached.
			type hook struct {
				dir    string
				input  bool
				name   string
				filter *FirewallFilter
			}
			for _, h := range []hook{
				{"input", true, unit.FilterInputV4, cfg.Firewall.FiltersInet[unit.FilterInputV4]},
				{"input-v6", true, unit.FilterInputV6, cfg.Firewall.FiltersInet6[unit.FilterInputV6]},
				{"output", false, unit.FilterOutputV4, cfg.Firewall.FiltersInet[unit.FilterOutputV4]},
				{"output-v6", false, unit.FilterOutputV6, cfg.Firewall.FiltersInet6[unit.FilterOutputV6]},
			} {
				if h.name == "" || h.filter == nil {
					continue
				}
				if (ifName == "lo0" || ifc.Name == "lo0") &&
					!lo0FilterHookEnforced(ifc, unitNum, unit, h.input) {
					continue
				}
				if firewallFilterHasCatchAllTerminator(h.filter) {
					continue
				}
				warnings = append(warnings, fmt.Sprintf(
					"interface %s unit %d: filter %s %q has no terminal "+
						"catch-all term; xpf accepts traffic matching no term "+
						"(Junos stateless filters imply a final discard) — append "+
						"an explicit final `term <name> { then discard; }` for "+
						"Junos-style deny-by-default, or `then accept` to make "+
						"permit-by-default explicit",
					ifName, unitNum, h.dir, h.name))
			}
		}
	}
	return warnings
}

// firewallFilterHasCatchAllTerminator reports whether the filter contains a
// term that both (a) is a terminating action (`then accept`/`discard`/`reject`
// with no `then next term`) and (b) has a fully unconstrained `from` (matches
// every packet). Such a term governs every packet that reaches it, so the
// filter does not rely on the implicit no-match default. A `then next term` or
// modifier-only fall-through is NOT a terminator; a `then routing-instance` PBR
// term terminates but is not accept/discard/reject and so is not a catch-all.
func firewallFilterHasCatchAllTerminator(f *FirewallFilter) bool {
	if f == nil {
		return false
	}
	for _, t := range f.Terms {
		if t == nil {
			continue
		}
		if firewallTermIsTerminatingAction(t) && firewallTermFromUnconstrained(t) {
			return true
		}
	}
	return false
}

// firewallTermIsTerminatingAction reports whether the term carries an explicit
// terminating action (accept/discard/reject) and is not an explicit
// fall-through (`then next term`). `then routing-instance` (PBR) and
// modifier-only terms (Action == "") are not terminating for this purpose.
func firewallTermIsTerminatingAction(t *FirewallFilterTerm) bool {
	if t.NextTerm {
		return false
	}
	switch t.Action {
	case "accept", "discard", "reject":
		return true
	default:
		return false
	}
}

// firewallTermFromUnconstrained reports whether the term's `from` is empty
// across EVERY match dimension — it matches any packet. This must enumerate all
// match fields on FirewallFilterTerm (types_system.go); a term carrying any
// constraint, including an unresolved/unknown match value (which the dataplane
// keeps verbatim and fails closed on, #3205/#3203/#3307), is constrained and is
// therefore NOT a catch-all. Adding a new match field to FirewallFilterTerm
// requires adding it here.
func firewallTermFromUnconstrained(t *FirewallFilterTerm) bool {
	// #9875: ValuelessFrom joins UnknownFrom below — a term that WROTE a
	// value-bearing leaf but left it empty compiles to the same empty match
	// set as an omitted leaf, yet it is a broken authored constraint, not
	// an intentional catch-all.
	return len(t.SourceAddresses) == 0 &&
		len(t.DestAddresses) == 0 &&
		len(t.SourcePrefixLists) == 0 &&
		len(t.DestPrefixLists) == 0 &&
		len(t.DSCPs) == 0 &&
		len(t.Protocols) == 0 &&
		len(t.DestinationPorts) == 0 &&
		len(t.SourcePorts) == 0 &&
		len(t.SourcePortsExcept) == 0 &&
		len(t.DestPortsExcept) == 0 &&
		len(t.ICMPTypes) == 0 &&
		len(t.ICMPCodes) == 0 &&
		len(t.UnknownICMPTypes) == 0 &&
		len(t.UnknownICMPCodes) == 0 &&
		len(t.UnknownPorts) == 0 &&
		len(t.UnknownAddresses) == 0 &&
		len(t.TCPFlags) == 0 &&
		!t.IsFragment &&
		t.FlexMatch == nil &&
		len(t.UnknownFlexMatch) == 0 &&
		len(t.UnknownFrom) == 0 &&
		len(t.ValuelessFrom) == 0
}
