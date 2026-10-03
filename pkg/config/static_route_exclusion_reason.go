package config

import (
	"fmt"
	"net"
	"strings"
)

// Shared "is this static route actually installed?" predicate.
//
// #7357 items 3-5: `show route` / `show routing-options` render every
// configured static route straight from config, while
// buildRouteSnapshots (pkg/dataplane/userspace/routes.go) DROPS eight
// classes of them. A dropped route printed as configured reads as an
// installed route, which is the #6534 archetype: the operator checks the
// surface after committing and it confirms a forwarding decision that is
// not in force.
//
// Same mechanism as FlowServerExcludedReason and the NAT family, and NOT an
// applied-set readback: every verdict below is a deterministic function of
// the committed config, so the renderer can reach it without runtime state.
//
// Seven of the eight reasons are per-route. The eighth (the next-table window)
// is ORDER-DEPENDENT and cannot be decided from one route, which is why
// StaticRouteExclusions exists alongside this.
//
// StaticRouteNextHopFamilyMismatchReason is shared by strict validation, the
// lenient snapshot exclusion and the FRR render belt; StaticRouteExclusions
// carries the same reason to every config-backed show surface.

// StaticRouteNextHopFamilyMismatchReason reports when an IP next-hop's family
// differs from its static route destination. Empty/interface-only next-hops,
// unparsable address tokens, and next-table routes are not family mismatches.
func StaticRouteNextHopFamilyMismatchReason(sr *StaticRoute) string {
	if sr == nil || sr.NextTable != "" {
		return ""
	}
	destinationFamily := FRRAddrFamily(sr.Destination)
	if destinationFamily == "" {
		return ""
	}
	for _, nh := range sr.NextHops {
		address, _, _ := strings.Cut(nh.Address, "@")
		nextHopFamily := FRRAddrFamily(address)
		if address == "" || nextHopFamily == "" || nextHopFamily == destinationFamily {
			continue
		}
		destinationVersion, nextHopVersion := "IPv6", "IPv4"
		if destinationFamily == "v4" {
			destinationVersion, nextHopVersion = "IPv4", "IPv6"
		}
		display := nh.Address
		if !strings.Contains(display, "@") && nh.Interface != "" {
			display += " interface " + nh.Interface
		}
		return fmt.Sprintf(
			"%s destination with %s next-hop %q is unsupported by userspace dataplane; "+
				"use a same-family gateway or a structured interface-only next-hop",
			destinationVersion, nextHopVersion, display)
	}
	return ""
}

// StaticRouteExcludedReason reports why buildRouteSnapshots drops `sr`, or ""
// when it publishes it.
//
// `perInstance` distinguishes a route under `routing-instances <n>
// routing-options` from a global one; `definedInstances` is the set of
// routing-instance names the config defines.
//
// It deliberately does NOT decide the next-table WINDOW case — that depends
// on how many eligible global next-table routes precede this one, which no
// per-route call can know. Use StaticRouteExclusions for a whole config.

func StaticRouteExcludedReason(sr *StaticRoute, perInstance bool, definedInstances map[string]struct{}) string {
	if sr == nil {
		return ""
	}
	// #11539: explicit operator intent takes precedence over derived
	// zero-disposition classification below.
	if sr.NoInstall {
		return "route has the `no-install` option set"
	}
	if sr.NextTable == "" {
		// #10000: ordinary routes still go through addSnapshot's wire
		// destination gate. Keep the shared builder/show verdict in lockstep
		// with that gate: valid CIDRs and bare host addresses are usable, while
		// the Junos `default` keyword and malformed destinations are not.
		if !staticRouteDestinationUsable(sr.Destination) {
			return fmt.Sprintf("destination %q is neither a CIDR prefix nor a bare IP address", sr.Destination)
		}
		if reason := StaticRouteNextHopFamilyMismatchReason(sr); reason != "" {
			return reason
		}
		if !staticRouteHasDisposition(sr) {
			return "route has no forwarding disposition (no next-hop, next-table, discard, or reject)"
		}
		return ""
	}

	// #5830: a `next-table` authored UNDER a routing-instance is NOT programmed
	// on the kernel/FRR forwarding plane — daemon_apply feeds only the GLOBAL
	// routing-options statics to ApplyNextTableRules, the FRR renderer emits
	// nothing for a NextTable route, and the kernel ip-rule leak carries no
	// source-table scoping. Publishing it as a live per-instance next-table made
	// the userspace FIB leak traffic the kernel/FRR view never routes — a
	// control-plane/data-plane split-brain. Both planes must agree it is ABSENT.
	//
	// The strict commit gate (validateNextTableTargetReferencesStrict, #5830)
	// hard-rejects such a config, so this is reachable only on the tolerantly-
	// loaded / peer-synced path where that reject is downgraded to a warning
	// (#1960 no-brick). GLOBAL next-table IS programmed via ip rule and stays
	// published so the Rust FIB can cross-reference the target table.
	if perInstance {
		return "next-table is not supported under a routing-instance — no ip rule is installed for it"
	}
	if _, ok := definedInstances[sr.NextTable]; !ok {
		return fmt.Sprintf("next-table target routing-instance %q is not defined", sr.NextTable)
	}
	if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
		return fmt.Sprintf("destination %q does not parse as a CIDR prefix", sr.Destination)
	}
	return ""
}

// staticRouteHasDisposition reports whether a static route describes an action
// that either routing plane can install. Empty qualified-next-hop placeholders
// are not forwarding targets: the snapshot builder skips them before deciding
// whether to publish a route row.
func staticRouteHasDisposition(sr *StaticRoute) bool {
	if sr == nil {
		return false
	}
	for _, nh := range sr.NextHops {
		if nh.Address != "" || nh.Interface != "" {
			return true
		}
	}
	return sr.NextTable != "" || sr.Discard || sr.Reject
}

// staticRouteDestinationUsable mirrors the destination acceptance in
// userspace.routeDestinationForWire without creating a package dependency
// cycle. A bare host is usable because the builder adds its host prefix before
// publishing the snapshot; all other non-CIDR values are dropped.
func staticRouteDestinationUsable(destination string) bool {
	if _, _, err := net.ParseCIDR(destination); err == nil {
		return true
	}
	return net.ParseIP(destination) != nil
}

// StaticRouteExclusions returns the exclusion reason for every static route in
// `cfg` that buildRouteSnapshots drops, keyed by the route pointer.
//
// It exists for the ORDER-DEPENDENT eighth reason. The kernel programs global
// next-table leaks as ip rules capped at NextTableRuleWindow entries — one
// slot per default-instance ingress interface per leak since #9420 (#9810) —
// and the applier advances that counter only for an ELIGIBLE route, drawn down
// leak-atomically in parsed-CIDR v4-first order. So whether a given route falls
// outside the window depends on how many eligible ones came before it, in the
// applier's own order, times the shared ingress count.
//
// That order is reproduced exactly and it is narrower than it looks: the window
// counter advances ONLY on the global path (`perInstance == false`), so
// per-instance routes cannot affect it and the walk below only needs the two
// global lists, stably partitioned v4-first by parsed CIDR exactly like the
// applier (a v6 CIDR under `static` is legal, #9820). Per-instance routes are
// still classified, just not counted.
func StaticRouteExclusions(cfg *Config) map[*StaticRoute]string {
	out := make(map[*StaticRoute]string)
	if cfg == nil {
		return out
	}
	defined := make(map[string]struct{}, len(cfg.RoutingInstances))
	for _, inst := range cfg.RoutingInstances {
		if inst != nil {
			defined[inst.Name] = struct{}{}
		}
	}

	// GLOBAL — the only routes that consume window slots, drawn in the
	// applier's parsed-CIDR v4-first order (nextTableWindowOrder).
	// #9810: each eligible leak costs one slot per default-instance ingress
	// interface (N from the shared resolver), leak-atomically: a leak whose
	// full expansion does not fit is excluded whole. With no ingress
	// interface the applier installs nothing (#9420 fail-closed), so every
	// eligible leak is excluded.
	ingress := len(DefaultInstanceIngressIfaces(cfg))
	window := 0
	for _, sr := range nextTableWindowOrder(cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes) {
		if sr == nil {
			continue
		}
		if reason := StaticRouteExcludedReason(sr, false, defined); reason != "" {
			out[sr] = reason
			continue
		}
		if sr.NextTable == "" {
			continue // not a leak; consumes no slot
		}
		if ingress == 0 {
			out[sr] = "beyond the next-table ip-rule window: no default-instance " +
				"ingress interface resolves, so the kernel installs no rule for it"
			continue
		}
		if window+ingress > NextTableRuleWindow {
			out[sr] = fmt.Sprintf(
				"beyond the %d-entry next-table ip-rule window with %d default-instance "+
					"ingress interfaces (each leak costs one rule per ingress interface) "+
					"— the kernel installs no rule for it",
				NextTableRuleWindow, ingress)
			continue
		}
		window += ingress
	}

	// PER-INSTANCE: classified, never counted.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		for _, routes := range [][]*StaticRoute{ri.StaticRoutes, ri.Inet6StaticRoutes} {
			for _, sr := range routes {
				if sr == nil {
					continue
				}
				if reason := StaticRouteExcludedReason(sr, true, defined); reason != "" {
					out[sr] = reason
				}
			}
		}
	}
	return out
}

// nextTableWindowOrder returns the global statics stably partitioned v4-first
// by PARSED CIDR — the same draw order the applier uses
// (pkg/routing.nextTableFamilyOrdered, #6583). A v6 CIDR under `static` is
// legal (#9820); drawing it in list position would pick different truncation
// survivors than the kernel (#9810).
func nextTableWindowOrder(v4, v6 []*StaticRoute) []*StaticRoute {
	combined := make([]*StaticRoute, 0, len(v4)+len(v6))
	combined = append(combined, v4...)
	combined = append(combined, v6...)
	out := make([]*StaticRoute, 0, len(combined))
	var v6group []*StaticRoute
	for _, sr := range combined {
		if sr == nil {
			out = append(out, sr)
			continue
		}
		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil || dst.IP.To4() != nil {
			out = append(out, sr)
			continue
		}
		v6group = append(v6group, sr)
	}
	return append(out, v6group...)
}
