package config

import "fmt"

// tunnelRoutingInstanceTargetError12520 checks one claim against compiled
// routing instances and returns its deterministic unsupported-target error.
func tunnelRoutingInstanceTargetError12520(
	claim routingInstanceTunnelDeviceClaim,
	instances map[string]*RoutingInstanceConfig,
) error {
	if IsReservedRoutingInstanceName(claim.Instance) {
		return fmt.Errorf(
			"%s: explicit tunnel routing-instance target %q is reserved for the management VRF (%s); use a defined tenant VRF (#12520)",
			claim.Member, claim.Instance, ManagementVRFDeviceName)
	}
	ri := instances[claim.Instance]
	if ri == nil {
		return fmt.Errorf(
			"%s: explicit tunnel routing-instance target %q is undefined; use a defined VRF routing instance (#12520)",
			claim.Member, claim.Instance)
	}
	if ri.InstanceType == "forwarding" {
		return fmt.Errorf(
			"%s: explicit tunnel routing-instance target %q is a forwarding instance with no VRF device; use a defined VRF routing instance (#12520)",
			claim.Member, claim.Instance)
	}
	return nil
}

func tunnelRoutingInstancesByName12520(cfg *Config) map[string]*RoutingInstanceConfig {
	instances := make(map[string]*RoutingInstanceConfig, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			instances[ri.Name] = ri
		}
	}
	return instances
}

// validateTunnelRoutingInstanceTargetsStrict12520 refuses explicit tunnel
// routing-instance stanzas that cannot resolve to a VRF owner. The kernel
// derives vrf-<target> even when userspace has no active owner for that target.
func validateTunnelRoutingInstanceTargetsStrict12520(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	claims := routingInstanceTunnelDeviceClaims(cfg)
	if len(claims) == 0 {
		return nil
	}
	instances := tunnelRoutingInstancesByName12520(cfg)
	for _, claim := range claims {
		if err := tunnelRoutingInstanceTargetError12520(claim, instances); err != nil {
			return err
		}
	}
	return nil
}

// removeQuarantinedTunnels12520 removes every tunnel in removed from the
// compiled config (#14390). An interface-level tunnel is removed the way
// #9909 removes one; units that inherited it must also go, or they survive
// as live non-tunnel interfaces. A unit-level tunnel takes its unit with
// it, as the tolerant #9899 unit skip does, because a unit left without
// its tunnel would inherit any interface-level tunnel. A unit with its
// own (non-removed) tunnel keeps it.
func removeQuarantinedTunnels12520(cfg *Config, removed map[*TunnelConfig]struct{}) {
	if len(removed) == 0 {
		return
	}
	removedRefs := make(map[string]struct{})
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		removeInterfaceTunnel := false
		if ifc.Tunnel != nil {
			_, removeInterfaceTunnel = removed[ifc.Tunnel]
			if removeInterfaceTunnel {
				ifc.Tunnel = nil
			}
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			if removeInterfaceTunnel && unit.Tunnel == nil {
				removedRefs[fmt.Sprintf("%s.%d", ifName, unitNum)] = struct{}{}
				delete(ifc.Units, unitNum)
				continue
			}
			if unit.Tunnel == nil {
				continue
			}
			if _, remove := removed[unit.Tunnel]; remove {
				removedRefs[fmt.Sprintf("%s.%d", ifName, unitNum)] = struct{}{}
				delete(ifc.Units, unitNum)
			}
		}
		// An interface-level removal with no surviving units leaves no
		// logical interface behind; record the bare ref too.
		if removeInterfaceTunnel && len(ifc.Units) == 0 {
			removedRefs[ifName] = struct{}{}
			// Unit 0 is the implicit row of an interface-level tunnel.
			removedRefs[fmt.Sprintf("%s.0", ifName)] = struct{}{}
		}
	}
	// Drop zone bindings naming a removed tunnel row: the interface no
	// longer exists as an ingress device, so the binding must not scope
	// host-inbound coverage (or any other consumer) to a phantom netdev.
	// A unit-qualified ref is dropped only when it names a removed unit;
	// a bare ref is dropped only when the whole interface is gone.
	// Surviving units and other interfaces are untouched.
	if len(removedRefs) == 0 {
		return
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || len(zone.Interfaces) == 0 {
			continue
		}
		kept := zone.Interfaces[:0]
		for _, ref := range zone.Interfaces {
			s := cfg.SplitInterfaceUnitRef(ref)
			key := s.Literal
			if !s.HasUnit || s.UnitTok == "" {
				key = s.Base
				if key == "" {
					key = ref
				}
			}
			if _, gone := removedRefs[key]; !gone {
				kept = append(kept, ref)
			}
		}
		for i := len(kept); i < len(zone.Interfaces); i++ {
			zone.Interfaces[i] = ""
		}
		zone.Interfaces = kept
	}
}

// skipQuarantinedGRECollisions12520 runs before the tolerant removal below.
// A quarantined tunnel's GRE decap identity (#10654: source, destination,
// key and transport instance) would, if the tunnel were installed in the
// default instance, belong to that instance; another tunnel may already
// own the same identity there. The #10654 gate ran before this gate with
// the authored targets still present and saw two distinct identities.
// Since #14390 every quarantined tunnel is removed, so no quarantined
// tunnel can take an owned identity; this check keeps the explicit
// collision diagnostic (naming the skipped tunnel and its owner) for the
// colliding sub-case instead of a plain removal warning.
//
// Every non-quarantined GRE endpoint claims its post-removal identity
// first (its RoutingInstance is unchanged by the removal), then the
// quarantined endpoints claim theirs in emitter order with the target
// treated as the default instance (""). A quarantined tunnel whose
// identity is already owned gets the collision warning; all quarantined
// tunnels are removed by removeQuarantinedTunnels12520 regardless.
// Duplicates among non-quarantined tunnels predate this gate and stay
// with #10654.
func skipQuarantinedGRECollisions12520(cfg *Config, quarantined map[*TunnelConfig]string) {
	if len(quarantined) == 0 {
		return
	}
	type greEndpoint struct {
		name   string
		tunnel *TunnelConfig
		key    greOuterKey
	}
	var owners, cleared []greEndpoint
	seen := make(map[*TunnelConfig]struct{})
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		// Inheritance fans one tunnel object out to several unit rows.
		if _, dup := seen[ep.Tunnel]; dup {
			continue
		}
		seen[ep.Tunnel] = struct{}{}
		key, ok := greOuterKeyForTunnel(ep.Tunnel)
		if !ok {
			continue
		}
		endpoint := greEndpoint{name: ep.Name, tunnel: ep.Tunnel, key: key}
		if _, wasQuarantined := quarantined[ep.Tunnel]; wasQuarantined {
			// The authored target never installs (#14390 removal), so
			// the identity this tunnel WOULD have claimed is the
			// default-instance one.
			endpoint.key.transportRI = ""
			cleared = append(cleared, endpoint)
		} else {
			owners = append(owners, endpoint)
		}
	}
	owner := make(map[greOuterKey]string, len(owners)+len(cleared))
	for _, endpoint := range owners {
		if _, taken := owner[endpoint.key]; !taken {
			owner[endpoint.key] = endpoint.name
		}
	}
	for _, endpoint := range cleared {
		kept, taken := owner[endpoint.key]
		if !taken {
			owner[endpoint.key] = endpoint.name
			continue
		}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"tunnel %q is skipped on tolerant load: its routing-instance target %q is unsupported, and installing it in the default instance would move its GRE outer (%s) onto tunnel %q, which already owns it (#14390, #12520, #10654)",
			endpoint.name, quarantined[endpoint.tunnel], endpoint.key.outerDescription(), kept))
	}
}

// runTailGatesTunnelRITarget12520 checks explicit tunnel targets after the
// established tail gates. Tolerant loads warn once per violating claim and
// remove that tunnel (#14390, the #9909 posture), without rejecting
// persisted configurations (#1960). Removing — not clearing the target —
// keeps the tunnel out of every routing domain: clearing installed it in
// the default domain (RoutingDomain 0), a VRF escape from the undefined,
// forwarding, or reserved-management domain the operator named.
func runTailGatesTunnelRITarget12520(cfg *Config, opts compileOpts) error {
	if cfg == nil {
		return nil
	}
	if !opts.lenientTunnelRITarget12520 {
		return validateTunnelRoutingInstanceTargetsStrict12520(cfg)
	}
	claims := routingInstanceTunnelDeviceClaims(cfg)
	if len(claims) == 0 {
		return nil
	}
	instances := tunnelRoutingInstancesByName12520(cfg)
	quarantined := make(map[*TunnelConfig]string)
	for _, claim := range claims {
		if err := tunnelRoutingInstanceTargetError12520(claim, instances); err != nil {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("tunnel routing-instance target (quarantined on tolerant path): %v", err))
			if claim.Tunnel != nil {
				quarantined[claim.Tunnel] = claim.Instance
			}
		}
	}
	skipQuarantinedGRECollisions12520(cfg, quarantined)
	removed := make(map[*TunnelConfig]struct{}, len(quarantined))
	for tunnel := range quarantined {
		removed[tunnel] = struct{}{}
	}
	removeQuarantinedTunnels12520(cfg, removed)
	return nil
}
