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

// skipQuarantinedGRECollisions12520 runs after the tolerant clear below.
// Clearing a target moves that tunnel's GRE decap identity (#10654: source,
// destination, key and transport instance) into the default instance, where
// another tunnel may already own it. The #10654 gate ran before the clear and
// saw two distinct identities; left alone, the snapshot builder would keep the
// first-sorting duplicate, which can be the quarantined tunnel, blackholing
// the valid tunnel's egress and crediting its inbound frames to the wrong one.
//
// Every non-quarantined GRE endpoint claims its identity first, then the
// quarantined endpoints claim theirs in emitter order. A quarantined tunnel
// whose identity is already owned is removed from the compiled config, so the
// kernel tunnel manager and the snapshot builder both see only the owner.
// Duplicates among non-quarantined tunnels predate this gate and stay with
// #10654. An interface-level tunnel is removed the way #9909 removes one; a
// unit-level tunnel takes its unit with it, as the tolerant #9899 unit skip
// does, because a unit left without its tunnel would inherit any
// interface-level tunnel.
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
		if _, wasCleared := quarantined[ep.Tunnel]; wasCleared {
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
	skipped := make(map[*TunnelConfig]struct{})
	for _, endpoint := range cleared {
		kept, taken := owner[endpoint.key]
		if !taken {
			owner[endpoint.key] = endpoint.name
			continue
		}
		skipped[endpoint.tunnel] = struct{}{}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"tunnel %q is skipped on tolerant load: clearing its routing-instance target %q moves its GRE outer (%s) into the default instance, where tunnel %q already owns it (#12520, #10654)",
			endpoint.name, quarantined[endpoint.tunnel], endpoint.key.outerDescription(), kept))
	}
	if len(skipped) == 0 {
		return
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil {
			if _, skip := skipped[ifc.Tunnel]; skip {
				ifc.Tunnel = nil
			}
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			if _, skip := skipped[unit.Tunnel]; skip {
				delete(ifc.Units, unitNum)
			}
		}
	}
}

// runTailGatesTunnelRITarget12520 checks explicit tunnel targets after the
// established tail gates. Tolerant loads warn once per violating claim and
// clear that target, keeping kernel and userspace ownership in the default
// routing domain without rejecting persisted configurations (#1960); a cleared
// GRE tunnel that collides with an owned outer identity is skipped instead.
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
				claim.Tunnel.RoutingInstance = ""
			}
		}
	}
	skipQuarantinedGRECollisions12520(cfg, quarantined)
	return nil
}
