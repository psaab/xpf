package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateRIDualClaimStrict11060 rejects any Linux netdevice claimed by more
// than one routing instance through list membership or a tunnel routing-instance
// stanza. Logical refs use the shared device resolver, so aliases, VLAN IDs,
// shared tunnels, and explicit tunnel ownership have one identity.
func validateRIDualClaimStrict11060(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	conflicts := RoutingInstanceMemberDeviceConflicts(cfg, cfg.TunnelNameMap())
	if len(conflicts) == 0 {
		return nil
	}
	return routingInstanceMemberConflictError(conflicts[0])
}

func routingInstanceMemberConflictError(conflict RoutingInstanceMemberDeviceConflict) error {
	return fmt.Errorf(
		"Linux interface device %q is claimed by multiple routing-instances %s; an interface must have exactly one routing-instance owner (#11060: remove every conflicting member except one)",
		conflict.LinuxName, formatRoutingInstanceMemberClaims(conflict.Claims))
}

func formatRoutingInstanceMemberClaims(claims []RoutingInstanceMemberClaim) string {
	parts := make([]string, 0, len(claims))
	for _, claim := range claims {
		parts = append(parts, fmt.Sprintf("%q (member %q)", claim.Instance, claim.Member))
	}
	return strings.Join(parts, ", ")
}

func recordRIDualClaimConflicts(cfg *Config, conflicts []RoutingInstanceMemberDeviceConflict) {
	if cfg == nil || len(conflicts) == 0 {
		return
	}
	cfg.QuarantinedRIMemberDeviceConflicts = append(
		cfg.QuarantinedRIMemberDeviceConflicts, conflicts...)
	for _, conflict := range conflicts {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"routing-instance interface membership QUARANTINED on tolerant path: Linux device %q is claimed by %s; conflicting memberships will be removed and the device left unbound in the default routing instance (#11060)",
			conflict.LinuxName, formatRoutingInstanceMemberClaims(conflict.Claims)))
	}
}

// quarantineRIDualClaimDevices runs after all compile tail gates so legacy
// validators can still inspect the authored memberships. It removes contested
// devices before the compiled config reaches apply or dataplane consumers.
func quarantineRIDualClaimDevices(cfg *Config, tunnelNames map[string]string) {
	if cfg == nil || len(cfg.QuarantinedRIMemberDeviceConflicts) == 0 {
		return
	}
	quarantined := make(map[string]struct{}, len(cfg.QuarantinedRIMemberDeviceConflicts))
	for _, conflict := range cfg.QuarantinedRIMemberDeviceConflicts {
		quarantined[conflict.LinuxName] = struct{}{}
	}

	// Preserve unaffected fanout units as explicit refs. A bare member's
	// primary key is stored as a typed base-only claim, never as the original
	// bare reference which would expand over a quarantined sibling again.
	primarySeen := make(map[string]struct{}, len(cfg.QuarantinedRIMemberPrimaryClaims))
	for _, claim := range cfg.QuarantinedRIMemberPrimaryClaims {
		primarySeen[claim.Instance+"\x00"+claim.InterfaceKey+"\x00"+claim.LinuxName] = struct{}{}
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		kept := make([]string, 0, len(ri.Interfaces))
		for _, member := range ri.Interfaces {
			if member == "" {
				kept = append(kept, member)
				continue
			}
			keys := RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member)
			touchesConflict := false
			for _, key := range keys {
				if _, found := quarantined[key.LinuxName]; found {
					touchesConflict = true
					break
				}
			}
			if !touchesConflict {
				kept = append(kept, member)
				continue
			}
			for _, key := range keys {
				if key.LinuxName == "" {
					continue
				}
				if _, found := quarantined[key.LinuxName]; found {
					continue
				}
				if key.Fanout {
					kept = append(kept, key.InterfaceKey)
					continue
				}
				claim := RoutingInstanceMemberPrimaryClaim{
					Instance: ri.Name, InterfaceKey: key.InterfaceKey, LinuxName: key.LinuxName,
				}
				claimKey := claim.Instance + "\x00" + claim.InterfaceKey + "\x00" + claim.LinuxName
				if _, found := primarySeen[claimKey]; !found {
					primarySeen[claimKey] = struct{}{}
					cfg.QuarantinedRIMemberPrimaryClaims = append(
						cfg.QuarantinedRIMemberPrimaryClaims, claim)
				}
			}
		}
		ri.Interfaces = kept
	}
	sort.Slice(cfg.QuarantinedRIMemberPrimaryClaims, func(i, j int) bool {
		left, right := cfg.QuarantinedRIMemberPrimaryClaims[i], cfg.QuarantinedRIMemberPrimaryClaims[j]
		if left.Instance != right.Instance {
			return left.Instance < right.Instance
		}
		if left.InterfaceKey != right.InterfaceKey {
			return left.InterfaceKey < right.InterfaceKey
		}
		return left.LinuxName < right.LinuxName
	})

	// A conflicting tunnel stanza is also an ownership claim. Clear every
	// stanza resolving to the contested device so the tunnel manager does not
	// re-enslave it after both conflicting memberships have been quarantined.
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		clearStanza := func(tc *TunnelConfig, device string) {
			if tc == nil || device == "" {
				return
			}
			if _, found := quarantined[device]; found {
				tc.RoutingInstance = ""
			}
		}
		if ifc.Tunnel != nil {
			clearStanza(ifc.Tunnel, ifc.Tunnel.Name)
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			device := unit.Tunnel.Name
			if ifc.Tunnel != nil && ifc.Tunnel.Mode == "wireguard" && ifc.Tunnel.Name != "" {
				device = ifc.Tunnel.Name
			}
			clearStanza(unit.Tunnel, device)
		}
	}
}

// runUniformGatesRIDualClaim11060 wires the device-identity gate into the
// tolerant/strict uniform-gate phase. Strict commits reject the conflict;
// tolerant loads record it now and defer membership removal until all tail
// validators have inspected the authored config.
func runUniformGatesRIDualClaim11060(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if cfg == nil {
		return nil
	}
	tunnelNames := cfg.TunnelNameMap()
	conflicts := RoutingInstanceMemberDeviceConflicts(cfg, tunnelNames)
	if len(conflicts) == 0 {
		return nil
	}
	if !opts.lenientRIDualClaim11060 {
		return routingInstanceMemberConflictError(conflicts[0])
	}
	recordRIDualClaimConflicts(cfg, conflicts)
	return nil
}
