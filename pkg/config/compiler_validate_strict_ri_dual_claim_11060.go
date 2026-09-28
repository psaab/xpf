package config

import (
	"fmt"
	"strings"
)

// validateRIDualClaimStrict11060 rejects any Linux netdevice claimed by more
// than one routing instance. Logical refs are expanded by
// RoutingInstanceMemberDeviceKeys, the same resolver used by kernel binding and
// userspace membership maps, so aliases, VLAN IDs, and shared tunnels have one
// ownership identity.
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
		"Linux interface device %q is claimed by multiple VRF-backed routing-instances %s; an interface must belong to exactly one VRF-backed routing-instance (#11060: remove every conflicting member except one)",
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

	// Keep unaffected generated units from a bare member as explicit refs.
	// Retaining the original bare ref would fan back down over the quarantined
	// device and recreate the ambiguous bind in both dataplane planes.
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
				if !key.Fanout || key.LinuxName == "" {
					continue
				}
				if _, found := quarantined[key.LinuxName]; !found {
					kept = append(kept, key.InterfaceKey)
				}
			}
		}
		ri.Interfaces = kept
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
