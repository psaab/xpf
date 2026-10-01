package config

import (
	"fmt"
	"sort"
)

// validateRIMgmtMemberStrict11392 rejects management-class interface devices
// claimed by a routing-instance list. Those names are assigned to vrf-mgmt by
// the daemon and must not also be treated as tenant VRF members.
func validateRIMgmtMemberStrict11392(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	tunnelNames := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		for _, key := range RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri) {
			if !IsManagementIfName(key.LinuxName) {
				continue
			}
			return fmt.Errorf(
				"routing-instances %q interface %q resolves to management-class Linux device %q; management interfaces are owned by vrf-mgmt and cannot be members of a tenant routing-instance (#11392)",
				ri.Name, key.InterfaceKey, key.LinuxName)
		}
	}
	return nil
}

// runUniformGatesRIMgmtMember11392 rejects on strict commit and warns on
// tolerant load/peer-sync so legacy configs remain bootable. Apply and reassert
// still keep these devices exclusively in the management VRF.
func runUniformGatesRIMgmtMember11392(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateRIMgmtMemberStrict11392(cfg); err != nil {
		if opts.lenientRIMgmtMember11392 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("management-class routing-instance interface membership (downgraded to warning on tolerant path): %v", err))
			return nil
		}
		return err
	}
	return nil
}

// quarantineRIRoleMembers removes management-class devices and configured
// host-inbound lifelines from tolerant tenant routing-instance memberships
// after tail validation. Bare references that fan out to ordinary devices are
// rewritten to those unaffected keys only.
func quarantineRIRoleMembers(cfg *Config, tunnelNames map[string]string) {
	if cfg == nil {
		return
	}
	lifelines := HostInboundLifelineSet(cfg)
	isFencedMember := func(interfaceKey, linuxName string) bool {
		return IsManagementIfName(linuxName) ||
			HostInboundLifelineInterface(interfaceKey, lifelines)
	}
	eligibleInstances := make(map[string]struct{}, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		eligibleInstances[ri.Name] = struct{}{}
	}

	// Earlier tolerant passes can retain primary claims from a bare member.
	// Drop management-class and configured lifeline claims before userspace /
	// kernel consumers observe them, while leaving reserved/forwarding ownership
	// untouched.
	retainedClaims := cfg.QuarantinedRIMemberPrimaryClaims[:0]
	primarySeen := make(map[string]struct{}, len(cfg.QuarantinedRIMemberPrimaryClaims))
	for _, claim := range cfg.QuarantinedRIMemberPrimaryClaims {
		_, eligible := eligibleInstances[claim.Instance]
		if eligible && isFencedMember(claim.InterfaceKey, claim.LinuxName) {
			continue
		}
		retainedClaims = append(retainedClaims, claim)
		primarySeen[claim.Instance+"\x00"+claim.InterfaceKey+"\x00"+claim.LinuxName] = struct{}{}
	}
	cfg.QuarantinedRIMemberPrimaryClaims = retainedClaims

	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if _, eligible := eligibleInstances[ri.Name]; !eligible {
			continue
		}
		kept := make([]string, 0, len(ri.Interfaces))
		for _, member := range ri.Interfaces {
			if member == "" {
				kept = append(kept, member)
				continue
			}
			keys := RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member)
			touchesFencedMember := false
			for _, key := range keys {
				if isFencedMember(key.InterfaceKey, key.LinuxName) {
					touchesFencedMember = true
					break
				}
			}
			if !touchesFencedMember {
				kept = append(kept, member)
				continue
			}

			for _, key := range keys {
				if key.LinuxName == "" || isFencedMember(key.InterfaceKey, key.LinuxName) {
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
				if _, found := primarySeen[claimKey]; found {
					continue
				}
				primarySeen[claimKey] = struct{}{}
				cfg.QuarantinedRIMemberPrimaryClaims = append(
					cfg.QuarantinedRIMemberPrimaryClaims, claim)
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
}
