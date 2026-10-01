package config

import (
	"fmt"
)

// validateRILifelineMemberStrict11364 rejects a configured host-inbound
// lifeline claimed by an operator routing instance. LOCAL_IN sees a VRF slave's
// master, not the slave, so a lifeline member would make the shared master
// unscopable for every data co-member. Management-name members are owned by the
// earlier #11392 gate and are left to that diagnostic.
func validateRILifelineMemberStrict11364(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	tunnelNames := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		for _, key := range RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri) {
			if key.LinuxName == "" || IsManagementIfName(key.LinuxName) ||
				!HostInboundLifelineInterface(key.InterfaceKey, lifelines) {
				continue
			}
			return fmt.Errorf(
				"routing-instances %q interface %q resolves to configured host-inbound lifeline %q; a lifeline cannot be a tenant routing-instance member because its VRF master would lose host-inbound ingress scope for co-members (#11364)",
				ri.Name, key.InterfaceKey, key.LinuxName)
		}
	}
	return nil
}

func runUniformGatesRILifelineMember11364(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateRILifelineMemberStrict11364(cfg); err != nil {
		if opts.lenientRIMgmtMember11392 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("configured lifeline routing-instance membership (downgraded to warning on tolerant path): %v; the lifeline is removed from the tenant VRF so co-member ingress scope remains matchable", err))
			return nil
		}
		return err
	}
	return nil
}
