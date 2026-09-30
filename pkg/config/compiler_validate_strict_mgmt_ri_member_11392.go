package config

import "fmt"

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
