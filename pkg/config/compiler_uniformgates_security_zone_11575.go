package config

func runUniformGatesUnknownSecurityZoneChild11575(cfg *Config, opts compileOpts) error {
	if cfg == nil {
		return nil
	}
	if err := validateUnknownSecurityZoneChild11575(cfg); err != nil {
		if !opts.lenientUnknownSecurityZoneChild11575 {
			return err
		}
	}
	cfg.Warnings = append(cfg.Warnings, toleratedUnknownSecurityZoneChildWarnings11575(cfg)...)
	return nil
}

// clearDroppedEnforcementZoneBindings11575 runs only after all compiler gates
// have inspected authored memberships. Keeping them through P6b lets the
// strict duplicate-interface gate reject them and the tolerant path quarantine
// contested interfaces; no poisoned enforcement state escapes compilation.
func clearDroppedEnforcementZoneBindings11575(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || !zone.DroppedEnforcementChild {
			continue
		}
		zone.DroppedEnforcementInterfaces = append(zone.DroppedEnforcementInterfaces[:0], zone.Interfaces...)
		zone.Interfaces = nil
		zone.InterfaceHostInbound = nil
		zone.ResolvedInterfaceOverrides = nil
		zone.ResolvedInterfaceDeclared = nil
		zone.DHCPScopeWithheld = nil
		zone.ScreenProfile = ""
		zone.ScreenProfileConfigured = false
		zone.HostInboundTraffic = nil
		zone.TCPRst = false
	}
}
