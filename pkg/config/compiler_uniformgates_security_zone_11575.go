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
