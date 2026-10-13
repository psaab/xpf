package config

func runUniformGatesUnknownSecurityPoliciesChild12217(cfg *Config, opts compileOpts) error {
	if cfg == nil {
		return nil
	}
	if err := validateUnknownSecurityPoliciesChild12217(cfg); err != nil {
		if !opts.lenientUnknownPoliciesChild12217 {
			return err
		}
	}
	cfg.Warnings = append(cfg.Warnings, toleratedUnknownSecurityPoliciesChildWarnings12217(cfg)...)
	children := enforcementSecurityPoliciesChildren12217(&cfg.Security)
	if len(children) != 0 {
		// An unknown enforcement-bearing child could hide a deny rulebase.
		// Reuse #12039's synthetic global carrier so userspace refuses the
		// incomplete policy snapshot.
		cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, &Policy{
			Name:                            "xpf-unknown-policies-child-poison",
			Action:                          PolicyDeny,
			terminalActions:                 []PolicyAction{PolicyDeny},
			LenientContentDropped:           true,
			UnknownSecurityPoliciesChildren: children,
		})
	}
	return nil
}
