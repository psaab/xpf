package config

func runUniformGatesUnknownSecurityPoliciesChild12217(cfg *Config, opts compileOpts) error {
	if cfg == nil {
		return nil
	}
	if err := validateUnknownSecurityPoliciesChild12217(cfg); err != nil {
		if !opts.lenientUnknownPoliciesChild12217 {
			return err
		}
		cfg.Warnings = append(cfg.Warnings, toleratedUnknownSecurityPoliciesChildWarnings12217(cfg)...)
		// The omitted container could hold a deny rulebase. Reuse #12039's
		// synthetic global carrier so the userspace builder lowers it to the
		// unsupported sentinel and refuses the entire snapshot.
		cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, &Policy{
			Name:                  "xpf-unknown-policies-child-poison",
			Action:                PolicyDeny,
			terminalActions:       []PolicyAction{PolicyDeny},
			LenientContentDropped: true,
		})
	}
	return nil
}
