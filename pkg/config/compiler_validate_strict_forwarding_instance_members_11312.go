package config

import (
	"fmt"
	"strings"
)

// validateForwardingInstanceMembersStrict rejects interface membership under
// instance-type forwarding (#11312). The daemon does not bind forwarding
// instances to VRF devices, so their interfaces remain in the default instance;
// placing their connected prefixes or ingress domain in the forwarding table
// would make kernel and userspace routing disagree.
func validateForwardingInstanceMembersStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType != "forwarding" || len(ri.Interfaces) == 0 {
			continue
		}
		return fmt.Errorf(
			"routing-instances %s interfaces %s: interface membership is not supported under "+
				"instance-type forwarding because the daemon leaves these devices in the default "+
				"routing instance; userspace assigning their connected routes or ingress domain "+
				"to the forwarding table would split the planes. Use instance-type virtual-router "+
				"(or vrf) for interface members, or keep the forwarding instance statics-only (#11312)",
			ri.Name, strings.Join(ri.Interfaces, ", "))
	}
	return nil
}

// runUniformGatesForwardingInstanceMembers11312 applies the strict commit gate
// and downgrades it to an operator-visible warning on tolerant load and
// peer-sync paths (#1960). Userspace member maps skip forwarding instances, so
// the warning path remains aligned with the daemon's default-instance binding.
func runUniformGatesForwardingInstanceMembers11312(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateForwardingInstanceMembersStrict(cfg); err != nil {
		if opts.lenientForwardingInstanceMembers {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("forwarding-instance interface membership (downgraded to warning on tolerant path): %v", err))
			return nil
		}
		return err
	}
	return nil
}
