package config

import "fmt"

// HostInboundVRFEnslavedNetdevs returns the kernel netdev names the daemon
// enslaves to an l3mdev VRF master, resolved through the same name rule as the
// junos-host iifname candidates (#6619). The #9637 ingress-zone judgement leaves
// them out of a host-inbound view's iifname scope: at LOCAL_IN, iifname names the
// VRF master, so a rule naming the enslaved device would match nothing.
func HostInboundVRFEnslavedNetdevs(cfg *Config) map[string]bool {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 || len(cfg.RoutingInstances) == 0 {
		return nil
	}
	tunNames := tunnelNameMapFn(cfg)
	return junosHostVRFEnslavedNetdevs(cfg, junosHostNetdevByRef(cfg, func(ifName string, unit *InterfaceUnit) string {
		return junosHostLinuxNameWith(cfg, ifName, unit, tunNames)
	}))
}

// junosHostNetdevByRef maps every physical interface ref and every unit ref
// ("<if>.<unit>") to its kernel netdev through name.
func junosHostNetdevByRef(cfg *Config, name func(ifName string, unit *InterfaceUnit) string) map[string]string {
	out := map[string]string{}
	for ifName, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		out[ifName] = name(ifName, nil)
		for un, unit := range iface.Units {
			if unit == nil {
				continue
			}
			out[fmt.Sprintf("%s.%d", ifName, un)] = name(ifName, unit)
		}
	}
	return out
}
