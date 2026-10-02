package config

// lo0AddressWarnings reports a commit-visible warning for configured lo0
// addresses on ordinary interfaces. Linux does not create a netdev named lo0
// from Junos loopback config; without a real device, the userspace helper drops
// the ifindex-0 row and must not classify its configured addresses as local.
func lo0AddressWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	var warnings []string
	for key, iface := range cfg.Interfaces.Interfaces {
		if iface == nil || (key != "lo0" && iface.Name != "lo0") || iface.Tunnel != nil {
			continue
		}
		hasAddress := false
		for _, unit := range iface.Units {
			if unit != nil && unit.Tunnel == nil && len(unit.Addresses) != 0 {
				hasAddress = true
				break
			}
		}
		if hasAddress {
			warnings = append(warnings,
				"interface lo0 has configured addresses but does not resolve to a Linux netdev on hosts that expose only lo; those addresses are not locally delivered by userspace-dp. Configure a real lo0 netdev/tunnel or use the Linux lo device.")
		}
	}
	return warnings
}
