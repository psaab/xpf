package config

import "fmt"

// validateOSPFMD5KeyIDs11794 rejects a compiled OSPF MD5 key-id outside FRR's
// 1..255 domain (#11794). SchemaValidate is strict on operator commits but is
// downgraded to a warning on tolerant Store.Load / SyncApply ingress; this
// compiler gate therefore also checks constructed configs and lets the
// tolerant path warn while the FRR renderer independently omits unsafe IDs.
func validateOSPFMD5KeyIDs11794(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, ospf *OSPFConfig) error {
		if ospf == nil {
			return nil
		}
		for _, area := range ospf.Areas {
			if area == nil {
				continue
			}
			for _, iface := range area.Interfaces {
				if iface == nil || iface.AuthType != "md5" {
					continue
				}
				if iface.AuthKeyID < 1 || iface.AuthKeyID > 255 {
					return fmt.Errorf("%sprotocols ospf area %s interface %s authentication md5 key-id %d is outside 1..255",
						scope, area.ID, iface.Name, iface.AuthKeyID)
				}
			}
		}
		return nil
	}
	if err := check("", cfg.Protocols.OSPF); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %q ", ri.Name), ri.OSPF); err != nil {
			return err
		}
	}
	return nil
}
