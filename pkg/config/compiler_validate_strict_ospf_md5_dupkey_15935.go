package config

import "fmt"

// validateOSPFMD5DuplicateKeys15935 rejects an OSPF MD5 key-id restated
// with a different non-empty key (#15935). The compiler coalesces same-ID
// fragments (empty-side fill for the #15715/#14414 inline+group shapes);
// two different non-empty keys for one ID are a conflicting duplicate
// Junos rejects. Without this gate the first key silently won and the
// operator's second key was dead with no diagnostic. Strict rejects
// naming area/interface/key-id; lenient warns (#1960) and keeps the
// first key deterministically. Identical-key restatements are legal.
func validateOSPFMD5DuplicateKeys15935(cfg *Config) error {
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
				if iface == nil {
					continue
				}
				for _, id := range iface.AuthMD5KeyConflictIDs {
					return fmt.Errorf("%sprotocols ospf area %s interface %s authentication md5 %d: duplicate key-id with different keys; remove the conflicting md5 %d statement",
						scope, area.ID, iface.Name, id, id)
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
