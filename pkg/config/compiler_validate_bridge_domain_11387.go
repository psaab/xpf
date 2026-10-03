package config

import (
	"fmt"
	"net/netip"
)

type bridgeDomainMemberKey11387 struct {
	interfaceName string
	vlanID        int
}

// validateBridgeDomainMembership11387 checks that each explicit bridge port
// resolves to a configured tagged unit whose VID is declared by that domain,
// that a VID names only one bridge domain, and that a zoned inet VLAN included
// in a bridge domain was explicitly named as a member. Networkd otherwise
// cannot distinguish same-VID units on separate trunks.
func validateBridgeDomainMembership11387(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	vidDomain := make(map[int]string)
	for _, bd := range cfg.BridgeDomains {
		if bd == nil {
			continue
		}
		for _, vid := range bd.VlanIDs {
			if owner, ok := vidDomain[vid]; ok && owner != bd.Name {
				return fmt.Errorf("bridge-domain %s vlan-id %d is also declared by bridge-domain %s; a VLAN ID may belong to only one bridge domain", bd.Name, vid, owner)
			}
			vidDomain[vid] = bd.Name
		}
	}

	members := make(map[bridgeDomainMemberKey11387]string)
	for _, bd := range cfg.BridgeDomains {
		if bd == nil {
			continue
		}
		declaredVIDs := make(map[int]bool, len(bd.VlanIDs))
		for _, vid := range bd.VlanIDs {
			declaredVIDs[vid] = true
		}
		for _, raw := range bd.Members {
			ref := cfg.SplitInterfaceUnitRef(raw)
			if !ref.HasUnit || ref.UnitTok == "" {
				return fmt.Errorf("bridge-domain %s interface %q must name a tagged logical unit (for example ge-0/0/0.0)", bd.Name, raw)
			}
			unitNumber, _, err := CanonicalLogicalUnit(ref.UnitTok)
			if err != nil {
				return fmt.Errorf("bridge-domain %s interface %q has invalid logical unit number: %v", bd.Name, raw, err)
			}
			ifc := cfg.Interfaces.Interfaces[ref.Base]
			if ifc == nil {
				return fmt.Errorf("bridge-domain %s interface %q does not reference a configured interface", bd.Name, raw)
			}
			unit := ifc.Units[unitNumber]
			if unit == nil {
				return fmt.Errorf("bridge-domain %s interface %q does not reference a configured unit", bd.Name, raw)
			}
			vid := unit.VlanID
			if !ifc.VlanTagging || vid < 1 || vid > 4094 {
				return fmt.Errorf("bridge-domain %s interface %q resolves to a unit with no VLAN ID (expected a tagged VLAN unit)", bd.Name, raw)
			}
			if !declaredVIDs[vid] {
				return fmt.Errorf("bridge-domain %s interface %q uses VLAN ID %d, which is not in vlan-id-list", bd.Name, raw, vid)
			}
			key := bridgeDomainMemberKey11387{interfaceName: LinuxIfName(ref.Base), vlanID: vid}
			if owner, ok := members[key]; ok && owner != bd.Name {
				return fmt.Errorf("interface %q is a member of both bridge-domain %s and bridge-domain %s", raw, owner, bd.Name)
			}
			members[key] = bd.Name
		}
	}

	zoneByInterface := InterfaceZoneMap(cfg)
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for unitNumber, unit := range ifc.Units {
			if unit == nil || unit.VlanID < 1 || vidDomain[unit.VlanID] == "" {
				continue
			}
			// Keep this tied to authored family inet, not the presence of an
			// IPv4 address or DHCP node: filter-only and other no-address inet
			// units are still zoned IPv4 interfaces.
			hasInet := unit.FamilyInet
			if !hasInet {
				hasInet = unit.DHCP
				for _, rawAddress := range unit.Addresses {
					prefix, err := netip.ParsePrefix(rawAddress)
					if err == nil && prefix.Addr().Is4() {
						hasInet = true
						break
					}
				}
			}
			if !hasInet {
				continue
			}
			logicalName := fmt.Sprintf("%s.%d", ifName, unitNumber)
			if _, zoned := zoneByInterface[logicalName]; !zoned {
				continue
			}
			key := bridgeDomainMemberKey11387{interfaceName: LinuxIfName(ifName), vlanID: unit.VlanID}
			if _, explicit := members[key]; !explicit {
				return fmt.Errorf("zoned inet unit %s (VLAN ID %d) is listed by bridge-domain %s but has no explicit bridge-domain interface member statement", logicalName, unit.VlanID, vidDomain[unit.VlanID])
			}
		}
	}
	return nil
}

func runUniformGatesBridgeDomainMembership11387(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateBridgeDomainMembership11387(cfg); err != nil {
		if opts.lenientBridgeDomainVlanID {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("bridge-domain membership (downgraded to warning on tolerant path): %v", err))
			return nil
		}
		return err
	}
	return nil
}
