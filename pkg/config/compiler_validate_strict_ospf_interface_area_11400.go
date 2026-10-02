package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ospfInterfaceArea11400 struct {
	areaKey string
	areaID  string
}

// ospfAreaIdentity11400 normalizes FRR's dotted-quad and integer spellings of
// the same 32-bit area ID. Invalid tolerant-path IDs remain distinct by their
// authored spelling; the existing area validator handles their strict error.
func ospfAreaIdentity11400(id string) string {
	if !strings.Contains(id, ":") {
		if ip := net.ParseIP(id); ip != nil && ip.To4() != nil {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(ip.To4())), 10)
		}
		if value, err := strconv.ParseUint(id, 10, 32); err == nil {
			return strconv.FormatUint(value, 10)
		}
	}
	return "raw:" + id
}

// validateOSPFAreaInterfaceReuse11400 rejects a resolved Linux interface that
// belongs to multiple OSPF areas within one routing domain. FRR stores a single
// area activation per interface, so multiple area commands silently overwrite
// one another. OSPFv2 and OSPFv3 and each routing domain have independent
// membership namespaces.
func validateOSPFAreaInterfaceReuse11400(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	tunnelNames := cfg.TunnelNameMap()
	check := func(scope, protocol string, seen map[string]ospfInterfaceArea11400, areaID, authoredName string) error {
		resolvedName := cfg.resolveKernelIfNameWith(authoredName, tunnelNames)
		if resolvedName == "" {
			return nil
		}
		areaKey := ospfAreaIdentity11400(areaID)
		if first, ok := seen[resolvedName]; ok {
			if first.areaKey != areaKey {
				return fmt.Errorf("%s %s interface %q resolves to Linux device %q and is configured in multiple areas (%q and %q); FRR supports one area per interface (#11400)",
					scope, protocol, authoredName, resolvedName, first.areaID, areaID)
			}
			return nil
		}
		seen[resolvedName] = ospfInterfaceArea11400{areaKey: areaKey, areaID: areaID}
		return nil
	}
	checkV2 := func(scope string, ospf *OSPFConfig) error {
		if ospf == nil {
			return nil
		}
		seen := make(map[string]ospfInterfaceArea11400)
		for _, area := range ospf.Areas {
			if area == nil {
				continue
			}
			for _, iface := range area.Interfaces {
				if iface == nil {
					continue
				}
				if err := check(scope, "OSPF", seen, area.ID, iface.Name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	checkV3 := func(scope string, ospf *OSPFv3Config) error {
		if ospf == nil {
			return nil
		}
		seen := make(map[string]ospfInterfaceArea11400)
		for _, area := range ospf.Areas {
			if area == nil {
				continue
			}
			for _, iface := range area.Interfaces {
				if iface == nil {
					continue
				}
				if err := check(scope, "OSPFv3", seen, area.ID, iface.Name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	checkScope := func(scope string, ospf *OSPFConfig, ospf3 *OSPFv3Config) error {
		if err := checkV2(scope, ospf); err != nil {
			return err
		}
		return checkV3(scope, ospf3)
	}
	if err := checkScope("protocols", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := checkScope(fmt.Sprintf("routing-instances %q protocols", ri.Name), ri.OSPF, ri.OSPFv3); err != nil {
			return err
		}
	}
	return nil
}
