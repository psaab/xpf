package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ospfInterfaceArea11400 struct {
	areaKey    string
	areaID     string
	settingsV2 OSPFInterfaceUnion12186
	settingsV3 OSPFv3InterfaceUnion12186
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

// OSPFAreaIdentity16631 is the exported spelling-normalized area
// identity (#11400) for cross-package render/filter consumers
// (#16631). It is exactly ospfAreaIdentity11400.
func OSPFAreaIdentity16631(id string) string {
	return ospfAreaIdentity11400(id)
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
	check := func(scope, protocol string, seen map[string]ospfInterfaceArea11400, areaID, authoredName string, v2 *OSPFInterface, v3 *OSPFv3Interface) error {
		resolvedName := cfg.resolveKernelIfNameWith(authoredName, tunnelNames)
		if resolvedName == "" {
			return nil
		}
		areaKey := ospfAreaIdentity11400(areaID)
		state, ok := seen[resolvedName]
		if ok && state.areaKey != areaKey {
			return fmt.Errorf("%s %s interface %q resolves to Linux device %q and is configured in multiple areas (%q and %q); FRR supports one area per interface (#11400)",
				scope, protocol, authoredName, resolvedName, state.areaID, areaID)
		}
		if !ok {
			state.areaKey = areaKey
			state.areaID = areaID
		}
		var conflicts []string
		if v2 != nil {
			conflicts = state.settingsV2.Merge(v2)
		} else {
			conflicts = state.settingsV3.Merge(v3)
		}
		if len(conflicts) > 0 {
			return fmt.Errorf("%s %s interface %q resolves to Linux device %q in area %q has conflicting settings: %s (#12186)",
				scope, protocol, authoredName, resolvedName, state.areaID, strings.Join(conflicts, ", "))
		}
		seen[resolvedName] = state
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
				if err := check(scope, "OSPF", seen, area.ID, iface.Name, iface, nil); err != nil {
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
				if err := check(scope, "OSPFv3", seen, area.ID, iface.Name, nil, iface); err != nil {
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
