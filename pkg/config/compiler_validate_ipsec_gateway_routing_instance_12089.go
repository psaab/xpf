package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// validateIPsecGatewayRoutingInstance12089 refuses IKE gateways whose
// external-interface resolves to a non-default routing-instance. strongSwan's
// IKE socket and xpf's parentless xfrmi are not scoped to that instance, so
// their outer traffic would use the wrong routing table (#12089).
func validateIPsecGatewayRoutingInstance12089(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil || len(cfg.Security.IPsec.Gateways) == 0 {
		return nil, nil
	}

	gatewayNames := make([]string, 0, len(cfg.Security.IPsec.Gateways))
	for name := range cfg.Security.IPsec.Gateways {
		gatewayNames = append(gatewayNames, name)
	}
	sort.Strings(gatewayNames)

	tunnelNames := cfg.TunnelNameMap()
	instanceOwners := ipsecGatewayRoutingInstanceOwners12089(cfg, tunnelNames)
	var warnings []string
	for _, name := range gatewayNames {
		gateway := cfg.Security.IPsec.Gateways[name]
		if gateway == nil || gateway.ExternalIface == "" {
			continue
		}
		instances := make(map[string]struct{})
		for _, device := range ipsecGatewayExternalDevices12089(cfg, tunnelNames, gateway) {
			if instance := instanceOwners[device]; instance != "" {
				instances[instance] = struct{}{}
			}
		}
		if len(instances) == 0 {
			continue
		}
		instanceNames := make([]string, 0, len(instances))
		for instance := range instances {
			instanceNames = append(instanceNames, instance)
		}
		sort.Strings(instanceNames)
		instanceList := strings.Join(instanceNames, ", ")
		if !lenient {
			return nil, fmt.Errorf(
				"ipsec gateway %q external-interface %q resolves to routing-instance %q, but IKE/ESP outer traffic is not scoped to that routing table; commit refused (#12089)",
				name, gateway.ExternalIface, instanceList)
		}
		warnings = append(warnings, fmt.Sprintf(
			"ipsec gateway %q external-interface %q resolves to routing-instance %q, but IKE/ESP outer traffic is not scoped to that routing table; existing config may route IKE/ESP via the wrong table (#12089)",
			name, gateway.ExternalIface, instanceList))
	}
	return warnings, nil
}

// ipsecGatewayRoutingInstanceOwners12089 uses the shared RI member device
// resolver so VLAN IDs, RETH aliases, tunnel devices, and tolerant-load
// primary claims agree with kernel binding and userspace membership maps.
func ipsecGatewayRoutingInstanceOwners12089(cfg *Config, tunnelNames map[string]string) map[string]string {
	owners := make(map[string]string)
	instances := make([]*RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" && !IsReservedRoutingInstanceName(ri.Name) {
			instances = append(instances, ri)
		}
	}
	sort.SliceStable(instances, func(i, j int) bool {
		return instances[i].Name < instances[j].Name
	})
	for _, ri := range instances {
		for _, device := range RoutingInstanceMemberLinuxNamesForInstance(cfg, tunnelNames, ri) {
			if device == "" {
				continue
			}
			if _, exists := owners[device]; !exists {
				owners[device] = ri.Name
			}
		}
	}
	for _, claim := range routingInstanceTunnelDeviceClaims(cfg) {
		if claim.LinuxName == "" || claim.Instance == "" || IsReservedRoutingInstanceName(claim.Instance) {
			continue
		}
		if _, exists := owners[claim.LinuxName]; !exists {
			owners[claim.LinuxName] = claim.Instance
		}
	}
	return owners
}

// ipsecGatewayExternalDevices12089 mirrors policy_addr's configured address
// selection for an external-interface. A bare reference can resolve to a
// nonzero logical unit; when remote family is unknown, retain the first
// usable unit for each possible family so a DNS-dependent choice cannot evade
// the strict commit gate.
func ipsecGatewayExternalDevices12089(cfg *Config, tunnelNames map[string]string, gateway *IPsecGateway) []string {
	if cfg == nil || gateway == nil || gateway.ExternalIface == "" {
		return nil
	}
	external := gateway.ExternalIface
	split := cfg.SplitInterfaceUnitRef(external)
	refs := make([]string, 0, 3)
	if split.HasUnit {
		refs = append(refs, external)
	} else if ifc := cfg.Interfaces.Interfaces[split.Base]; ifc != nil {
		if gateway.LocalAddress != "" {
			refs = append(refs, ipsecAddressUnitRefs12089(split.Base, ifc, gateway.LocalAddress)...)
		}
		if len(refs) == 0 && gateway.LocalAddress == "" {
			for _, family := range ipsecGatewayRemoteFamilies12089(gateway) {
				unitNum, found := ipsecFirstAddressedUnit12089(ifc, family)
				if !found && family != 0 {
					unitNum, found = ipsecFirstAddressedUnit12089(ifc, 0)
				}
				if found {
					refs = append(refs, fmt.Sprintf("%s.%d", split.Base, unitNum))
				}
			}
		}
	}
	if len(refs) == 0 {
		refs = append(refs, external)
	}

	devices := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		device := cfg.resolveKernelIfNameWith(ref, tunnelNames)
		if device == "" {
			continue
		}
		if _, duplicate := seen[device]; duplicate {
			continue
		}
		seen[device] = struct{}{}
		devices = append(devices, device)
	}
	return devices
}

func ipsecGatewayRemoteFamilies12089(gateway *IPsecGateway) []int {
	if family := ipsecAddressFamily12089(gateway.Address); family != 0 || gateway.Address != "" {
		return []int{family}
	}
	if family := ipsecAddressFamily12089(gateway.DynamicHostname); family != 0 {
		return []int{family}
	}
	if gateway.DynamicHostname != "" {
		return []int{4, 6, 0}
	}
	return []int{0}
}

func ipsecAddressFamily12089(value string) int {
	ip := net.ParseIP(value)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func ipsecFirstAddressedUnit12089(ifc *InterfaceConfig, family int) (int, bool) {
	unitNums := make([]int, 0, len(ifc.Units))
	for unitNum := range ifc.Units {
		unitNums = append(unitNums, unitNum)
	}
	sort.Ints(unitNums)
	for _, unitNum := range unitNums {
		if ipsecUnitHasAddressFamily12089(ifc.Units[unitNum], family) {
			return unitNum, true
		}
	}
	return 0, false
}

func ipsecUnitHasAddressFamily12089(unit *InterfaceUnit, family int) bool {
	if unit == nil {
		return false
	}
	if ipsecAddressMatchesFamily12089(unit.PrimaryAddress, family) ||
		ipsecAddressMatchesFamily12089(unit.PreferredAddress, family) {
		return true
	}
	for _, address := range unit.Addresses {
		if ipsecAddressMatchesFamily12089(address, family) {
			return true
		}
	}
	return false
}

func ipsecAddressMatchesFamily12089(value string, family int) bool {
	ip := ipsecParseConfiguredAddress12089(value)
	if ip == nil || (!ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast()) {
		return false
	}
	switch family {
	case 4:
		return ip.To4() != nil && !ip.IsLinkLocalUnicast()
	case 6:
		return ip.To4() == nil
	default:
		return ip.IsGlobalUnicast()
	}
}

func ipsecParseConfiguredAddress12089(value string) net.IP {
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	ip, _, err := net.ParseCIDR(value)
	if err != nil {
		return nil
	}
	return ip
}

func ipsecAddressUnitRefs12089(base string, ifc *InterfaceConfig, localAddress string) []string {
	target := ipsecParseConfiguredAddress12089(localAddress)
	if target == nil {
		return nil
	}
	unitNums := make([]int, 0, len(ifc.Units))
	for unitNum := range ifc.Units {
		unitNums = append(unitNums, unitNum)
	}
	sort.Ints(unitNums)
	var refs []string
	for _, unitNum := range unitNums {
		unit := ifc.Units[unitNum]
		if unit == nil {
			continue
		}
		matches := ipsecParseConfiguredAddress12089(unit.PrimaryAddress)
		if matches != nil && matches.Equal(target) {
			refs = append(refs, fmt.Sprintf("%s.%d", base, unitNum))
			continue
		}
		matches = ipsecParseConfiguredAddress12089(unit.PreferredAddress)
		if matches != nil && matches.Equal(target) {
			refs = append(refs, fmt.Sprintf("%s.%d", base, unitNum))
			continue
		}
		for _, address := range unit.Addresses {
			matches = ipsecParseConfiguredAddress12089(address)
			if matches != nil && matches.Equal(target) {
				refs = append(refs, fmt.Sprintf("%s.%d", base, unitNum))
				break
			}
		}
	}
	return refs
}
