package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// validateIPsecGatewayRoutingInstance12089 refuses IKE gateways whose
// EFFECTIVE local address resolves to a non-default routing-instance.
// strongSwan's IKE socket and xpf's parentless xfrmi are not scoped to that
// instance, so their outer traffic would use the wrong routing table (#12089).
//
// The effective address follows the renderer exactly: a VPN-level
// `local-address` wins first, then the gateway's `local-address`, and only
// then is an address derived from `external-interface` (resolveRemoteAddr in
// pkg/ipsec/policy.go, then PrepareConfig/policy_addr.go resolution). A gate
// that inspected external-interface alone would both let the bug through
// (VR-owned local-address with a default external-interface) and refuse valid
// configs (a default-instance local-address overriding a VR external-interface).
func validateIPsecGatewayRoutingInstance12089(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil ||
		(len(cfg.Security.IPsec.Gateways) == 0 && len(cfg.Security.IPsec.VPNs) == 0) {
		return nil, nil
	}

	gatewayNames := make([]string, 0, len(cfg.Security.IPsec.Gateways))
	for name := range cfg.Security.IPsec.Gateways {
		gatewayNames = append(gatewayNames, name)
	}
	sort.Strings(gatewayNames)

	vpnNames := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	gatewayVPNs := make(map[string][]string)
	for _, vpnName := range vpnNames {
		vpn := cfg.Security.IPsec.VPNs[vpnName]
		if vpn != nil && vpn.Gateway != "" {
			gatewayVPNs[vpn.Gateway] = append(gatewayVPNs[vpn.Gateway], vpnName)
		}
	}

	tunnelNames := cfg.TunnelNameMap()
	instanceOwners := ipsecGatewayRoutingInstanceOwners12089(cfg, tunnelNames)
	addressIndex := ipsecAddressUnitIndex12089(cfg, tunnelNames)
	quarantined := ipsecGatewayQuarantinedDevices12089(cfg, lenient)
	var warnings []string
	report := func(subject, source string, instances []string) error {
		if len(instances) == 0 {
			return nil
		}
		instanceList := strings.Join(instances, ", ")
		if !lenient {
			return fmt.Errorf(
				"%s %s resolves to routing-instance %q, but IKE/ESP outer traffic is not scoped to that routing table; commit refused (#12089)",
				subject, source, instanceList)
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s %s resolves to routing-instance %q, but IKE/ESP outer traffic is not scoped to that routing table; existing config may route IKE/ESP via the wrong table (#12089)",
			subject, source, instanceList))
		return nil
	}
	for _, name := range gatewayNames {
		gateway := cfg.Security.IPsec.Gateways[name]
		if gateway == nil {
			continue
		}
		subject := fmt.Sprintf("ipsec gateway %q", name)
		referencing := gatewayVPNs[name]
		gatewayAddressMemo := make(map[string][]string)
		if len(referencing) == 0 {
			instances, source := ipsecGatewayScopedInstances12089(
				cfg, tunnelNames, instanceOwners, quarantined, addressIndex, gatewayAddressMemo, gateway, nil)
			if err := report(subject, source, instances); err != nil {
				return nil, err
			}
			continue
		}
		for _, vpnName := range referencing {
			vpn := cfg.Security.IPsec.VPNs[vpnName]
			instances, source := ipsecGatewayScopedInstances12089(
				cfg, tunnelNames, instanceOwners, quarantined, addressIndex, gatewayAddressMemo, gateway, vpn)
			if err := report(subject+" "+fmt.Sprintf("vpn %q", vpnName), source, instances); err != nil {
				return nil, err
			}
		}
	}

	// A VPN may use an inline gateway endpoint (or no gateway object), but its
	// local-address still becomes swanctl local_addrs. Check those sources too;
	// there is no gateway external-interface from which to derive a fallback.
	for _, name := range vpnNames {
		vpn := cfg.Security.IPsec.VPNs[name]
		if vpn == nil || vpn.LocalAddr == "" {
			continue
		}
		if gateway := cfg.Security.IPsec.Gateways[vpn.Gateway]; vpn.Gateway != "" && gateway != nil {
			continue // handled with the referenced gateway above
		}
		devices := ipsecLocalAddressDevices12089(addressIndex, vpn.LocalAddr)
		instances := ipsecScopedInstances12089(instanceOwners, quarantined, devices)
		if err := report(fmt.Sprintf("ipsec vpn %q", name),
			fmt.Sprintf("local-address %q", vpn.LocalAddr), instances); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// ipsecGatewayScopedInstances12089 resolves one (gateway, vpn) pair's
// effective local address to owning instances. An explicit local-address
// (vpn first, then gateway) maps through the validation's shared address index;
// only when neither is set does the external-interface derivation apply.
// Devices under a recorded #11060 conflict read as unowned: the dual-claim gate
// owns that diagnostic, and tolerant quarantine removes every conflicting
// membership. The per-gateway memo avoids re-resolving a shared gateway source
// for each referencing VPN.
func ipsecGatewayScopedInstances12089(cfg *Config, tunnelNames map[string]string, instanceOwners map[string]string, quarantined map[string]struct{}, addressIndex map[string][]string, addressMemo map[string][]string, gateway *IPsecGateway, vpn *IPsecVPN) ([]string, string) {
	localAddress := ""
	if vpn != nil && vpn.LocalAddr != "" {
		localAddress = vpn.LocalAddr
	} else if gateway.LocalAddress != "" {
		localAddress = gateway.LocalAddress
	}
	if localAddress != "" {
		key := ipsecAddressIndexKey12089(localAddress)
		source := fmt.Sprintf("local-address %q", localAddress)
		if key != "" {
			if instances, found := addressMemo[key]; found {
				return instances, source
			}
		}
		devices := ipsecLocalAddressDevices12089(addressIndex, localAddress)
		instances := ipsecScopedInstances12089(instanceOwners, quarantined, devices)
		if key != "" {
			addressMemo[key] = instances
		}
		return instances, source
	}
	devices := ipsecGatewayExternalDevices12089(cfg, tunnelNames, gateway)
	return ipsecScopedInstances12089(instanceOwners, quarantined, devices),
		fmt.Sprintf("external-interface %q", gateway.ExternalIface)
}

// ipsecScopedInstances12089 maps devices to their owning instances, dropping
// devices in a recorded #11060 conflict. The sorted names keep the diagnostic
// deterministic when a bare external-interface fans across instances.
func ipsecScopedInstances12089(instanceOwners map[string]string, quarantined map[string]struct{}, devices []string) []string {
	seen := make(map[string]struct{})
	var instances []string
	for _, device := range devices {
		if _, conflicted := quarantined[device]; conflicted {
			continue
		}
		instance := instanceOwners[device]
		if instance == "" {
			continue
		}
		if _, duplicate := seen[instance]; duplicate {
			continue
		}
		seen[instance] = struct{}{}
		instances = append(instances, instance)
	}
	sort.Strings(instances)
	return instances
}

// ipsecGatewayQuarantinedDevices12089 returns devices excluded from #12089
// ownership checks. Dual-claim evidence owns #11060 on strict and tolerant
// paths. On tolerant loads, role-fenced members are also excluded because
// quarantineRIRoleMembers removes them after the uniform gates.
func ipsecGatewayQuarantinedDevices12089(cfg *Config, includeRoleQuarantine bool) map[string]struct{} {
	devices := make(map[string]struct{})
	if cfg == nil {
		return devices
	}
	tunnelNames := cfg.TunnelNameMap()
	for _, conflict := range RoutingInstanceMemberDeviceConflicts(cfg, tunnelNames) {
		if conflict.LinuxName != "" {
			devices[conflict.LinuxName] = struct{}{}
		}
	}
	for _, conflict := range cfg.QuarantinedRIMemberDeviceConflicts {
		if conflict.LinuxName != "" {
			devices[conflict.LinuxName] = struct{}{}
		}
	}
	if !includeRoleQuarantine {
		return devices
	}
	lifelines := HostInboundLifelineSet(cfg)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		for _, key := range RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri) {
			if key.LinuxName != "" &&
				(IsManagementIfName(key.LinuxName) || HostInboundLifelineInterface(key.InterfaceKey, lifelines)) {
				devices[key.LinuxName] = struct{}{}
			}
		}
	}
	for _, claim := range cfg.QuarantinedRIMemberPrimaryClaims {
		if claim.LinuxName != "" &&
			(IsManagementIfName(claim.LinuxName) || HostInboundLifelineInterface(claim.InterfaceKey, lifelines)) {
			devices[claim.LinuxName] = struct{}{}
		}
	}
	return devices
}

// ipsecAddressUnitIndex12089 builds a single normalized host-address to kernel
// device index for all configured interface addresses and VRRP virtual
// addresses. Local-address lookups then scale with VPN count, not VPNs × units.
func ipsecAddressUnitIndex12089(cfg *Config, tunnelNames map[string]string) map[string][]string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	index := make(map[string][]string)
	record := func(address, device string) {
		key := ipsecAddressIndexKey12089(address)
		if key == "" || device == "" {
			return
		}
		for _, existing := range index[key] {
			if existing == device {
				return
			}
		}
		index[key] = append(index[key], device)
	}
	baseNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for base := range cfg.Interfaces.Interfaces {
		baseNames = append(baseNames, base)
	}
	sort.Strings(baseNames)
	for _, base := range baseNames {
		ifc := cfg.Interfaces.Interfaces[base]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil {
				continue
			}
			device := cfg.resolveKernelIfNameWith(fmt.Sprintf("%s.%d", base, unitNum), tunnelNames)
			record(unit.PrimaryAddress, device)
			record(unit.PreferredAddress, device)
			for _, address := range unit.Addresses {
				record(address, device)
			}
			for _, group := range unit.VRRPGroups {
				if group == nil {
					continue
				}
				for _, address := range group.VirtualAddresses {
					record(address, device)
				}
			}
		}
	}
	return index
}

func ipsecAddressIndexKey12089(value string) string {
	ip := ipsecParseConfiguredAddress12089(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// ipsecLocalAddressDevices12089 looks up an explicit source address in the
// validation's shared address index. CIDR suffixes and non-canonical IPv6
// spellings normalize to the same host key.
func ipsecLocalAddressDevices12089(index map[string][]string, localAddress string) []string {
	if key := ipsecAddressIndexKey12089(localAddress); key != "" {
		return index[key]
	}
	return nil
}

// ipsecGatewayRoutingInstanceOwners12089 uses the shared RI member device
// resolver so VLAN IDs, RETH aliases, tunnel devices, and tolerant-load
// primary claims agree with kernel binding and userspace membership maps.
func ipsecGatewayRoutingInstanceOwners12089(cfg *Config, tunnelNames map[string]string) map[string]string {
	owners := make(map[string]string)
	instances := make([]*RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" && ri.InstanceType != "forwarding" && !IsReservedRoutingInstanceName(ri.Name) {
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
		if claim.LinuxName == "" || claim.Instance == "" ||
			ipsecGatewayInstanceIsForwarding12089(cfg, claim.Instance) ||
			IsReservedRoutingInstanceName(claim.Instance) {
			continue
		}
		if _, exists := owners[claim.LinuxName]; !exists {
			owners[claim.LinuxName] = claim.Instance
		}
	}
	return owners
}

// ipsecGatewayInstanceIsForwarding12089 reports whether the named instance is
// a forwarding instance. The daemon does not bind those members to VRF
// devices, so #11312 owns their diagnostic rather than the #12089 gateway gate.
func ipsecGatewayInstanceIsForwarding12089(cfg *Config, instance string) bool {
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == instance {
			return ri.InstanceType == "forwarding"
		}
	}
	return false
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
