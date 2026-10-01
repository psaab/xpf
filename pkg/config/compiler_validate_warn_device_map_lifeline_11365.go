package config

import (
	"fmt"
	"sort"
)

// validateDeviceMapHostInboundLifelineWarnings11365 reports device-map NICs
// whose management-name class assigns them to vrf-mgmt while their actual
// host-inbound lifeline identity does not exempt them from zone denies.
func validateDeviceMapHostInboundLifelineWarnings11365(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) == 0 {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	names := make([]string, 0, len(cfg.Chassis.DeviceMap.Entries))
	for _, entry := range cfg.Chassis.DeviceMap.Entries {
		if entry.LogicalName == "" {
			continue
		}
		_, iface, declared := LookupInterfaceByLinuxName(cfg, entry.LogicalName)
		if declared && iface != nil && IsManagementIfName(entry.LogicalName) &&
			!HostInboundLifelineInterface(entry.LogicalName, lifelines) {
			names = append(names, entry.LogicalName)
		}
	}
	sort.Strings(names)
	warnings := make([]string, 0, len(names))
	previous := ""
	for _, name := range names {
		if name == previous {
			continue
		}
		previous = name
		warnings = append(warnings, fmt.Sprintf(
			"chassis device-map interface %q is assigned to vrf-mgmt by its management-name class but is not host-inbound lifeline-exempt; transit fencing does not exempt it from host-inbound zone denies, so configure the interface as an explicit cluster control/fabric lifeline if that exemption is intended (#11365)",
			name))
	}
	return warnings
}
