package config

import (
	"fmt"
	"sort"
)

const routingInstanceVRFDevicePrefix = "vrf-"

// routingInstanceVRFDeviceNameIssue reports an invalid derived Linux VRF device
// name. Valid names return empty strings so callers checking a large name set
// avoid allocating a derived name for every instance. Kernel netdev names are
// limited to 15 bytes (IFNAMSIZ includes the terminating NUL), and
// dev_valid_name rejects slash, colon, ASCII whitespace, and NUL. VRF names are
// not slash-folded like interface names.
func routingInstanceVRFDeviceNameIssue(name string) (deviceName, reason string) {
	if len(name) > maxLinuxIfNameLen-len(routingInstanceVRFDevicePrefix) {
		deviceName = routingInstanceVRFDevicePrefix + name
		return deviceName, fmt.Sprintf(
			"it is %d bytes, exceeding the Linux IFNAMSIZ limit of %d bytes",
			len(deviceName), maxLinuxIfNameLen)
	}
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '/', ':', ' ', '\t', '\n', '\v', '\f', '\r', '\x00':
			deviceName = routingInstanceVRFDevicePrefix + name
			return deviceName, fmt.Sprintf(
				"byte 0x%02x is rejected by Linux dev_valid_name", name[i])
		}
	}
	return "", ""
}

// validateRoutingInstanceKernelNameAST refuses routing instances that cannot
// become the vrf-<name> Linux device the runtime creates. It uses the same
// expanded name union as the #3855 and #9622 gates, so group and node-specific
// instances cannot bypass strict commit validation.
func validateRoutingInstanceKernelNameAST(tree *ConfigTree, compiledNode *int) error {
	names := routingInstanceNameUnionAST(tree, compiledNode)
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		deviceName, reason := routingInstanceVRFDeviceNameIssue(name)
		if reason != "" {
			return fmt.Errorf(
				"routing-instances: routing-instance %q derives invalid Linux VRF device name %q: %s (#11391)",
				name, deviceName, reason)
		}
	}
	return nil
}
