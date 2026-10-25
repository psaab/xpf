package config

import (
	"fmt"
	"sort"
)

const bridgeDevicePrefix = "br-"

// bridgeDomainBridgeDeviceNameIssue reports an invalid derived Linux bridge
// device name. It mirrors routingInstanceVRFDeviceNameIssue (#11391):
// "br-"+name must fit maxLinuxIfNameLen (15 bytes, IFNAMSIZ incl. NUL) and
// pass dev_valid_name (no slash, colon, ASCII whitespace, NUL).
func bridgeDomainBridgeDeviceNameIssue(name string) (deviceName, reason string) {
	if len(name) > maxLinuxIfNameLen-len(bridgeDevicePrefix) {
		deviceName = bridgeDevicePrefix + name
		return deviceName, fmt.Sprintf(
			"it is %d bytes, exceeding the Linux IFNAMSIZ limit of %d bytes",
			len(deviceName), maxLinuxIfNameLen)
	}
	for i := range len(name) {
		switch name[i] {
		case '/', ':', ' ', '\t', '\n', '\v', '\f', '\r', '\x00':
			deviceName = bridgeDevicePrefix + name
			return deviceName, fmt.Sprintf(
				"byte 0x%02x is rejected by Linux dev_valid_name", name[i])
		}
	}
	return "", ""
}

// validateBridgeDomainKernelNameAST refuses bridge domains whose name cannot
// become the br-<name> Linux device the runtime creates (#16792). Unlike
// routing instances, EVERY bridge domain creates that device (L2-only and
// IRB-backed alike), so no type exemption applies.
func validateBridgeDomainKernelNameAST(tree *ConfigTree, compiledNode *int) error {
	names := bridgeDomainNameUnionAST(tree, compiledNode)
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		deviceName, reason := bridgeDomainBridgeDeviceNameIssue(name)
		if reason != "" {
			return fmt.Errorf(
				"bridge-domains: bridge-domain %q derives invalid Linux bridge device name %q: %s (#16792)",
				name, deviceName, reason)
		}
	}
	return nil
}

func bridgeDomainNameUnionAST(tree *ConfigTree, compiledNode *int) map[string]struct{} {
	names := make(map[string]struct{})
	emitGenericExpandedBridgeDomainsAST(tree, names)
	emitNodeExpandedBridgeDomainsAST(tree, 0, names)
	emitNodeExpandedBridgeDomainsAST(tree, 1, names)
	if compiledNode != nil && *compiledNode != 0 && *compiledNode != 1 {
		emitNodeExpandedBridgeDomainsAST(tree, *compiledNode, names)
	}
	return names
}

func emitGenericExpandedBridgeDomainsAST(tree *ConfigTree, names map[string]struct{}) {
	clone := tree.Clone()
	if _, err := clone.ExpandGroupsNodeFallback15031(false); err != nil {
		return
	}
	for _, bdNode := range clone.FindChildren("bridge-domains") {
		collectBridgeDomainNamesAST(bdNode, names)
	}
}

func emitNodeExpandedBridgeDomainsAST(tree *ConfigTree, nodeID int, names map[string]struct{}) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	for _, bdNode := range clone.FindChildren("bridge-domains") {
		collectBridgeDomainNamesAST(bdNode, names)
	}
}

func collectBridgeDomainNamesAST(bdNode *Node, names map[string]struct{}) {
	if bdNode == nil {
		return
	}
	for _, child := range bdNode.Children {
		if len(child.Keys) == 0 || isApplyStatementNode(child) {
			continue
		}
		// Mirror compileBridgeDomains: a bare leaf with no content compiles
		// to nothing and is skipped, except the compact interface leaf
		// (Keys=[domain, interface, member...]) which does compile.
		if child.IsLeaf && !(len(child.Keys) > 1 && child.Keys[1] == "interface") {
			continue
		}
		if child.Keys[0] != "" {
			names[child.Keys[0]] = struct{}{}
		}
	}
}

// quarantineInvalidBridgeDomains16792 drops bridge domains whose derived
// br-<name> device is invalid, on tolerant paths only. Returns kept slice.
func quarantineInvalidBridgeDomains16792(cfg *Config) []*BridgeDomainConfig {
	kept := cfg.BridgeDomains[:0]
	for _, bd := range cfg.BridgeDomains {
		if bd == nil {
			kept = append(kept, bd)
			continue
		}
		deviceName, reason := bridgeDomainBridgeDeviceNameIssue(bd.Name)
		if reason != "" {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
				"bridge-domain %q QUARANTINED: derived Linux bridge device name %q is invalid: %s — "+
					"no bridge created and its members are not enslaved until the name is fixed (#16792)",
				bd.Name, deviceName, reason))
			cfg.QuarantinedBridgeDomains = append(cfg.QuarantinedBridgeDomains, bd)
			continue
		}
		kept = append(kept, bd)
	}
	return kept
}
