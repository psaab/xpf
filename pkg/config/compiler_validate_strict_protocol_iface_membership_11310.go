package config

import "fmt"

// protocolInterfaceMembershipMismatches11310 reports references whose protocol
// scope does not match the routing-instance owner of the referenced Linux
// device. It uses the same device resolution as membership ownership while
// leaving undeclared refs to the #9405 advisory.
func protocolInterfaceMembershipMismatches11310(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	refs := collectProtocolInterfaceRefs(cfg)
	if len(refs) == 0 {
		return nil
	}
	declared := declaredInterfaceIndex(cfg)
	refNames := make([]string, len(refs))
	for i, ref := range refs {
		refNames[i] = ref.ref
	}
	ownersByRef := RoutingInstanceMemberDeviceOwnersForRefs(cfg, refNames)

	var mismatches []string
	for _, ref := range refs {
		if ref.ref == "all" || unresolvedInterfaceRef(declared, ref.ref) != "" {
			continue
		}
		owner := ownersByRef[ref.ref]
		if ref.global {
			if owner == "" {
				continue
			}
			mismatches = append(mismatches, fmt.Sprintf(
				"%s %s interface %s resolves to a Linux device owned by routing-instance %q; global protocols cannot reference an instance-owned device (#11310)",
				ref.scope, ref.proto, ref.ref, owner))
			continue
		}
		if owner != "" && owner == ref.instance {
			continue
		}
		if owner == "" {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s %s interface %s resolves to a device with no routing-instance owner (default instance), but the protocol is scoped to %q (#11310)",
				ref.scope, ref.proto, ref.ref, ref.instance))
			continue
		}
		mismatches = append(mismatches, fmt.Sprintf(
			"%s %s interface %s resolves to a device owned by routing-instance %q, not protocol instance %q (#11310)",
			ref.scope, ref.proto, ref.ref, owner, ref.instance))
	}
	return mismatches
}
