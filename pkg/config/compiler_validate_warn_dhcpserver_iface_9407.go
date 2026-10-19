package config

import (
	"fmt"
	"strings"
)

// validateDHCPServerInterfaceRefWarnings is the ValidateConfig twin of
// the #15206 strict gate.
//
// `system services dhcp-local-server group <g> interface <ref>` (and the
// DHCPv6 twin) names the segment Kea serves. The daemon resolves it to a
// kernel device through Config.ResolveKernelIfName (#9407), and that
// resolver has an honest limit: when the ref names a unit the config
// never declares, it cannot know what device was meant and returns the
// ref verbatim — `reth1.7` stays `reth1.7`, which is not a device.
//
// #9407 left this advisory-only, saying "the segment gets no leases".
// That understated the blast radius (#15206, A17-03): Kea validates the
// rendered file as one unit, so the phantom device makes it refuse the
// whole file and every pool of the family stops serving. The strict
// commit / commit-check path therefore hard-rejects the ref
// (validateDHCPServerInterfaceRefStrict); this advisory remains because
// the alarm surfaces recompute ValidateConfig from the ACTIVE config
// rather than reading cfg.Warnings (the #4788/#4785 doctrine), so a box
// already carrying the bad ref — committed by an older build, loaded
// leniently per #1960 — still hears about it, now with the correct
// whole-family consequence.
//
// The ref walk is shared with the strict gate
// (dhcpServerGroupIfaceRefs15206) and families/groups are walked in
// sorted order, so the message set is deterministic and the two
// surfaces can never disagree about which refs exist.
func validateDHCPServerInterfaceRefWarnings(cfg *Config) []string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	refs := dhcpServerGroupIfaceRefs15206(cfg)
	if len(refs) == 0 {
		return nil
	}
	declared := declaredInterfaceIndex(cfg)
	lifelines := HostInboundLifelineSet(cfg)
	var warnings []string
	for _, r := range refs {
		if strings.HasSuffix(r.ref, "*") || HostInboundLifelineInterface(r.ref, lifelines) {
			continue
		}
		reason := unresolvedInterfaceRef(declared, r.ref)
		if reason == "" {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"system services %s group %s interface %s %s — Kea will be "+
				"given a device name the kernel does not have; Kea refuses "+
				"to load the rendered file, so every pool of the %s family "+
				"stops serving, not just this segment (#15206).",
			r.family, r.group, r.ref, reason, r.family))
	}
	return warnings
}
