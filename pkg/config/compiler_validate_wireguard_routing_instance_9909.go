package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateWireguardRoutingInstance9909 closes the commit-time hole between
// the persistent wgN device and the userspace control socket (#9909). The
// routing manager can put wgN in a routing-instance, and the userspace WG
// control thread now binds its outer UDP socket to the corresponding
// `vrf-<instance>` device (#10196). Forwarding instances have no VRF device,
// so that unsupported scope remains refused. A tolerant load warns and
// removes an unsupported tunnel and its matching RI membership from the
// compiled config before routing or snapshot consumers can act on it.
//
// Both scope paths are deliberate:
//   - TunnelConfig.RoutingInstance comes from `tunnel routing-instance`.
//   - RoutingInstanceConfig.Interfaces is the `routing-instances <ri>
//     interface <wg>` membership path. The daemon copies this into
//     TunnelConfig.RIListMember while collecting applied tunnels, but this
//     compiler gate must catch it before that later runtime pass.
func validateWireguardRoutingInstance9909(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil, nil
	}

	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	// Lazy TunnelNameMap: built at most once, only when a WireGuard scope
	// check actually needs membership expansion. Configs without WG tunnels
	// (the common case) pay zero walks; explicit-stanza violations
	// short-circuit without building.
	var tunMap map[string]string
	tunMapReady := false
	getTunMap := func() map[string]string {
		if !tunMapReady {
			tunMap = tunnelNameMapFn(cfg)
			tunMapReady = true
		}
		return tunMap
	}
	scopesFor := func(tc *TunnelConfig) []string {
		if tc == nil {
			return nil
		}
		if tc.RoutingInstance != "" || tc.RIListMember != "" || len(cfg.RoutingInstances) == 0 {
			return wireguardRoutingInstances9909(cfg, nil, tc)
		}
		return wireguardRoutingInstances9909(cfg, getTunMap(), tc)
	}

	type deviceScopeClaim struct {
		ifName  string
		unitNum int
		tc      *TunnelConfig
		scopes  map[string]struct{}
	}
	deviceClaims := make(map[string]*deviceScopeClaim)
	recordDeviceScopes := func(ifName string, unitNum int, parent, tc *TunnelConfig, scopes []string) {
		if tc == nil || len(scopes) == 0 {
			return
		}
		device := tc.Name
		if parent != nil && parent.Mode == "wireguard" && parent.Name != "" {
			device = parent.Name
		}
		if device == "" {
			return
		}
		claim := deviceClaims[device]
		if claim == nil {
			claim = &deviceScopeClaim{
				ifName: ifName, unitNum: unitNum, tc: tc,
				scopes: make(map[string]struct{}, len(scopes)),
			}
			deviceClaims[device] = claim
		}
		for _, scope := range scopes {
			claim.scopes[scope] = struct{}{}
		}
	}

	violations := make([]wireguardRoutingInstanceViolation9909, 0)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}

		if tc := ifc.Tunnel; tc != nil && tc.Mode == "wireguard" {
			scopes := scopesFor(tc)
			recordDeviceScopes(ifName, -1, nil, tc, scopes)
			if len(scopes) == 1 && !wireguardOuterVRFSupported9909(cfg, scopes[0]) {
				violations = append(violations, wireguardRoutingInstanceViolation9909{
					ifName: ifName, unitNum: -1, tc: tc, ri: scopes[0],
				})
			}
		}

		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, n := range unitNums {
			unit := ifc.Units[n]
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.Mode != "wireguard" {
				continue
			}
			scopes := scopesFor(unit.Tunnel)
			recordDeviceScopes(ifName, n, ifc.Tunnel, unit.Tunnel, scopes)
			if len(scopes) == 1 && !wireguardOuterVRFSupported9909(cfg, scopes[0]) {
				violations = append(violations, wireguardRoutingInstanceViolation9909{
					ifName: ifName, unitNum: n, tc: unit.Tunnel, ri: scopes[0],
				})
			}
		}
	}

	devices := make([]string, 0, len(deviceClaims))
	for device := range deviceClaims {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	for _, device := range devices {
		claim := deviceClaims[device]
		if len(claim.scopes) < 2 {
			continue
		}
		scopes := make([]string, 0, len(claim.scopes))
		for scope := range claim.scopes {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		violations = append(violations, wireguardRoutingInstanceViolation9909{
			ifName: claim.ifName, unitNum: claim.unitNum, tc: claim.tc,
			ri: strings.Join(scopes, ","), conflict: true,
		})
	}
	if len(violations) == 0 {
		return nil, nil
	}
	if !lenient {
		v := violations[0]
		if v.conflict {
			return nil, fmt.Errorf(
				"wireguard tunnel %q has conflicting routing-instance claims %q for one outer device; commit refused (#9909, #10196)",
				tunnelLabel(v.ifName, v.unitNum, v.tc), v.ri)
		}
		return nil, fmt.Errorf(
			"wireguard tunnel %q is scoped to routing-instance %q, but that scope has no supported VRF device for outer UDP binding; commit refused (#9909, #10196)",
			tunnelLabel(v.ifName, v.unitNum, v.tc), v.ri)
	}
	// Remove RI memberships while all tunnel records still exist. This is
	// important when an interface-level WG and a scope-only unit override
	// share one device: removing just the violating unit would leave the
	// interface-level endpoint alive on an unsupported outer socket.

	quarantineMap := tunMap
	if len(cfg.RoutingInstances) > 0 && !tunMapReady {
		quarantineMap = getTunMap()
	}
	quarantineWireguardRoutingInstanceMembers9909(cfg, quarantineMap, violations)
	quarantineWireguardRoutingInstanceRecords9909(cfg, violations)
	var warnings []string
	warned := make(map[string]struct{}, len(violations))
	for _, v := range violations {
		key := v.tc.Name + "\x00" + v.ri
		if _, ok := warned[key]; ok {
			continue
		}
		warned[key] = struct{}{}
		if v.conflict {
			warnings = append(warnings, fmt.Sprintf(
				"wireguard tunnel %q is skipped on tolerant load: conflicting routing-instance claims %q target one outer device (#9909, #10196)",
				tunnelLabel(v.ifName, v.unitNum, v.tc), v.ri))
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"wireguard tunnel %q in routing-instance %q is skipped on tolerant load: that scope has no supported VRF device for outer UDP binding (#9909, #10196)",
			tunnelLabel(v.ifName, v.unitNum, v.tc), v.ri))
	}
	return warnings, nil
}

type wireguardRoutingInstanceViolation9909 struct {
	ifName   string
	unitNum  int
	tc       *TunnelConfig
	ri       string
	conflict bool
}

// wireguardRoutingInstanceMemberRef9909 pairs one authored RI member spelling
// with each kernel device the daemon's bind loop gives that spelling.
type wireguardRoutingInstanceMemberRef9909 struct {
	ref    string
	device string
}

// wireguardRoutingInstance9909 returns the first deterministic routing-instance
// scope for one WG tunnel. Callers that enforce the one-device invariant use
// wireguardRoutingInstances9909 so conflicting claims are not hidden.
func wireguardRoutingInstance9909(cfg *Config, tunMap map[string]string, tc *TunnelConfig) string {
	scopes := wireguardRoutingInstances9909(cfg, tunMap, tc)
	if len(scopes) == 0 {
		return ""
	}
	return scopes[0]
}

// wireguardRoutingInstances9909 returns every distinct routing-instance scope
// claiming one WG tunnel, in deterministic order. Explicit tunnel scope wins
// over list membership, matching reconcileVRFClaimLocked; otherwise all
// matching RI members are retained so two supported VRFs cannot silently
// collapse onto one shared outer UDP socket.
func wireguardRoutingInstances9909(cfg *Config, tunMap map[string]string, tc *TunnelConfig) []string {
	if cfg == nil || tc == nil {
		return nil
	}
	if tc.RoutingInstance != "" {
		return []string{tc.RoutingInstance}
	}
	if tc.RIListMember != "" {
		return []string{tc.RIListMember}
	}

	ris := make([]*RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			ris = append(ris, ri)
		}
	}
	sort.SliceStable(ris, func(i, j int) bool { return ris[i].Name < ris[j].Name })
	scopes := make([]string, 0, len(ris))
	seen := make(map[string]struct{}, len(ris))
	for _, ri := range ris {
		for _, member := range ri.Interfaces {
			if !wireguardMemberMatches9909(cfg, tunMap, tc, member) {
				continue
			}
			if _, duplicate := seen[ri.Name]; duplicate {
				break
			}
			seen[ri.Name] = struct{}{}
			scopes = append(scopes, ri.Name)
			break
		}
	}
	return scopes
}

// wireguardOuterVRFSupported9909 reports whether a named routing-instance has
// a kernel VRF device that the userspace WG socket can bind. Every supported
// non-forwarding instance type ("virtual-router", "vrf", or omitted) creates
// a VRF; forwarding instances intentionally do not.
func wireguardOuterVRFSupported9909(cfg *Config, instance string) bool {
	if cfg == nil || instance == "" {
		return false
	}
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == instance {
			return ri.InstanceType != "forwarding"
		}
	}
	return false
}

// quarantineWireguardRoutingInstanceMembers9909 removes affected WG devices
// from RI membership. A declared bare member fans down to every configured
// unit, so a partial match is rewritten to explicit surviving unit refs rather
// than deleting the whole bare member and stripping an unrelated sibling.
func quarantineWireguardRoutingInstanceMembers9909(cfg *Config, tunMap map[string]string, violations []wireguardRoutingInstanceViolation9909) {
	affected := wireguardAffectedDevices9909(violations)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}

		// Prefer an already-authored explicit member over a generated survivor
		// from a bare member. This keeps narrowing order-preserving and avoids
		// introducing a duplicate unit ref when both spellings were authored.
		authoredDevices := make(map[string]struct{}, len(ri.Interfaces))
		for _, member := range ri.Interfaces {
			if wireguardDeclaredBareMember9909(cfg, member) {
				continue
			}
			for _, ref := range wireguardMemberRefs9909(cfg, tunMap, member) {
				if ref.device != "" {
					authoredDevices[ref.device] = struct{}{}
				}
			}
		}

		kept := make([]string, 0, len(ri.Interfaces))
		generatedDevices := make(map[string]struct{}, len(authoredDevices))
		for device := range authoredDevices {
			generatedDevices[device] = struct{}{}
		}
		for _, member := range ri.Interfaces {
			refs := wireguardMemberRefs9909(cfg, tunMap, member)
			matched := false
			for _, ref := range refs {
				if _, ok := affected[ref.device]; ok {
					matched = true
					break
				}
			}
			if !matched {
				kept = append(kept, member)
				continue
			}
			if !wireguardDeclaredBareMember9909(cfg, member) {
				continue
			}
			for _, survivor := range wireguardSurvivingBareRefs9909(cfg, tunMap, member, refs, affected) {
				if survivor.device == "" {
					continue
				}
				if _, duplicate := generatedDevices[survivor.device]; duplicate {
					continue
				}
				generatedDevices[survivor.device] = struct{}{}
				kept = append(kept, survivor.ref)
			}
		}
		ri.Interfaces = kept
	}
}

// quarantineWireguardRoutingInstanceRecords9909 drops every WG config record
// that shares an affected kernel device. Interface-level WireGuard and a
// scope-only unit override can be separate records for one persistent wgN.
func quarantineWireguardRoutingInstanceRecords9909(cfg *Config, violations []wireguardRoutingInstanceViolation9909) {
	affected := wireguardAffectedDevices9909(violations)
	if len(affected) == 0 {
		return
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil && ifc.Tunnel.Mode == "wireguard" {
			if _, ok := affected[ifc.Tunnel.Name]; ok {
				ifc.Tunnel = nil
			}
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.Mode != "wireguard" {
				continue
			}
			if _, ok := affected[unit.Tunnel.Name]; ok {
				unit.Tunnel = nil
			}
		}
	}
}

func wireguardAffectedDevices9909(violations []wireguardRoutingInstanceViolation9909) map[string]struct{} {
	affected := make(map[string]struct{}, len(violations))
	for _, v := range violations {
		if v.tc != nil && v.tc.Name != "" {
			affected[v.tc.Name] = struct{}{}
		}
	}
	return affected
}

func wireguardDeclaredBareMember9909(cfg *Config, member string) bool {
	if cfg == nil || member == "" {
		return false
	}
	split := cfg.SplitInterfaceUnitRef(member)
	return !split.HasUnit && cfg.Interfaces.Interfaces[split.Base] != nil
}

func wireguardSurvivingBareRefs9909(cfg *Config, tunMap map[string]string, member string, refs []wireguardRoutingInstanceMemberRef9909, affected map[string]struct{}) []wireguardRoutingInstanceMemberRef9909 {
	split := cfg.SplitInterfaceUnitRef(member)
	seenDevices := make(map[string]struct{}, len(refs))
	out := make([]wireguardRoutingInstanceMemberRef9909, 0, len(refs))
	for i, ref := range refs {
		if ref.device == "" {
			continue
		}
		if _, drop := affected[ref.device]; drop {
			continue
		}
		if _, duplicate := seenDevices[ref.device]; duplicate {
			continue
		}

		candidate := ref.ref
		if i == 0 {
			// A bare base has no safe unit spelling when unit 0 uses a
			// VLAN-ID (Base.0 resolves to Base.<vlan>). Only preserve it
			// when the explicit spelling resolves back to the same device.
			candidate = split.Base + ".0"
		}
		if wireguardMemberDevice9909(cfg, tunMap, candidate) != ref.device {
			continue
		}
		seenDevices[ref.device] = struct{}{}
		out = append(out, wireguardRoutingInstanceMemberRef9909{
			ref: candidate, device: ref.device,
		})
	}
	return out
}

// wireguardMemberRefs9909 mirrors the daemon's RI-member expansion using the
// shared config primitives. Declared bare members fan down through
// InterfaceUnitRefKeys; generated unit keys resolve through TunnelNameMap
// before the producer-rule fallback. Unit-shaped and alias refs resolve only
// to their one runtime device.
func wireguardMemberRefs9909(cfg *Config, tunMap map[string]string, member string) []wireguardRoutingInstanceMemberRef9909 {
	if cfg == nil || member == "" {
		return nil
	}
	split := cfg.SplitInterfaceUnitRef(member)
	if !split.HasUnit && cfg.Interfaces.Interfaces[split.Base] != nil {
		refs := InterfaceUnitRefKeys(cfg, member)
		if len(refs) == 0 {
			return []wireguardRoutingInstanceMemberRef9909{{
				ref: member, device: LinuxIfName(split.Base),
			}}
		}
		out := make([]wireguardRoutingInstanceMemberRef9909, 0, len(refs))
		for i, ref := range refs {
			device := ""
			if i == 0 {
				// The daemon's singular bare resolver deliberately skips
				// TunnelNameMap; this is the base device in all cases.
				device = LinuxIfName(split.Base)
			} else {
				device = wireguardGeneratedMemberDevice9909(cfg, tunMap, split.Base, ref)
			}
			if device != "" {
				out = append(out, wireguardRoutingInstanceMemberRef9909{
					ref: ref, device: device,
				})
			}
		}
		return out
	}
	if device := wireguardMemberDevice9909(cfg, tunMap, member); device != "" {
		return []wireguardRoutingInstanceMemberRef9909{{ref: member, device: device}}
	}
	return nil
}

func wireguardGeneratedMemberDevice9909(cfg *Config, tunMap map[string]string, base, ref string) string {
	if device := tunMap[ref]; device != "" {
		return device
	}
	rest, ok := strings.CutPrefix(ref, base+".")
	if !ok {
		return ""
	}
	unitNum, _, err := CanonicalLogicalUnit(rest)
	if err != nil {
		return ""
	}
	var unit *InterfaceUnit
	if _, ifc, ok := LookupInterfaceByLinuxName(cfg, base); ok && ifc != nil {
		unit = ifc.Units[unitNum]
	}
	return wireguardLogicalUnitDevice9909(LinuxIfName(base), unitNum, unit)
}

func wireguardMemberDevice9909(cfg *Config, tunMap map[string]string, member string) string {
	split := cfg.SplitInterfaceUnitRef(member)
	if device := tunMap[split.Literal]; device != "" {
		return device
	}
	if split.HasUnit {
		if stanzaKey, _, ok := LookupInterfaceByLinuxName(cfg, split.Base); ok && stanzaKey != split.Base {
			if suffix, ok := strings.CutPrefix(split.Literal, split.Base); ok {
				if device := tunMap[stanzaKey+suffix]; device != "" {
					return device
				}
			}
		}
		unitNum, _, err := CanonicalLogicalUnit(split.UnitTok)
		if err != nil {
			return LinuxIfName(split.Literal)
		}
		var unit *InterfaceUnit
		if _, ifc, ok := LookupInterfaceByLinuxName(cfg, split.Base); ok && ifc != nil {
			unit = ifc.Units[unitNum]
		}
		return wireguardLogicalUnitDevice9909(LinuxIfName(split.Base), unitNum, unit)
	}
	return LinuxIfName(split.Base)
}

func wireguardLogicalUnitDevice9909(base string, unitNum int, unit *InterfaceUnit) string {
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", base, unit.VlanID)
	}
	if unitNum == 0 {
		return base
	}
	return fmt.Sprintf("%s.%d", base, unitNum)
}

// wireguardMemberMatches9909 follows the daemon's device expansion instead of
// comparing only the base Linux name. This catches every WG device a bare
// member binds, while leaving an undeclared nonzero unit ref untouched.
func wireguardMemberMatches9909(cfg *Config, tunMap map[string]string, tc *TunnelConfig, member string) bool {
	if tc == nil || member == "" {
		return false
	}
	for _, ref := range wireguardMemberRefs9909(cfg, tunMap, member) {
		if ref.device == tc.Name {
			return true
		}
	}
	return false
}
