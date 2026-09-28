package config

import (
	"fmt"
	"sort"
	"strings"
)

// RoutingInstanceMemberDeviceKey is one logical snapshot key claimed by an RI
// list member or retained base-only claim and the Linux netdevice the daemon
// binds for that key. Fanout is true only for generated keys from a bare member.
// Cross-instance conflicts can also originate in explicit tunnel stanzas.
type RoutingInstanceMemberDeviceKey struct {
	InterfaceKey string
	LinuxName    string
	Fanout       bool
}

// RoutingInstanceMemberClaim identifies one authored RI member that claims a
// Linux device. One representative member per instance is enough to explain a
// cross-instance device conflict.
type RoutingInstanceMemberClaim struct {
	Instance string
	Member   string
}

// RoutingInstanceMemberPrimaryClaim preserves an uncontested primary device
// from a tolerant bare-member fanout without retaining the fanout-capable bare
// reference in RoutingInstanceConfig.Interfaces.
type RoutingInstanceMemberPrimaryClaim struct {
	Instance     string
	InterfaceKey string
	LinuxName    string
}

// RoutingInstanceMemberDeviceConflict records one Linux netdevice claimed by
// multiple routing instances.
type RoutingInstanceMemberDeviceConflict struct {
	LinuxName string
	Claims    []RoutingInstanceMemberClaim
}

// MemberDeclaredBase is a routing-instance member resolved to its declared
// interface base, when one exists. Unit is -1 for a malformed suffix.
type MemberDeclaredBase struct {
	Base    string
	Unit    int
	HasUnit bool
	OK      bool
}

// ResolveRoutingInstanceMemberBase resolves an RI member through the ordered
// alias rules used by kernel binding: exact split base, Linux-name-matched split
// base, whole raw member, then whole canonical member. Sorted alias lookup keeps
// tolerant configs deterministic.
func ResolveRoutingInstanceMemberBase(cfg *Config, member string) MemberDeclaredBase {
	none := MemberDeclaredBase{Unit: -1}
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return none
	}
	declared := cfg.Interfaces.Interfaces
	s := cfg.SplitInterfaceUnitRef(member)
	if declared[s.Base] != nil {
		return splitMemberUnitReading(s)
	}

	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if declared[name] != nil && LinuxIfName(name) == LinuxIfName(s.Base) {
			out := splitMemberUnitReading(s)
			out.Base = name
			return out
		}
	}
	for _, name := range names {
		if declared[name] != nil && LinuxIfName(name) == LinuxIfName(member) {
			return MemberDeclaredBase{Base: name, Unit: -1, OK: true}
		}
	}
	for _, name := range names {
		if declared[name] != nil && LinuxIfName(name) == LinuxIfName(s.Literal) {
			return MemberDeclaredBase{Base: name, Unit: -1, OK: true}
		}
	}
	return none
}

func splitMemberUnitReading(s InterfaceRefSplit) MemberDeclaredBase {
	out := MemberDeclaredBase{Base: s.Base, Unit: -1, OK: true}
	if !s.HasUnit {
		return out
	}
	out.HasUnit = true
	n, _, err := CanonicalLogicalUnit(s.UnitTok)
	if err == nil {
		out.Unit = n
	}
	return out
}

// LogicalUnitDeviceKey returns the Linux device key produced for one declared
// logical unit. VLAN units use their configured VLAN ID; untagged nonzero units
// retain their unit number, and unit zero collapses onto the base device.
func LogicalUnitDeviceKey(base string, unitNum int, unit *InterfaceUnit) string {
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", base, unit.VlanID)
	}
	if unitNum != 0 {
		return fmt.Sprintf("%s.%d", base, unitNum)
	}
	return base
}

// LogicalUnitDeviceKeyForRef resolves a reference to the Linux key produced by
// LogicalUnitDeviceKey. It intentionally does not resolve reth members or
// tunnels; RI tunnel resolution is handled by RoutingInstanceMemberDeviceKeys.
func LogicalUnitDeviceKeyForRef(cfg *Config, ref string) string {
	s := cfg.SplitInterfaceUnitRef(ref)
	base := LinuxIfName(s.Base)
	if !s.HasUnit {
		return base
	}
	unitNum, _, err := CanonicalLogicalUnit(s.UnitTok)
	if err != nil {
		return LinuxIfName(s.Literal)
	}
	var unit *InterfaceUnit
	if _, ifc, ok := LookupInterfaceByLinuxName(cfg, s.Base); ok {
		unit = ifc.Units[unitNum]
	}
	return LogicalUnitDeviceKey(base, unitNum, unit)
}

// RoutingInstanceMemberDeviceKeys resolves one RI member into the logical keys
// used by userspace snapshots and the Linux devices bound by the daemon. It is
// the shared identity boundary for strict validation, tolerant quarantine,
// kernel binding, reassertion, and userspace membership maps.
func RoutingInstanceMemberDeviceKeys(cfg *Config, tunnelNames map[string]string, member string) []RoutingInstanceMemberDeviceKey {
	if member == "" {
		return nil
	}
	s := cfg.SplitInterfaceUnitRef(member)
	claim := ResolveRoutingInstanceMemberBase(cfg, member)

	// A declared bare member (including a Linux-spelling alias of a whole
	// declared name) claims its authored key plus every generated unit key.
	if claim.OK && !claim.HasUnit {
		keys := InterfaceUnitRefKeys(cfg, claim.Base)
		if len(keys) == 0 {
			return []RoutingInstanceMemberDeviceKey{{
				InterfaceKey: claim.Base,
				LinuxName:    LogicalUnitDeviceKeyForRef(cfg, claim.Base),
			}}
		}
		out := make([]RoutingInstanceMemberDeviceKey, 0, len(keys))
		out = append(out, RoutingInstanceMemberDeviceKey{
			InterfaceKey: keys[0],
			LinuxName:    LogicalUnitDeviceKeyForRef(cfg, keys[0]),
		})
		for _, key := range keys[1:] {
			out = append(out, RoutingInstanceMemberDeviceKey{
				InterfaceKey: key,
				LinuxName:    memberUnitLinuxName(cfg, tunnelNames, claim.Base, key),
				Fanout:       true,
			})
		}
		return out
	}

	key := s.Literal
	if claim.OK && claim.HasUnit {
		if suffix, ok := strings.CutPrefix(s.Literal, s.Base); ok {
			key = claim.Base + suffix
		}
	}
	return []RoutingInstanceMemberDeviceKey{{
		InterfaceKey: key,
		LinuxName:    routingInstanceMemberLinuxName(cfg, tunnelNames, key),
	}}
}

// RoutingInstanceMemberLinuxNames returns the distinct Linux devices claimed
// by one member, in stable primary-then-fanout order.
func RoutingInstanceMemberLinuxNames(cfg *Config, tunnelNames map[string]string, member string) []string {
	keys := RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member)
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if key.LinuxName == "" {
			continue
		}
		if _, exists := seen[key.LinuxName]; exists {
			continue
		}
		seen[key.LinuxName] = struct{}{}
		out = append(out, key.LinuxName)
	}
	return out
}

// RoutingInstanceMemberDeviceKeysForInstance returns every logical key
// claimed by one instance's interface list plus any base-only primary claims
// produced by tolerant quarantine.
func RoutingInstanceMemberDeviceKeysForInstance(
	cfg *Config, tunnelNames map[string]string, ri *RoutingInstanceConfig,
) []RoutingInstanceMemberDeviceKey {
	if cfg == nil || ri == nil {
		return nil
	}
	out := make([]RoutingInstanceMemberDeviceKey, 0, len(ri.Interfaces))
	for _, member := range ri.Interfaces {
		out = append(out, RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member)...)
	}
	for _, claim := range cfg.QuarantinedRIMemberPrimaryClaims {
		if claim.Instance == ri.Name && claim.InterfaceKey != "" && claim.LinuxName != "" {
			out = append(out, RoutingInstanceMemberDeviceKey{
				InterfaceKey: claim.InterfaceKey,
				LinuxName:    claim.LinuxName,
			})
		}
	}
	return out
}

// RoutingInstanceMemberLinuxNamesForInstance returns each Linux device claimed
// by the instance once, including retained primary claims.
func RoutingInstanceMemberLinuxNamesForInstance(
	cfg *Config, tunnelNames map[string]string, ri *RoutingInstanceConfig,
) []string {
	keys := RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri)
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if key.LinuxName == "" {
			continue
		}
		if _, found := seen[key.LinuxName]; found {
			continue
		}
		seen[key.LinuxName] = struct{}{}
		out = append(out, key.LinuxName)
	}
	return out
}

// RoutingInstanceMemberDeviceConflicts finds every Linux device claimed by
// multiple routing instances through either an `interface` list or an explicit
// tunnel `routing-instance` stanza. Forwarding instances do not bind links to
// Linux VRFs, but their interface ownership is consumed by userspace maps and
// must not overlap a VRF claim. Repeated same-instance claims remain harmless.
func RoutingInstanceMemberDeviceConflicts(cfg *Config, tunnelNames map[string]string) []RoutingInstanceMemberDeviceConflict {
	if cfg == nil {
		return nil
	}
	type owner struct {
		claim RoutingInstanceMemberClaim
		seen  map[string]struct{}
	}
	ownersByDevice := make(map[string][]owner)
	ownerIndex := make(map[string]map[string]int)
	recordOwner := func(linuxName, instance, member string) {
		if linuxName == "" || instance == "" {
			return
		}
		byInstance := ownerIndex[linuxName]
		if byInstance == nil {
			byInstance = make(map[string]int)
			ownerIndex[linuxName] = byInstance
		}
		idx, exists := byInstance[instance]
		if !exists {
			idx = len(ownersByDevice[linuxName])
			byInstance[instance] = idx
			ownersByDevice[linuxName] = append(ownersByDevice[linuxName], owner{
				claim: RoutingInstanceMemberClaim{Instance: instance, Member: member},
				seen:  make(map[string]struct{}),
			})
		}
		ownersByDevice[linuxName][idx].seen[member] = struct{}{}
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		for _, member := range ri.Interfaces {
			for _, key := range RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member) {
				recordOwner(key.LinuxName, ri.Name, member)
			}
		}
	}

	// A tunnel's explicit routing-instance stanza is an ownership claim on the
	// tunnel's compiled Linux device, just like an RI list member. The compiler
	// assigns shared WireGuard units the parent name and mode-overriding units
	// their distinct uN name, so use the resolved unit name verbatim.
	interfaceNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for ifName := range cfg.Interfaces.Interfaces {
		interfaceNames = append(interfaceNames, ifName)
	}
	sort.Strings(interfaceNames)
	for _, ifName := range interfaceNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		if tc := ifc.Tunnel; tc != nil && tc.RoutingInstance != "" {
			recordOwner(tc.Name, tc.RoutingInstance, fmt.Sprintf("%s tunnel routing-instance", ifName))
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.RoutingInstance == "" {
				continue
			}
			recordOwner(unit.Tunnel.Name, unit.Tunnel.RoutingInstance,
				fmt.Sprintf("%s.%d tunnel routing-instance", ifName, unitNum))
		}
	}
	for _, claim := range cfg.QuarantinedRIMemberPrimaryClaims {
		recordOwner(claim.LinuxName, claim.Instance, "primary "+claim.InterfaceKey)
	}

	devices := make([]string, 0, len(ownersByDevice))
	for device, owners := range ownersByDevice {
		if len(owners) > 1 {
			devices = append(devices, device)
		}
	}
	sort.Strings(devices)
	out := make([]RoutingInstanceMemberDeviceConflict, 0, len(devices))
	for _, device := range devices {
		owners := ownersByDevice[device]
		claims := make([]RoutingInstanceMemberClaim, 0, len(owners))
		for _, owner := range owners {
			members := make([]string, 0, len(owner.seen))
			for member := range owner.seen {
				members = append(members, member)
			}
			sort.Strings(members)
			claim := owner.claim
			claim.Member = members[0]
			claims = append(claims, claim)
		}
		sort.Slice(claims, func(i, j int) bool {
			if claims[i].Instance != claims[j].Instance {
				return claims[i].Instance < claims[j].Instance
			}
			return claims[i].Member < claims[j].Member
		})
		out = append(out, RoutingInstanceMemberDeviceConflict{LinuxName: device, Claims: claims})
	}
	return out
}

// RoutingInstanceDualClaimedLinuxNames returns the devices that cannot be
// safely assigned to one RI without an explicit ownership decision.
func RoutingInstanceDualClaimedLinuxNames(cfg *Config, tunnelNames map[string]string) map[string]bool {
	conflicts := RoutingInstanceMemberDeviceConflicts(cfg, tunnelNames)
	if len(conflicts) == 0 {
		return nil
	}
	out := make(map[string]bool, len(conflicts))
	for _, conflict := range conflicts {
		out[conflict.LinuxName] = true
	}
	return out
}

func routingInstanceMemberLinuxName(cfg *Config, tunnelNames map[string]string, ref string) string {
	s := cfg.SplitInterfaceUnitRef(ref)
	if !s.HasUnit && cfg != nil && cfg.Interfaces.Interfaces[s.Base] != nil {
		return LogicalUnitDeviceKeyForRef(cfg, s.Literal)
	}
	if name := tunnelNames[s.Literal]; name != "" {
		return name
	}
	if s.HasUnit {
		if stanza, _, ok := LookupInterfaceByLinuxName(cfg, s.Base); ok && stanza != s.Base {
			if suffix, ok := strings.CutPrefix(s.Literal, s.Base); ok {
				if name := tunnelNames[stanza+suffix]; name != "" {
					return name
				}
			}
		}
	}
	return LogicalUnitDeviceKeyForRef(cfg, s.Literal)
}

func memberUnitLinuxName(cfg *Config, tunnelNames map[string]string, base, key string) string {
	if name := tunnelNames[key]; name != "" {
		return name
	}
	rest, ok := strings.CutPrefix(key, base+".")
	if !ok {
		return ""
	}
	unitNum, _, err := CanonicalLogicalUnit(rest)
	if err != nil {
		return ""
	}
	var unit *InterfaceUnit
	if cfg != nil && cfg.Interfaces.Interfaces != nil {
		if ifc := cfg.Interfaces.Interfaces[base]; ifc != nil {
			unit = ifc.Units[unitNum]
		}
	}
	return LogicalUnitDeviceKey(LinuxIfName(base), unitNum, unit)
}
