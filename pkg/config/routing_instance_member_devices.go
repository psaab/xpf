package config

import (
	"fmt"
	"sort"
	"strings"
)

// RoutingInstanceMemberDeviceKey is one logical snapshot key claimed by an RI
// member and the Linux netdevice that the daemon binds for that key. Fanout is
// true only for generated keys from a bare member. Consumers preserve it for
// explicit-unit precedence within one instance; cross-instance device claims
// are rejected or quarantined by RoutingInstanceMemberDeviceConflicts.
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

// RoutingInstanceMemberDeviceConflicts finds every Linux device claimed by
// multiple VRF-backed routing instances. Forwarding instances stay in the
// default Linux routing context and do not bind their interfaces. Repeated
// members inside one instance remain harmless.
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
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		for _, member := range ri.Interfaces {
			for _, key := range RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member) {
				if key.LinuxName == "" {
					continue
				}
				byInstance := ownerIndex[key.LinuxName]
				if byInstance == nil {
					byInstance = make(map[string]int)
					ownerIndex[key.LinuxName] = byInstance
				}
				idx, exists := byInstance[ri.Name]
				if !exists {
					idx = len(ownersByDevice[key.LinuxName])
					byInstance[ri.Name] = idx
					ownersByDevice[key.LinuxName] = append(ownersByDevice[key.LinuxName], owner{
						claim: RoutingInstanceMemberClaim{Instance: ri.Name, Member: member},
						seen:  make(map[string]struct{}),
					})
				}
				ownersByDevice[key.LinuxName][idx].seen[member] = struct{}{}
			}
		}
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
