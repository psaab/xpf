package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
)

// MaxVRRPVirtualAddressesIPv4 / MaxVRRPVirtualAddressesIPv6 bound the number of
// virtual addresses of ONE family that a single VRRP instance may carry.
//
// RFC 5798 §5.2.4 defines the advertisement's "Count IPvX Addr" field as a
// single byte, so at most 255 addresses can be expressed. The IPv6 budget is one
// lower because RFC 5798 §5.2.9 / §6.1 require the virtual router's link-local
// address to be listed FIRST: pkg/vrrp/instance_send.go sendPacketIPv6 prepends
// that link-local to the configured VIP slice immediately before Marshal, so it
// consumes one of the 255 slots and only 254 remain for configured addresses.
//
// Duplicated here rather than imported — pkg/vrrp imports pkg/config, so
// pkg/config validators must stay free of the reverse dependency (same rationale
// as RethVRRPGroupIDBase, #4826). The values are NOT independently maintained:
// pkg/vrrp/advert_capacity_agreement_6779_test.go asserts that each constant is
// exactly the largest count pkg/vrrp's real Marshal accepts for that family, so
// a change to the wire builder that these constants did not follow fails the
// pkg/vrrp suite rather than silently splitting the validator from the builder.
const (
	MaxVRRPVirtualAddressesIPv4 = 255
	MaxVRRPVirtualAddressesIPv6 = 254
)

// maxVRRPVirtualAddresses returns the per-family configured-VIP ceiling.
func maxVRRPVirtualAddresses(isIPv6 bool) int {
	if isIPv6 {
		return MaxVRRPVirtualAddressesIPv6
	}
	return MaxVRRPVirtualAddressesIPv4
}

// canonicalVRRPVIPIdentity normalizes CIDR spellings for config-side set
// operations without importing pkg/vrrp (which depends on pkg/config).
func canonicalVRRPVIPIdentity(vip string) string {
	ip, ipNet, err := net.ParseCIDR(vip)
	if err != nil {
		return vip
	}
	ones, _ := ipNet.Mask.Size()
	return ip.String() + "/" + strconv.Itoa(ones)
}

// dedupeVRRPVIPs preserves input order and the first spelling of each canonical
// identity. Invalid tokens remain available for the existing tolerant path.
func dedupeVRRPVIPs(vips []string) []string {
	if len(vips) < 2 {
		return vips
	}
	seen := make(map[string]struct{}, len(vips))
	var unique []string
	for i, vip := range vips {
		id := canonicalVRRPVIPIdentity(vip)
		if _, exists := seen[id]; exists {
			if unique == nil {
				unique = append([]string(nil), vips[:i]...)
			}
			continue
		}
		seen[id] = struct{}{}
		if unique != nil {
			unique = append(unique, vip)
		}
	}
	if unique != nil {
		return unique
	}
	return vips
}

// countVRRPVIPFamilies counts distinct canonical address/prefix identities by
// family, accepting CIDRs or bare literals and skipping unparseable entries.
func countVRRPVIPFamilies(vips []string) (nV4, nV6 int) {
	seen := make(map[string]struct{}, len(vips))
	for _, vip := range vips {
		ip := vrrpVIPHostIP(vip)
		if ip == nil {
			continue
		}
		id := canonicalVRRPVIPIdentity(vip)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		if ip.To4() != nil {
			nV4++
		} else {
			nV6++
		}
	}
	return nV4, nV6
}

// vrrpVIPCountErr builds the operator-facing rejection for an over-capacity
// family, or nil when both families fit. `where` names the offending config
// object (interface/unit/group) and is prefixed onto the message.
func vrrpVIPCountErr(where string, vips []string) error {
	nV4, nV6 := countVRRPVIPFamilies(vips)
	for _, fam := range []struct {
		isIPv6 bool
		n      int
		name   string
		extra  string
	}{
		{false, nV4, "IPv4", ""},
		{true, nV6, "IPv6", " (one of the 255 slots is reserved for the " +
			"mandatory link-local address RFC 5798 §6.1 requires first in an " +
			"IPv6 advertisement)"},
	} {
		limit := maxVRRPVirtualAddresses(fam.isIPv6)
		if fam.n <= limit {
			continue
		}
		return fmt.Errorf("%s carries %d %s virtual addresses, which exceeds the "+
			"maximum of %d that fit in a VRRPv3 advertisement%s — the "+
			"advertisement's address count is a single wire byte (RFC 5798 "+
			"§5.2.4), so every advert for this group would fail to build while "+
			"the node still claimed the virtual addresses: the peer stops "+
			"hearing this master, promotes itself, and both nodes answer for "+
			"the same addresses — reduce the virtual-address count or split the "+
			"addresses across additional groups",
			where, fam.n, fam.name, limit, fam.extra)
	}
	return nil
}

// validateVRRPVIPCountStrict hard-rejects, at commit / commit-check, a VRRP
// virtual-address set whose per-family cardinality exceeds what a single VRRPv3
// advertisement can express (#6779).
//
// The failure this prevents is an ORDERING problem, not merely a malformed
// packet. pkg/vrrp becomeMaster claims the VIP set and publishes MASTER, and
// only then calls sendAdvert — which discards a Marshal failure at slog.Debug.
// Marshal refuses an out-of-range address count rather than truncating the u8
// Count byte (#5090), so an oversized family makes EVERY advert fail after the
// node has already taken ownership. The node then holds the addresses while
// emitting nothing: the peer's masterDownTimer expires and it promotes too
// (dual-master, duplicate addresses on the segment), or, when the peer shares
// the same synced config, no node can advertise and the addresses are stranded.
//
// Both VIP sources are covered, because both feed the same advert builder:
//
//   - explicit `vrrp-group <id> virtual-address <vip>` (CollectInstances)
//   - RETH-derived instances, where a redundancy-group RETH interface's own
//     unit addresses BECOME the advertised VIP set (CollectRethInstances). A
//     VLAN-tagged RETH builds one instance per unit, so each unit is counted
//     separately; an untagged RETH concatenates every unit's addresses into a
//     single instance, so those are counted together.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientVRRPVIPCount) so an already-persisted or peer-synced
// config an older binary accepted still BOOTS (#1960 no-brick); the pkg/vrrp
// runtime guards independently refuse to build the instance (UpdateInstances)
// and refuse to claim MASTER (becomeMaster), so a leniently-loaded oversized set
// is bounded — a WARN plus a group that stays out of the election — rather than
// a silent non-advertising owner. Same doctrine as lenientRethVRRPGroupID.
func validateVRRPVIPCountStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}

	// Mirror CollectRethInstances' early return: when the cluster manages VIPs
	// directly (no-reth-vrrp) or elects over the control link only
	// (private-rg-election), no RETH-derived VRRP instance is synthesized, so a
	// RETH unit's address count has no advert consequence. Explicit vrrp-group
	// blocks are still checked — they are independent of cluster mode.
	rethVRRPActive := true
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		rethVRRPActive = false
	}

	// Deterministic walk so the first-error commit-check message is stable
	// across map-ordered runs, matching the sibling strict validators.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, ifName := range names {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		// Explicit `vrrp-group` blocks: one instance per group, carrying that
		// group's own virtual-address list.
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				where := fmt.Sprintf("interfaces %s unit %d vrrp-group %d",
					ifName, un, vg.ID)
				if err := vrrpVIPCountErr(where, vg.VirtualAddresses); err != nil {
					return err
				}
			}
		}

		// RETH-derived instances: the unit addresses themselves are the VIPs.
		if !rethVRRPActive || ifc.RedundancyGroup <= 0 {
			continue
		}
		if ifc.VlanTagging {
			// One instance per addressed unit.
			for _, un := range unitNums {
				unit := ifc.Units[un]
				if unit == nil || len(unit.Addresses) == 0 {
					continue
				}
				where := fmt.Sprintf("interfaces %s unit %d (reth "+
					"redundancy-group %d VRRP)", ifName, un, ifc.RedundancyGroup)
				if err := vrrpVIPCountErr(where, unit.Addresses); err != nil {
					return err
				}
			}
			continue
		}
		// Untagged: every unit's addresses land in ONE instance.
		var all []string
		for _, un := range unitNums {
			if unit := ifc.Units[un]; unit != nil {
				all = append(all, unit.Addresses...)
			}
		}
		where := fmt.Sprintf("interfaces %s (reth redundancy-group %d VRRP)",
			ifName, ifc.RedundancyGroup)
		if err := vrrpVIPCountErr(where, all); err != nil {
			return err
		}
	}
	return nil
}
