package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	// Management DNS steering runs after the VRF-miss terminator: a lookup
	// bound to a tenant VRF must fail in that VRF instead of falling through
	// to the management table. Keep its miss shadow adjacent to the lookup so
	// a missing table-999 route cannot fall through to main's WAN default.
	mgmtDNSRulePriority       = 2500
	mgmtDNSRuleShadowPriority = mgmtDNSRulePriority + 1
	mgmtDNSRuleInterface      = "lo"
	mgmtDNSRuleLookupTable    = config.ManagementVRFTableID
)

const (
	_ = uint(mgmtDNSRulePriority - 2001) // after VRF miss terminator at 2000
	_ = uint(config.PBRRulePriorityBase - mgmtDNSRuleShadowPriority - 1)
)

type mgmtDNSRuleOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RuleList(family int) ([]netlink.Rule, error)
}

type netlinkMgmtDNSRuleOps struct{}

func (netlinkMgmtDNSRuleOps) RuleAdd(rule *netlink.Rule) error { return netlink.RuleAdd(rule) }
func (netlinkMgmtDNSRuleOps) RuleDel(rule *netlink.Rule) error { return netlink.RuleDel(rule) }

// RuleList decodes the policy-rule action from fib_rule_hdr.Type. netlink
// v1.3.1's RuleList omits that field, so use the same kernel dump while
// retaining the selectors needed to reconcile only our host-DNS rules.
func (netlinkMgmtDNSRuleOps) RuleList(family int) ([]netlink.Rule, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	req.AddData(nl.NewIfInfomsg(family))
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil {
		return nil, err
	}
	return decodeMgmtDNSRuleMessages(family, msgs)
}

func decodeMgmtDNSRuleMessages(family int, msgs [][]byte) ([]netlink.Rule, error) {
	rules := make([]netlink.Rule, 0, len(msgs))
	for _, raw := range msgs {
		if len(raw) < unix.SizeofRtMsg {
			return nil, fmt.Errorf("short family %d policy-rule message: %d bytes", family, len(raw))
		}
		msg := nl.DeserializeRtMsg(raw)
		attrs, err := nl.ParseRouteAttr(raw[msg.Len():])
		if err != nil {
			return nil, fmt.Errorf("parse family %d policy-rule attributes: %w", family, err)
		}
		rule := netlink.NewRule()
		rule.Priority = 0
		rule.Family = int(msg.Family)
		rule.Table = int(msg.Table)
		rule.Type = msg.Type
		rule.Invert = msg.Flags&netlink.FibRuleInvert != 0
		rule.Tos = uint(msg.Tos)
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.RTA_TABLE:
				if len(attr.Value) < 4 {
					return nil, fmt.Errorf("short policy-rule table attribute in family %d", family)
				}
				rule.Table = int(nl.NativeEndian().Uint32(attr.Value[:4]))
			case nl.FRA_PRIORITY:
				value, err := mgmtDNSRuleUint32(attr.Value, "priority")
				if err != nil {
					return nil, err
				}
				rule.Priority = int(value)
			case nl.FRA_DST:
				prefix, err := mgmtDNSRulePrefix(attr.Value, msg.Dst_len)
				if err != nil {
					return nil, fmt.Errorf("decode policy-rule destination in family %d: %w", family, err)
				}
				rule.Dst = prefix
			case nl.FRA_SRC:
				prefix, err := mgmtDNSRulePrefix(attr.Value, msg.Src_len)
				if err != nil {
					return nil, fmt.Errorf("decode policy-rule source in family %d: %w", family, err)
				}
				rule.Src = prefix
			case nl.FRA_FWMARK:
				value, err := mgmtDNSRuleUint32(attr.Value, "mark")
				if err != nil {
					return nil, err
				}
				rule.Mark = value
			case nl.FRA_FWMASK:
				value, err := mgmtDNSRuleUint32(attr.Value, "mark mask")
				if err != nil {
					return nil, err
				}
				rule.Mask = &value
			case nl.FRA_TUN_ID:
				if len(attr.Value) < 8 {
					return nil, fmt.Errorf("short policy-rule tunnel id attribute in family %d", family)
				}
				rule.TunID = uint(nl.NativeEndian().Uint64(attr.Value[:8]))
			case nl.FRA_IIFNAME:
				rule.IifName = mgmtDNSRuleIfName(attr.Value)
			case nl.FRA_OIFNAME:
				rule.OifName = mgmtDNSRuleIfName(attr.Value)
			case nl.FRA_SUPPRESS_PREFIXLEN:
				value, err := mgmtDNSRuleUint32(attr.Value, "suppress prefix length")
				if err != nil {
					return nil, err
				}
				if value != ^uint32(0) {
					rule.SuppressPrefixlen = int(value)
				}
			case nl.FRA_SUPPRESS_IFGROUP:
				value, err := mgmtDNSRuleUint32(attr.Value, "suppress interface group")
				if err != nil {
					return nil, err
				}
				if value != ^uint32(0) {
					rule.SuppressIfgroup = int(value)
				}
			case nl.FRA_FLOW:
				value, err := mgmtDNSRuleUint32(attr.Value, "flow")
				if err != nil {
					return nil, err
				}
				rule.Flow = int(value)
			case nl.FRA_GOTO:
				value, err := mgmtDNSRuleUint32(attr.Value, "goto")
				if err != nil {
					return nil, err
				}
				rule.Goto = int(value)
			case nl.FRA_IP_PROTO:
				value, err := mgmtDNSRuleUint32(attr.Value, "IP protocol")
				if err != nil {
					return nil, err
				}
				rule.IPProto = int(value)
			case nl.FRA_DPORT_RANGE:
				if len(attr.Value) < 4 {
					return nil, fmt.Errorf("short policy-rule destination-port range in family %d", family)
				}
				native := nl.NativeEndian()
				rule.Dport = netlink.NewRulePortRange(native.Uint16(attr.Value[:2]), native.Uint16(attr.Value[2:4]))
			case nl.FRA_SPORT_RANGE:
				if len(attr.Value) < 4 {
					return nil, fmt.Errorf("short policy-rule source-port range in family %d", family)
				}
				native := nl.NativeEndian()
				rule.Sport = netlink.NewRulePortRange(native.Uint16(attr.Value[:2]), native.Uint16(attr.Value[2:4]))
			case nl.FRA_UID_RANGE:
				if len(attr.Value) < 8 {
					return nil, fmt.Errorf("short policy-rule UID range in family %d", family)
				}
				native := nl.NativeEndian()
				rule.UIDRange = netlink.NewRuleUIDRange(native.Uint32(attr.Value[:4]), native.Uint32(attr.Value[4:8]))
			case nl.FRA_PROTOCOL:
				if len(attr.Value) < 1 {
					return nil, fmt.Errorf("short policy-rule protocol attribute in family %d", family)
				}
				rule.Protocol = attr.Value[0]
			}
		}
		rules = append(rules, *rule)
	}
	return rules, nil
}

func mgmtDNSRulePrefix(ip []byte, prefixLen uint8) (*net.IPNet, error) {
	if (len(ip) != net.IPv4len && len(ip) != net.IPv6len) || int(prefixLen) > 8*len(ip) {
		return nil, fmt.Errorf("invalid address length %d or prefix length %d", len(ip), prefixLen)
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(prefixLen), 8*len(ip))}, nil
}

func mgmtDNSRuleUint32(value []byte, name string) (uint32, error) {
	if len(value) < 4 {
		return 0, fmt.Errorf("short policy-rule %s attribute", name)
	}
	return nl.NativeEndian().Uint32(value[:4]), nil
}

func mgmtDNSRuleIfName(value []byte) string {
	name := string(value)
	if len(name) > 0 && name[len(name)-1] == 0 {
		name = name[:len(name)-1]
	}
	return name
}

type mgmtDNSRuleKey struct {
	family int
	dst    string
}

type mgmtDNSRulePair struct {
	key    mgmtDNSRuleKey
	lookup netlink.Rule
	shadow netlink.Rule
}

// mgmtDNSRulePairs builds host-only lookup/terminal pairs for nameservers on
// management-VRF DHCP leases. Locally generated default-context traffic has
// iif=lo; the exact destination keeps this away from unrelated host traffic.
// Tenant-VRF local traffic reaches the existing l3mdev miss terminator at
// priority 2000 before these rules can match.
func mgmtDNSRulePairs(leases []*dhcp.Lease, mgmtSet map[string]bool) []mgmtDNSRulePair {
	seen := make(map[mgmtDNSRuleKey]struct{})
	pairs := make([]mgmtDNSRulePair, 0)
	for _, lease := range leases {
		if lease == nil || !mgmtSet[lease.Interface] {
			continue
		}
		for _, ip := range lease.DNS {
			if !validLeaseDNSServer(ip) {
				continue
			}
			family, bits := unix.AF_INET6, 128
			if ip.Is4() {
				family, bits = unix.AF_INET, 32
			}
			prefix := netip.PrefixFrom(ip, bits)
			key := mgmtDNSRuleKey{family: family, dst: prefix.String()}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}

			_, dst, err := net.ParseCIDR(prefix.String())
			if err != nil {
				continue // PrefixFrom above produces a canonical, valid CIDR.
			}
			lookup := netlink.NewRule()
			lookup.Family = family
			lookup.Priority = mgmtDNSRulePriority
			lookup.Table = mgmtDNSRuleLookupTable
			lookup.Type = unix.RTN_UNICAST
			lookup.IifName = mgmtDNSRuleInterface
			lookup.Dst = dst

			shadow := *lookup
			shadow.Priority = mgmtDNSRuleShadowPriority
			shadow.Table = unix.RT_TABLE_UNSPEC
			shadow.Type = nl.FR_ACT_UNREACHABLE
			pairs = append(pairs, mgmtDNSRulePair{key: key, lookup: *lookup, shadow: shadow})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key.family != pairs[j].key.family {
			return pairs[i].key.family < pairs[j].key.family
		}
		return pairs[i].key.dst < pairs[j].key.dst
	})
	return pairs
}

// applyMgmtDNSRules reconciles DNS routing from the current lease snapshot.
// It also runs with no DHCP manager or no management leases so stale rules from
// a withdrawn/deconfigured management interface are removed.
func (d *Daemon) applyMgmtDNSRules() error {
	var leases []*dhcp.Lease
	if d.dhcp != nil {
		leases = d.dhcp.Leases()
	}
	return reconcileMgmtDNSRules(netlinkMgmtDNSRuleOps{}, leases, d.mgmtVRFIfaceSet())
}

func reconcileMgmtDNSRules(ops mgmtDNSRuleOps, leases []*dhcp.Lease, mgmtSet map[string]bool) error {
	pairs := mgmtDNSRulePairs(leases, mgmtSet)
	wanted := make(map[mgmtDNSRuleKey]struct{}, len(pairs))
	for _, pair := range pairs {
		wanted[pair.key] = struct{}{}
	}

	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list management DNS rules family %d: %w", family, err))
			continue
		}
		lookups := make(map[mgmtDNSRuleKey][]netlink.Rule)
		shadows := make(map[mgmtDNSRuleKey][]netlink.Rule)
		invalids := make(map[mgmtDNSRuleKey][]netlink.Rule)
		for _, rule := range rules {
			key, kind, ok := managedMgmtDNSRule(rule)
			if !ok || key.family != family {
				continue
			}
			switch kind {
			case "lookup":
				lookups[key] = append(lookups[key], rule)
			case "shadow":
				shadows[key] = append(shadows[key], rule)
			case "invalid":
				invalids[key] = append(invalids[key], rule)
			}
		}

		// Install every miss shadow before its lookup. If lookup installation
		// fails, the retained shadow makes the failure fail-closed, not a route
		// fallback through main's unrelated default.
		failedShadow := make(map[mgmtDNSRuleKey]bool)
		blocked := make(map[mgmtDNSRuleKey]bool)
		// Reserved-priority rules with the right host selector but the wrong
		// action/table can preempt the intended pair. Remove them exactly before
		// installing anything; if removal fails, suppress resolver publication.
		for _, key := range sortedMgmtDNSRuleKeys(invalids) {
			for _, rule := range invalids[key] {
				if err := deleteExactMgmtDNSRule(ops, rule); err != nil {
					errs = append(errs, fmt.Errorf("remove invalid management DNS rule to %s: %w", key.dst, err))
					blocked[key] = true
				}
			}
		}
		for key := range blocked {
			failedShadow[key] = true
			for _, lookup := range lookups[key] {
				if err := deleteMgmtDNSRule(ops, lookup, mgmtDNSRuleLookupTable); err != nil {
					errs = append(errs, fmt.Errorf("remove management DNS lookup behind invalid rule to %s: %w", key.dst, err))
				}
			}
		}
		for _, pair := range pairs {
			if pair.key.family != family || blocked[pair.key] {
				continue
			}
			if len(shadows[pair.key]) == 0 {
				if err := ops.RuleAdd(&pair.shadow); err != nil && !errors.Is(err, unix.EEXIST) {
					errs = append(errs, fmt.Errorf("add management DNS miss shadow to %s: %w", pair.key.dst, err))
					failedShadow[pair.key] = true
					// Repair a pre-existing lookup without its fail-closed shadow.
					for _, lookup := range lookups[pair.key] {
						if delErr := deleteMgmtDNSRule(ops, lookup, mgmtDNSRuleLookupTable); delErr != nil {
							errs = append(errs, fmt.Errorf("remove unshadowed management DNS lookup to %s: %w", pair.key.dst, delErr))
						}
					}
					continue
				}
			}
			if len(lookups[pair.key]) == 0 {
				if err := ops.RuleAdd(&pair.lookup); err != nil && !errors.Is(err, unix.EEXIST) {
					errs = append(errs, fmt.Errorf("add management DNS lookup to %s: %w", pair.key.dst, err))
				}
			}
		}

		// Remove stale lookups first. A stale shadow is kept if its lookup
		// cannot be removed, so the stale lookup can never fall through to main.
		lookupDeleteFailed := make(map[mgmtDNSRuleKey]bool)
		for _, key := range sortedMgmtDNSRuleKeys(lookups) {
			if _, keep := wanted[key]; keep || failedShadow[key] {
				continue
			}
			for _, rule := range lookups[key] {
				if err := deleteMgmtDNSRule(ops, rule, mgmtDNSRuleLookupTable); err != nil {
					errs = append(errs, fmt.Errorf("remove stale management DNS lookup to %s: %w", key.dst, err))
					lookupDeleteFailed[key] = true
				}
			}
		}
		for _, key := range sortedMgmtDNSRuleKeys(shadows) {
			if _, keep := wanted[key]; keep || lookupDeleteFailed[key] {
				continue
			}
			for _, rule := range shadows[key] {
				if err := deleteMgmtDNSRule(ops, rule, unix.RT_TABLE_UNSPEC); err != nil {
					errs = append(errs, fmt.Errorf("remove stale management DNS miss shadow to %s: %w", key.dst, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// mgmtDNSRuleReadiness returns only nameservers whose lease-scoped lookup and
// unreachable shadow are both installed. The resolver merge uses this as a
// fail-closed publication gate if either netlink rule could not be reconciled.
func mgmtDNSRuleReadiness(ops mgmtDNSRuleOps) (map[string]bool, error) {
	lookups := make(map[mgmtDNSRuleKey]int)
	shadows := make(map[mgmtDNSRuleKey]int)
	invalids := make(map[mgmtDNSRuleKey]bool)
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("read management DNS rules family %d: %w", family, err))
			continue
		}
		for _, rule := range rules {
			key, kind, ok := managedMgmtDNSRule(rule)
			if !ok || key.family != family {
				continue
			}
			switch kind {
			case "lookup":
				lookups[key]++
			case "shadow":
				shadows[key]++
			case "invalid":
				invalids[key] = true
			}
		}
	}
	ready := make(map[string]bool)
	for key, count := range lookups {
		if count != 1 || shadows[key] != 1 || invalids[key] {
			continue
		}
		prefix, err := netip.ParsePrefix(key.dst)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse installed management DNS rule destination %q: %w", key.dst, err))
			continue
		}
		ready[prefix.Addr().String()] = true
	}
	return ready, errors.Join(errs...)
}

func managedMgmtDNSRule(rule netlink.Rule) (mgmtDNSRuleKey, string, bool) {
	if rule.IifName != mgmtDNSRuleInterface || rule.Dst == nil || !mgmtDNSRuleSelectorsExact(rule) {
		return mgmtDNSRuleKey{}, "", false
	}
	ones, bits := rule.Dst.Mask.Size()
	if ones != bits {
		return mgmtDNSRuleKey{}, "", false
	}
	switch rule.Family {
	case unix.AF_INET:
		if bits != 32 {
			return mgmtDNSRuleKey{}, "", false
		}
	case unix.AF_INET6:
		if bits != 128 {
			return mgmtDNSRuleKey{}, "", false
		}
	default:
		return mgmtDNSRuleKey{}, "", false
	}
	key := mgmtDNSRuleKey{family: rule.Family, dst: rule.Dst.String()}
	switch rule.Priority {
	case mgmtDNSRulePriority:
		if rule.Table == mgmtDNSRuleLookupTable && rule.Type == unix.RTN_UNICAST {
			return key, "lookup", true
		}
		return key, "invalid", true
	case mgmtDNSRuleShadowPriority:
		if rule.Table == unix.RT_TABLE_UNSPEC && rule.Type == nl.FR_ACT_UNREACHABLE {
			return key, "shadow", true
		}
		return key, "invalid", true
	default:
		return mgmtDNSRuleKey{}, "", false
	}
}

func mgmtDNSRuleSelectorsExact(rule netlink.Rule) bool {
	return !rule.Invert && rule.Src == nil && rule.Mark == 0 && rule.Mask == nil &&
		rule.Tos == 0 && rule.TunID == 0 && rule.Goto == -1 && rule.Flow == -1 &&
		rule.OifName == "" && rule.SuppressIfgroup == -1 && rule.SuppressPrefixlen == -1 &&
		rule.Dport == nil && rule.Sport == nil && rule.IPProto == 0 &&
		rule.UIDRange == nil && rule.Protocol == 0
}

func sortedMgmtDNSRuleKeys(rules map[mgmtDNSRuleKey][]netlink.Rule) []mgmtDNSRuleKey {
	keys := make([]mgmtDNSRuleKey, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].family != keys[j].family {
			return keys[i].family < keys[j].family
		}
		return keys[i].dst < keys[j].dst
	})
	return keys
}
func deleteExactMgmtDNSRule(ops mgmtDNSRuleOps, rule netlink.Rule) error {
	err := ops.RuleDel(&rule)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func deleteMgmtDNSRule(ops mgmtDNSRuleOps, rule netlink.Rule, table int) error {
	candidate := rule
	candidate.Table = table
	err := ops.RuleDel(&candidate)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}
