package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	// Management DNS steering runs after the VRF-miss terminator: a lookup
	// bound to a tenant VRF must fail in that VRF instead of falling through
	// to the management table. Keep each miss shadow adjacent to its lookup so
	// a missing table-999 route cannot fall through to main's WAN default.
	// Only DNS traffic is steered (#14971): each protocol gets its own
	// lookup/shadow pair scoped by FRA_IP_PROTO + destination port 53, so
	// non-DNS host traffic to a nameserver's IP (SSH, NTP, monitoring, ...)
	// keeps its main-table route instead of being hijacked into table 999 or
	// blackholed by the shadow. Legacy unscoped pairs (UDP/TCP priorities
	// 2500/2501) are reconciled away as invalid (#14971 migration).
	mgmtDNSUDPRulePriority    = 2500
	mgmtDNSUDPShadowPriority  = mgmtDNSUDPRulePriority + 1
	mgmtDNSTCPRulePriority    = 2502
	mgmtDNSTCPShadowPriority  = mgmtDNSTCPRulePriority + 1
	mgmtDNSRulePriority       = mgmtDNSUDPRulePriority
	mgmtDNSRuleShadowPriority = mgmtDNSUDPShadowPriority
	mgmtDNSRuleInterface      = "lo"
	mgmtDNSRuleLookupTable    = config.ManagementVRFTableID
	mgmtDNSPort               = 53
)

const (
	_ = uint(mgmtDNSUDPRulePriority - 2001) // after VRF miss terminator at 2000
	_ = uint(config.PBRRulePriorityBase - mgmtDNSTCPShadowPriority - 1)
)

// mgmtDNSProtocols are the DNS transports, in priority order. A kernel ip
// rule carries exactly one FRA_IP_PROTO value, so DNS-over-UDP and
// DNS-over-TCP each need their own lookup/shadow pair (#14971).
var mgmtDNSProtocols = []struct {
	proto          int
	lookupPriority int
	shadowPriority int
}{
	{proto: unix.IPPROTO_UDP, lookupPriority: mgmtDNSUDPRulePriority, shadowPriority: mgmtDNSUDPShadowPriority},
	{proto: unix.IPPROTO_TCP, lookupPriority: mgmtDNSTCPRulePriority, shadowPriority: mgmtDNSTCPShadowPriority},
}

type mgmtDNSRuleProto struct {
	proto          int
	lookupPriority int
	shadowPriority int
}

func mgmtDNSProtoForPriority(priority int) (mgmtDNSRuleProto, bool) {
	for _, p := range mgmtDNSProtocols {
		if priority == p.lookupPriority || priority == p.shadowPriority {
			return mgmtDNSRuleProto(p), true
		}
	}
	return mgmtDNSRuleProto{}, false
}

func mgmtDNSIsLookupPriority(priority int) bool {
	for _, p := range mgmtDNSProtocols {
		if priority == p.lookupPriority {
			return true
		}
	}
	return false
}

func mgmtDNSIsShadowPriority(priority int) bool {
	for _, p := range mgmtDNSProtocols {
		if priority == p.shadowPriority {
			return true
		}
	}
	return false
}

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
				// Kernel emits FRA_IP_PROTO as u8 (1 byte); the previous
				// u32 decode only ever saw our synthetic 4-byte fixtures.
				// Accept 1..4 bytes, fail closed on empty/oversize (#14971).
				if len(attr.Value) < 1 || len(attr.Value) > 4 {
					return nil, fmt.Errorf("invalid policy-rule IP protocol attribute length %d in family %d", len(attr.Value), family)
				}
				var protoBuf [4]byte
				copy(protoBuf[:], attr.Value)
				rule.IPProto = int(nl.NativeEndian().Uint32(protoBuf[:]))
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
	proto  int
}

type mgmtDNSRulePair struct {
	key    mgmtDNSRuleKey
	lookup netlink.Rule
	shadow netlink.Rule
}

// mgmtDNSRulePairs builds host-only lookup/terminal pairs for nameservers on
// management-VRF DHCP leases, one pair per DNS transport (UDP, TCP).
// Locally generated default-context traffic has iif=lo; the rules are
// additionally scoped by protocol and destination port 53 (#14971) so only
// DNS traffic is steered — non-DNS host traffic to the same IP keeps its
// main-table route. Tenant-VRF local traffic reaches the existing l3mdev
// miss terminator at priority 2000 before these rules can match.

// mgmtDNSRefusedNameserver reports whether a management-DHCP nameserver
// must be refused steering/publication (#15059, A36-01 residual). Even
// DNS-scoped steering is wrong when the address is already reachable via
// the default context: a main-table connected (RTPROT_KERNEL, no gateway)
// or static (RTPROT_STATIC) route covering it, or an exact configured
// control-plane peer (cluster control/fabric peers). Refusing keeps its
// DNS on the main route the operator/peer topology already selected,
// instead of diverting it into table 999. Peer matching is exact-address
// only — a peer's connected prefix does not refuse unrelated hosts.
func mgmtDNSRefusedNameserver(ip netip.Addr, mainRoutes []netlink.Route, cfg *config.Config) (string, bool) {
	if !ip.IsValid() {
		return "", false
	}
	family := netlink.FAMILY_V6
	if ip.Is4() {
		family = netlink.FAMILY_V4
	}
	for _, route := range mainRoutes {
		if route.Table != unix.RT_TABLE_MAIN && route.Table != 0 {
			continue
		}
		if route.Protocol != unix.RTPROT_KERNEL && route.Protocol != unix.RTPROT_STATIC {
			continue
		}
		if route.Protocol == unix.RTPROT_KERNEL && !mgmtRouteIsConnected(route, family) {
			continue
		}
		prefix, ok := mgmtRoutePrefix(route, family)
		if !ok || !prefix.Contains(ip) {
			continue
		}
		kind := "static"
		if route.Protocol == unix.RTPROT_KERNEL {
			kind = "connected"
		}
		return fmt.Sprintf("covered by main-table %s route %s", kind, prefix.String()), true
	}
	if cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		for _, raw := range []string{cc.PeerAddress, cc.FabricPeerAddress, cc.Fabric1PeerAddress} {
			peer, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			if peer.Unmap() == ip.Unmap() {
				return "matches configured control-plane peer " + peer.String(), true
			}
		}
	}
	return "", false
}

// mgmtDNSRulePairsFiltered is mgmtDNSRulePairs with #15059 refusal: refused
// nameservers get no pairs (so reconcile also removes any stale pairs for
// them, since they leave the wanted set) and are warned about once per
// distinct server.
func mgmtDNSRulePairsFiltered(leases []*dhcp.Lease, mgmtSet map[string]bool, mainRoutes []netlink.Route, cfg *config.Config) []mgmtDNSRulePair {
	warned := make(map[netip.Addr]bool)
	filtered := make([]*dhcp.Lease, 0, len(leases))
	for _, lease := range leases {
		if lease == nil {
			filtered = append(filtered, lease)
			continue
		}
		kept := *lease
		kept.DNS = nil
		for _, ip := range lease.DNS {
			if mgmtSet[lease.Interface] {
				if reason, refused := mgmtDNSRefusedNameserver(ip, mainRoutes, cfg); refused {
					if !warned[ip] {
						warned[ip] = true
						slog.Warn("SECURITY: refusing management DHCP nameserver "+reason+" (#15059); its DNS will use the main-table route, not table 999",
							"interface", lease.Interface, "server", ip.String(), "reason", reason)
					}
					continue
				}
			}
			kept.DNS = append(kept.DNS, ip)
		}
		filtered = append(filtered, &kept)
	}
	return mgmtDNSRulePairs(filtered, mgmtSet)
}

// mgmtDNSMainRoutes lists main-table routes for both families. A list
// failure returns an error so the caller fails closed (no steering, no
// publication) rather than steering a possibly-covered nameserver.
func mgmtDNSMainRoutes() ([]netlink.Route, error) {
	var out []netlink.Route
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, fmt.Errorf("list main-table routes family %d: %w", family, err)
		}
		out = append(out, routes...)
	}
	return out, nil
}

// mgmtDNSRefusedSet returns refused nameserver strings for the publication
// gate (#15059): even a complete installed pair must not make a
// covered/peer nameserver publishable.
func mgmtDNSRefusedSet(leases []*dhcp.Lease, mgmtSet map[string]bool, mainRoutes []netlink.Route, cfg *config.Config) map[string]bool {
	refused := make(map[string]bool)
	for _, lease := range leases {
		if lease == nil || !mgmtSet[lease.Interface] {
			continue
		}
		for _, ip := range lease.DNS {
			if _, ok := mgmtDNSRefusedNameserver(ip, mainRoutes, cfg); ok {
				refused[ip.String()] = true
			}
		}
	}
	return refused
}
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
			_, dst, err := net.ParseCIDR(prefix.String())
			if err != nil {
				continue // PrefixFrom above produces a canonical, valid CIDR.
			}
			for _, mp := range mgmtDNSProtocols {
				key := mgmtDNSRuleKey{family: family, dst: prefix.String(), proto: mp.proto}
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
				lookup := netlink.NewRule()
				lookup.Family = family
				lookup.Priority = mp.lookupPriority
				lookup.Table = mgmtDNSRuleLookupTable
				lookup.Type = unix.RTN_UNICAST
				lookup.IifName = mgmtDNSRuleInterface
				lookup.Dst = dst
				lookup.IPProto = mp.proto
				lookup.Dport = netlink.NewRulePortRange(mgmtDNSPort, mgmtDNSPort)

				shadow := *lookup
				shadow.Dport = netlink.NewRulePortRange(mgmtDNSPort, mgmtDNSPort)
				shadow.Priority = mp.shadowPriority
				shadow.Table = unix.RT_TABLE_UNSPEC
				shadow.Type = nl.FR_ACT_UNREACHABLE
				pairs = append(pairs, mgmtDNSRulePair{key: key, lookup: *lookup, shadow: shadow})
			}
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key.family != pairs[j].key.family {
			return pairs[i].key.family < pairs[j].key.family
		}
		if pairs[i].key.dst != pairs[j].key.dst {
			return pairs[i].key.dst < pairs[j].key.dst
		}
		return pairs[i].key.proto < pairs[j].key.proto
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
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	mainRoutes, err := mgmtDNSMainRoutes()
	if err != nil {
		// Fail closed (#15059): without the main inventory we cannot prove
		// a nameserver is not already main-covered, so install nothing.
		// Existing rules are left for the next successful reconcile; the
		// publication gate independently refuses covered/peer servers.
		slog.Warn("SECURITY: refusing management DNS steering without main-table inventory (#15059)", "err", err)
		return err
	}
	return reconcileMgmtDNSRulesFiltered(netlinkMgmtDNSRuleOps{}, leases, d.mgmtVRFIfaceSet(), mainRoutes, cfg)
}

func reconcileMgmtDNSRules(ops mgmtDNSRuleOps, leases []*dhcp.Lease, mgmtSet map[string]bool) error {
	return reconcileMgmtDNSRulesFiltered(ops, leases, mgmtSet, nil, nil)
}

func reconcileMgmtDNSRulesFiltered(ops mgmtDNSRuleOps, leases []*dhcp.Lease, mgmtSet map[string]bool, mainRoutes []netlink.Route, cfg *config.Config) error {
	pairs := mgmtDNSRulePairsFiltered(leases, mgmtSet, mainRoutes, cfg)
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
		// action/table/proto/port can preempt the intended pair. Remove them
		// exactly before installing anything; if removal fails, suppress
		// resolver publication for every protocol of that destination. A
		// legacy unscoped invalid (proto 0) blocks both protocols (#14971).
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
			for _, mp := range mgmtDNSProtocols {
				protoKey := mgmtDNSRuleKey{family: key.family, dst: key.dst, proto: mp.proto}
				failedShadow[protoKey] = true
				blocked[protoKey] = true
				for _, lookup := range lookups[protoKey] {
					if err := deleteMgmtDNSRule(ops, lookup, mgmtDNSRuleLookupTable); err != nil {
						errs = append(errs, fmt.Errorf("remove management DNS lookup behind invalid rule to %s: %w", key.dst, err))
					}
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

// mgmtDNSRuleReadiness returns only nameservers whose UDP and TCP
// lookup/unreachable-shadow pairs are all installed exactly once (#14971).
// The resolver merge uses this as a fail-closed publication gate if any
// netlink rule could not be reconciled or a legacy/wrong-proto rule remains.
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
				// A legacy/wrong-proto invalid carries proto 0; poison every
				// protocol key for the same destination.
				for _, mp := range mgmtDNSProtocols {
					invalids[mgmtDNSRuleKey{family: key.family, dst: key.dst, proto: mp.proto}] = true
				}
			}
		}
	}
	type dstID struct {
		family int
		dst    string
	}
	candidates := make(map[dstID]bool)
	for key := range lookups {
		candidates[dstID{family: key.family, dst: key.dst}] = true
	}
	ready := make(map[string]bool)
	for id := range candidates {
		okAll := true
		for _, mp := range mgmtDNSProtocols {
			key := mgmtDNSRuleKey{family: id.family, dst: id.dst, proto: mp.proto}
			if lookups[key] != 1 || shadows[key] != 1 || invalids[key] {
				okAll = false
				break
			}
		}
		if !okAll {
			continue
		}
		prefix, err := netip.ParsePrefix(id.dst)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse installed management DNS rule destination %q: %w", id.dst, err))
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
	if mgmtDNSIsLookupPriority(rule.Priority) || mgmtDNSIsShadowPriority(rule.Priority) {
		expected, known := mgmtDNSProtoForPriority(rule.Priority)
		if !known || rule.IPProto != expected.proto || !mgmtDNSDportIsDNS(rule) {
			// Legacy pre-#14971 unscoped rule (no proto/port) or a
			// wrong-proto/port rule at a reserved priority: invalid, so
			// reconcile removes it exactly and blocks resolver publication.
			// Key stays proto-less; readiness invalidates via priority.
			return mgmtDNSRuleKey{family: rule.Family, dst: rule.Dst.String()}, "invalid", true
		}
		key := mgmtDNSRuleKey{family: rule.Family, dst: rule.Dst.String(), proto: rule.IPProto}
		if mgmtDNSIsLookupPriority(rule.Priority) {
			if rule.Table == mgmtDNSRuleLookupTable && rule.Type == unix.RTN_UNICAST {
				return key, "lookup", true
			}
			return key, "invalid", true
		}
		if rule.Table == unix.RT_TABLE_UNSPEC && rule.Type == nl.FR_ACT_UNREACHABLE {
			return key, "shadow", true
		}
		return key, "invalid", true
	}
	return mgmtDNSRuleKey{}, "", false
}

func mgmtDNSDportIsDNS(rule netlink.Rule) bool {
	return rule.Dport != nil && rule.Dport.Start == mgmtDNSPort && rule.Dport.End == mgmtDNSPort
}

// mgmtDNSRuleSelectorsExact reports whether every selector other than the
// #14971 protocol/destination-port pair (validated by the caller against the
// priority's protocol) is at its unset default, so a rule carrying any extra
// selector (source, mark, sport, uid, ...) is not mistaken for ours.
func mgmtDNSRuleSelectorsExact(rule netlink.Rule) bool {
	return !rule.Invert && rule.Src == nil && rule.Mark == 0 && rule.Mask == nil &&
		rule.Tos == 0 && rule.TunID == 0 && rule.Goto == -1 && rule.Flow == -1 &&
		rule.OifName == "" && rule.SuppressIfgroup == -1 && rule.SuppressPrefixlen == -1 &&
		rule.Sport == nil && rule.UIDRange == nil && rule.Protocol == 0
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
		if keys[i].dst != keys[j].dst {
			return keys[i].dst < keys[j].dst
		}
		return keys[i].proto < keys[j].proto
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
