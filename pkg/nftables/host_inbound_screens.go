package nftables

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// HostInboundScreenFloodMeterSize caps entries in each per-source meter.
const HostInboundScreenFloodMeterSize = 65536

// HostInboundScreenFloodMeterTimeout expires idle per-source and aggregate buckets.
const HostInboundScreenFloodMeterTimeout = time.Minute

// Keep the coarse zone ceiling aligned with userspace-dp/src/screen/zone.rs:
// per-destination UDP/ICMP limits are followed by an 8x zone-saturation cap.
const hostInboundScreenFloodSecondaryCeilingMultiplier uint32 = 8

// HostInboundScreenFloodRule is one normalized per-zone, per-family flood
// screen. UDP and ICMP use per-source meters at their configured thresholds.
// SYN uses its configured zone attack threshold and optional source threshold.
type HostInboundScreenFloodRule struct {
	Zone               string
	Family             string // "ip" or "ip6"
	Protocol           string // "udp", "icmp", "icmpv6", or "tcp-syn"
	AggregateThreshold uint32
	SourceThreshold    uint32
	IngressNetdevs     []string
	IngressVRFScopes   []config.HostInboundVRFIngressScope
	Addresses          []string
	AlarmWithoutDrop   bool
}

// HostInboundScreenFloodRules coalesces per-interface host-inbound views into
// one screen budget per zone and address family. Ingress device scopes take
// precedence over destination addresses, matching the worker's ingress-zone
// screen selection; address matching is the fallback for views without an
// unambiguous ingress device.
func HostInboundScreenFloodRules(views []HostInboundZoneView) []HostInboundScreenFloodRule {
	type zoneFlood struct {
		v4, v6, ingress              map[string]struct{}
		vrfIngress                   map[string]map[string]struct{}
		icmp, udp, syn, synSource    uint32
		profileSet, alarmWithoutDrop bool
	}
	zones := make(map[string]*zoneFlood)
	for _, view := range views {
		z := zones[view.Zone]
		if z == nil {
			z = &zoneFlood{
				v4:         make(map[string]struct{}),
				v6:         make(map[string]struct{}),
				ingress:    make(map[string]struct{}),
				vrfIngress: make(map[string]map[string]struct{}),
			}
			zones[view.Zone] = z
		}
		for _, addr := range view.V4Addrs {
			z.v4[addr] = struct{}{}
		}
		for _, addr := range view.V6Addrs {
			z.v6[addr] = struct{}{}
		}
		for _, name := range hostInboundDirectIngressNetdevs(view) {
			z.ingress[name] = struct{}{}
		}
		for _, scope := range view.IngressVRFScopes {
			if scope.Master == "" {
				continue
			}
			if z.vrfIngress[scope.Master] == nil {
				z.vrfIngress[scope.Master] = make(map[string]struct{}, len(scope.Slaves))
			}
			for _, slave := range scope.Slaves {
				z.vrfIngress[scope.Master][slave] = struct{}{}
			}
		}

		active := view.ICMPFloodThreshold > 0 || view.UDPFloodThreshold > 0 ||
			view.SYNFloodThreshold > 0 || view.SYNFloodSrcThreshold > 0
		if active {
			if !z.profileSet {
				z.alarmWithoutDrop = view.AlarmWithoutDrop
				z.profileSet = true
			} else {
				z.alarmWithoutDrop = z.alarmWithoutDrop && view.AlarmWithoutDrop
			}
			z.icmp = lowerNonZero(z.icmp, view.ICMPFloodThreshold)
			z.udp = lowerNonZero(z.udp, view.UDPFloodThreshold)
			z.syn = lowerNonZero(z.syn, view.SYNFloodThreshold)
			z.synSource = lowerNonZero(z.synSource, view.SYNFloodSrcThreshold)
		}
	}

	zoneNames := make([]string, 0, len(zones))
	for name := range zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)

	var out []HostInboundScreenFloodRule
	for _, zoneName := range zoneNames {
		z := zones[zoneName]
		ingress := sortedKeys(z.ingress)
		for _, family := range []string{"ip", "ip6"} {
			addresses := sortedKeys(z.v4)
			if family == "ip6" {
				addresses = sortedKeys(z.v6)
			}
			if len(ingress) == 0 && len(z.vrfIngress) == 0 && len(addresses) == 0 {
				continue
			}
			appendRule := func(protocol string, aggregateThreshold, sourceThreshold uint32) {
				if aggregateThreshold == 0 && sourceThreshold == 0 {
					return
				}
				out = append(out, HostInboundScreenFloodRule{
					Zone:               zoneName,
					Family:             family,
					Protocol:           protocol,
					AggregateThreshold: aggregateThreshold,
					SourceThreshold:    sourceThreshold,
					IngressNetdevs:     ingress,
					IngressVRFScopes:   sortedScreenVRFScopes(z.vrfIngress),
					Addresses:          addresses,
					AlarmWithoutDrop:   z.alarmWithoutDrop,
				})
			}
			appendRule("udp", screenFloodSaturatingMultiply(z.udp, hostInboundScreenFloodSecondaryCeilingMultiplier), z.udp)
			if family == "ip" {
				appendRule("icmp", screenFloodSaturatingMultiply(z.icmp, hostInboundScreenFloodSecondaryCeilingMultiplier), z.icmp)
			} else {
				appendRule("icmpv6", screenFloodSaturatingMultiply(z.icmp, hostInboundScreenFloodSecondaryCeilingMultiplier), z.icmp)
			}
			appendRule("tcp-syn", z.syn, z.synSource)
		}
	}
	return out
}

func sortedScreenVRFScopes(scopes map[string]map[string]struct{}) []config.HostInboundVRFIngressScope {
	masters := make([]string, 0, len(scopes))
	for master := range scopes {
		masters = append(masters, master)
	}
	sort.Strings(masters)
	out := make([]config.HostInboundVRFIngressScope, 0, len(masters))
	for _, master := range masters {
		slaves := make([]string, 0, len(scopes[master]))
		for slave := range scopes[master] {
			slaves = append(slaves, slave)
		}
		sort.Strings(slaves)
		if len(slaves) > 0 {
			out = append(out, config.HostInboundVRFIngressScope{Master: master, Slaves: slaves})
		}
	}
	return out
}

// HostInboundScreenFloodSetName identifies the bounded dynamic source-meter set
// for one normalized screen rule.
func HostInboundScreenFloodSetName(rule HostInboundScreenFloodRule) string {
	return hostInboundScreenFloodName("xpf_his_s_", rule, "source")
}

// HostInboundScreenFloodAggregateSetName identifies the single-key dynamic
// meter shared by reply- and original-direction rule placements.
func HostInboundScreenFloodAggregateSetName(rule HostInboundScreenFloodRule) string {
	return hostInboundScreenFloodName("xpf_his_a_", rule, "aggregate")
}

// HostInboundScreenFloodCounterName identifies either the aggregate or
// per-source over-threshold counter for one normalized screen rule.
func HostInboundScreenFloodCounterName(rule HostInboundScreenFloodRule, source bool) string {
	scope := "aggregate"
	if source {
		scope = "source"
	}
	return hostInboundScreenFloodName("xpf_his_c_", rule, scope)
}

// HostInboundScreenFloodAlarmPrefix labels a rate-limited kernel log record
// with its protocol, family, and stable counter identity.
func HostInboundScreenFloodAlarmPrefix(rule HostInboundScreenFloodRule, source bool) string {
	return "xpf screen flood " + rule.Protocol + "/" + rule.Family + " " + HostInboundScreenFloodCounterName(rule, source) + ": "
}

func hostInboundScreenFloodName(prefix string, rule HostInboundScreenFloodRule, scope string) string {
	key := rule.Zone + "\x00" + rule.Family + "\x00" + rule.Protocol + "\x00" + scope
	sum := sha256.Sum256([]byte(key))
	return prefix + hex.EncodeToString(sum[:12])
}

func lowerNonZero(current, next uint32) uint32 {
	if next == 0 || (current != 0 && current <= next) {
		return current
	}
	return next
}

func screenFloodSaturatingMultiply(value, multiplier uint32) uint32 {
	if multiplier != 0 && value > ^uint32(0)/multiplier {
		return ^uint32(0)
	}
	return value * multiplier
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
