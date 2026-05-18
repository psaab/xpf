// Phase 3 of #1043: extract the seven NAT-related ShowText case bodies
// into dedicated methods. Same methodology as Phases 1-2 (#1148, #1150):
// semantic relocation, no behavior change. Each case body is moved
// verbatim apart from `&buf` references becoming `buf` (passed-in
// `*strings.Builder`). Output is unchanged.

package grpcapi

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// showNATStatic renders `cli show security nat static` — static NAT and
// NPTv6 prefix rule-sets from configuration.
func (s *Server) showNATStatic(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		buf.WriteString("No static NAT rules configured.\n")
		return
	}
	for _, rs := range cfg.Security.NAT.Static {
		fmt.Fprintf(buf, "Static NAT rule-set: %s\n", rs.Name)
		fmt.Fprintf(buf, "  From zone: %s\n", rs.FromZone)
		for _, rule := range rs.Rules {
			fmt.Fprintf(buf, "  Rule: %s\n", rule.Name)
			fmt.Fprintf(buf, "    Match destination-address: %s\n", rule.Match)
			if rule.IsNPTv6 {
				fmt.Fprintf(buf, "    Then nptv6-prefix:         %s\n", rule.Then)
			} else {
				fmt.Fprintf(buf, "    Then static-nat prefix:    %s\n", rule.Then)
			}
		}
		buf.WriteString("\n")
	}
}

// showNATNPTv6 renders `cli show security nat nptv6` — only the NPTv6
// rules within the static rule-sets.
func (s *Server) showNATNPTv6(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		buf.WriteString("No NPTv6 rules configured.\n")
		return
	}
	found := false
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if !rule.IsNPTv6 {
				continue
			}
			if !found {
				fmt.Fprintf(buf, "%-20s %-20s %-50s %-50s\n",
					"Rule-set", "Rule", "External prefix", "Internal prefix")
				found = true
			}
			fmt.Fprintf(buf, "%-20s %-20s %-50s %-50s\n",
				rs.Name, rule.Name, rule.Match, rule.Then)
		}
	}
	if !found {
		buf.WriteString("No NPTv6 rules configured.\n")
	}
}

// showPersistentNAT renders the persistent-NAT bindings table with
// remaining timeout per binding.
func (s *Server) showPersistentNAT(buf *strings.Builder) {
	if s.dp == nil || s.dp.GetPersistentNAT() == nil {
		buf.WriteString("Persistent NAT table not available\n")
		return
	}
	bindings := s.dp.GetPersistentNAT().All()
	if len(bindings) == 0 {
		buf.WriteString("No persistent NAT bindings\n")
		return
	}
	fmt.Fprintf(buf, "Total persistent NAT bindings: %d\n\n", len(bindings))
	fmt.Fprintf(buf, "%-20s %-8s %-20s %-8s %-15s %-10s\n",
		"Source IP", "SrcPort", "NAT IP", "NATPort", "Pool", "Timeout")
	for _, b := range bindings {
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}
		fmt.Fprintf(buf, "%-20s %-8d %-20s %-8d %-15s %-10s\n",
			b.SrcIP, b.SrcPort, b.NatIP, b.NatPort, b.PoolName,
			remaining.Truncate(time.Second))
	}
}

// showNATSourceRuleDetail renders detailed source NAT rule information,
// including pool details, translation hit counters, and active session
// counts per rule-set.
func (s *Server) showNATSourceRuleDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		buf.WriteString("No source NAT rules configured\n")
		return
	}
	// Count active SNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	cr := s.applyResult()
	if s.dp != nil && s.dp.IsLoaded() && cr != nil {
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			} else if rule.Then.Off {
				action = "off"
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Fprintf(buf, "source NAT rule: %s\n", rule.Name)
			fmt.Fprintf(buf, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(buf, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Fprintf(buf, "    Match:\n")
			fmt.Fprintf(buf, "      Source addresses:      %s\n", srcMatch)
			fmt.Fprintf(buf, "      Destination addresses: %s\n", dstMatch)
			if rule.Match.Protocol != "" {
				fmt.Fprintf(buf, "      IP protocol:           %s\n", rule.Match.Protocol)
			}
			fmt.Fprintf(buf, "    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
				if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
					if pool.PersistentNAT != nil {
						fmt.Fprintf(buf, "    Persistent NAT:          enabled\n")
					}
					if len(pool.Addresses) > 0 {
						fmt.Fprintf(buf, "    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
					}
					portLow, portHigh := pool.PortLow, pool.PortHigh
					if portLow == 0 {
						portLow = 1024
					}
					if portHigh == 0 {
						portHigh = 65535
					}
					fmt.Fprintf(buf, "    Port range:              %d-%d\n", portLow, portHigh)
				}
			}

			if s.dp != nil && cr != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Fprintf(buf, "    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Fprintf(buf, "    Number of sessions:      %d\n\n", sessions)
		}
	}
}

// showNATDestRuleDetail renders detailed destination NAT rule
// information, including pool address/port, translation hit counters,
// and active session counts per rule-set.
func (s *Server) showNATDestRuleDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		buf.WriteString("No destination NAT rules configured\n")
		return
	}
	dnat := cfg.Security.NAT.Destination
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	cr := s.applyResult()
	if s.dp != nil && s.dp.IsLoaded() && cr != nil {
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Fprintf(buf, "destination NAT rule: %s\n", rule.Name)
			fmt.Fprintf(buf, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(buf, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Fprintf(buf, "    Match:\n")
			fmt.Fprintf(buf, "      Destination addresses: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Fprintf(buf, "      Destination port:      %d\n", rule.Match.DestinationPort)
			}
			if rule.Match.Protocol != "" {
				fmt.Fprintf(buf, "      IP protocol:           %s\n", rule.Match.Protocol)
			}
			if rule.Match.Application != "" {
				fmt.Fprintf(buf, "      Application:           %s\n", rule.Match.Application)
			}
			fmt.Fprintf(buf, "    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && dnat.Pools != nil {
				if pool, ok := dnat.Pools[rule.Then.PoolName]; ok {
					fmt.Fprintf(buf, "    Pool address:            %s\n", pool.Address)
					if pool.Port != 0 {
						fmt.Fprintf(buf, "    Pool port:               %d\n", pool.Port)
					}
				}
			}

			if s.dp != nil && cr != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Fprintf(buf, "    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Fprintf(buf, "    Number of sessions:      %d\n\n", sessions)
		}
	}
}

// showPersistentNATDetail renders per-binding detail for persistent-NAT
// bindings, including current session counts per (NAT IP, NAT port).
func (s *Server) showPersistentNATDetail(buf *strings.Builder) {
	if s.dp == nil || s.dp.GetPersistentNAT() == nil {
		buf.WriteString("Persistent NAT table not available\n")
		return
	}
	bindings := s.dp.GetPersistentNAT().All()
	if len(bindings) == 0 {
		buf.WriteString("No persistent NAT bindings\n")
		return
	}
	// natKey uses a unified `netip.Addr` so v4 and v6 NAT IPs share
	// one map. v4 sessions are stored via `netip.AddrFrom4` and v6
	// sessions via `netip.AddrFrom16` — matching the producer side
	// in conntrack/gc.go (Save calls). Persistent-NAT bindings store
	// `netip.Addr` directly so the lookup matches without
	// family-specific shimming (was: hardcoded `b.NatIP.As4()` which
	// panicked on v6 bindings).
	type natKey struct {
		addr netip.Addr
		port uint16
	}
	sessionCounts := make(map[natKey]int)
	if s.dp.IsLoaded() {
		_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				// SessionValue.NATSrcIP is a `uint32` holding the IP's
				// network-order bytes in native-endian word form (the
				// BPF `__be32` is serialized as native-endian uint32 by
				// cilium/ebpf; see CLAUDE.md "Byte Order"). Recover the
				// original 4 bytes via NativeEndian.PutUint32 to match
				// conntrack/gc.go:277-279's storage path. Do NOT use
				// BigEndian here — that would re-swap the bytes.
				var ip4 [4]byte
				binary.NativeEndian.PutUint32(ip4[:], val.NATSrcIP)
				sessionCounts[natKey{netip.AddrFrom4(ip4), val.NATSrcPort}]++
			}
			return true
		})
		_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				// Match conntrack/gc.go:397 — no Unmap, the binding
				// stores the 16-byte form for v6 NAT.
				addr := netip.AddrFrom16(val.NATSrcIP)
				sessionCounts[natKey{addr, val.NATSrcPort}]++
			}
			return true
		})
	}

	fmt.Fprintf(buf, "Total persistent NAT bindings: %d\n\n", len(bindings))
	for i, b := range bindings {
		if i > 0 {
			buf.WriteString("\n")
		}
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}
		sessions := sessionCounts[natKey{b.NatIP, b.NatPort}]

		fmt.Fprintf(buf, "Persistent NAT binding:\n")
		fmt.Fprintf(buf, "  Internal IP:        %s\n", b.SrcIP)
		fmt.Fprintf(buf, "  Internal port:      %d\n", b.SrcPort)
		fmt.Fprintf(buf, "  Reflexive IP:       %s\n", b.NatIP)
		fmt.Fprintf(buf, "  Reflexive port:     %d\n", b.NatPort)
		fmt.Fprintf(buf, "  Pool:               %s\n", b.PoolName)
		if b.PermitAnyRemoteHost {
			fmt.Fprintf(buf, "  Any remote host:    yes\n")
		}
		fmt.Fprintf(buf, "  Current sessions:   %d\n", sessions)
		fmt.Fprintf(buf, "  Left time:          %s\n", remaining.Truncate(time.Second))
		fmt.Fprintf(buf, "  Configured timeout: %ds\n", int(b.Timeout.Seconds()))
	}
}

// showNAT64 renders `cli show security nat nat64` — NAT64 rule-sets
// from configuration.
func (s *Server) showNAT64(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		buf.WriteString("No NAT64 rule-sets configured\n")
		return
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		fmt.Fprintf(buf, "NAT64 rule-set: %s\n", rs.Name)
		if rs.Prefix != "" {
			fmt.Fprintf(buf, "  Prefix:      %s\n", rs.Prefix)
		}
		if rs.SourcePool != "" {
			fmt.Fprintf(buf, "  Source pool:  %s\n", rs.SourcePool)
		}
		buf.WriteString("\n")
	}
}
