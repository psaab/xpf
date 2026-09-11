// Phase 4 of #1043: extract the DHCP, LLDP, and SNMP ShowText case
// bodies into dedicated methods. Same methodology as Phases 1-3
// (#1148, #1150, #1151): semantic relocation, no behavior change. Each
// case body is moved verbatim apart from `&buf` references becoming
// `buf` (passed-in `*strings.Builder`) and the original
// `if … { … } else { … }` flattened into an early-return form. Output
// is unchanged.

package grpcapi

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/termsafe"
)

// showSNMP renders `cli show snmp` — community/trap-group/USM-user
// summary from configuration.
func (s *Server) showSNMP(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.SNMP == nil {
		buf.WriteString("No SNMP configured\n")
		return
	}
	snmpCfg := cfg.System.SNMP
	if snmpCfg.Location != "" {
		fmt.Fprintf(buf, "Location:    %s\n", snmpCfg.Location)
	}
	if snmpCfg.Contact != "" {
		fmt.Fprintf(buf, "Contact:     %s\n", snmpCfg.Contact)
	}
	if snmpCfg.Description != "" {
		fmt.Fprintf(buf, "Description: %s\n", snmpCfg.Description)
	}
	if len(snmpCfg.Communities) > 0 {
		buf.WriteString("Communities:\n")
		// #6532: the SNMPv1/v2c community string IS the authenticator, and it
		// is the Communities map KEY — a plain string that the Secret newtype's
		// String() redaction does not cover (config.SNMPCommunity). Printing
		// the raw key leaked the cleartext credential on an RPC that is NOT
		// loopback-bound: ShowText is on the cluster-fabric allowlist (#4122),
		// so this render is reachable from the peer chassis over the fabric.
		// Both sibling surfaces were already hardened — pkg/cli `show snmp`
		// (#4111) and the pkg/api show-text handler (#5315); this one was left
		// in the clear.
		//
		// The mask is unconditional, matching pkg/api and the sibling gRPC
		// ShowConfig raw-AST redaction (#4051): gRPC carries no login class to
		// gate on, so unlike pkg/cli there is no privileged caller to exempt.
		// The authorization mode stays visible; only the secret is masked.
		// Iteration runs over the real (sorted) keys so the render stays
		// deterministic once every displayed key is the same placeholder
		// (mirrors #4712 on the REST sibling).
		for _, name := range sortedMapKeys(snmpCfg.Communities) {
			comm := snmpCfg.Communities[name]
			fmt.Fprintf(buf, "  %s: %s\n",
				config.SNMPCommunityDisplayName(name, true), comm.Authorization)
		}
	}
	// #6532: the remaining map iterations sort too, completing the #4712
	// determinism parity with the REST sibling (pkg/api/show_text.go, which
	// sorts communities AND trap groups). Go randomizes map iteration, so
	// these lines reordered between two identical requests.
	if len(snmpCfg.TrapGroups) > 0 {
		buf.WriteString("Trap groups:\n")
		for _, name := range sortedMapKeys(snmpCfg.TrapGroups) {
			tg := snmpCfg.TrapGroups[name]
			fmt.Fprintf(buf, "  %s: %s\n", name, strings.Join(tg.Targets, ", "))
		}
	}
	if len(snmpCfg.V3Users) > 0 {
		buf.WriteString("SNMPv3 USM users:\n")
		for _, name := range sortedMapKeys(snmpCfg.V3Users) {
			u := snmpCfg.V3Users[name]
			auth := u.AuthProtocol
			if auth == "" {
				auth = "none"
			}
			priv := u.PrivProtocol
			if priv == "" {
				priv = "none"
			}
			fmt.Fprintf(buf, "  %s: auth=%s priv=%s\n", name, auth, priv)
		}
	}
}

// sortedMapKeys returns a string-keyed map's keys in ascending order, so a
// config map renders deterministically across requests (Go randomizes map
// iteration order — #4712).
func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// showSNMPv3 renders the SNMPv3 USM user table.
func (s *Server) showSNMPv3(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.V3Users) == 0 {
		buf.WriteString("No SNMPv3 users configured\n")
		return
	}
	buf.WriteString("SNMPv3 USM Users:\n")
	fmt.Fprintf(buf, "  %-20s %-12s %-12s\n", "User", "Auth", "Privacy")
	for _, u := range cfg.System.SNMP.V3Users {
		auth := u.AuthProtocol
		if auth == "" {
			auth = "none"
		}
		priv := u.PrivProtocol
		if priv == "" {
			priv = "none"
		}
		fmt.Fprintf(buf, "  %-20s %-12s %-12s\n", u.Name, auth, priv)
	}
}

// showDHCPServer renders the active DHCPv4/v6 lease tables from the
// running Kea-backed DHCP server.
func (s *Server) showDHCPServer(buf *strings.Builder) {
	if s.dhcpServer == nil || !s.dhcpServer.IsRunning() {
		buf.WriteString("DHCP server not running\n")
		return
	}
	// #5938 Invariant 2/8: prefer the live lease_cmds DB over the memfile
	// snapshot, and surface a banner when the source is degraded (socket
	// unavailable → memfile fallback, or an unreadable sibling was skipped) so a
	// partial display is never mistaken for a healthy empty set.
	leases4, src4 := s.dhcpServer.GetLeasesWithSource4()
	leases6, src6 := s.dhcpServer.GetLeasesWithSource6()
	for _, b := range dhcpserver.DegradedBanners(src4, src6) {
		buf.WriteString(b + "\n")
	}
	if len(leases4) == 0 && len(leases6) == 0 {
		buf.WriteString("No active leases\n")
	}
	if len(leases4) > 0 {
		buf.WriteString("DHCPv4 Leases:\n")
		fmt.Fprintf(buf, "  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
		for _, l := range leases4 {
			fmt.Fprintf(buf, "  %-18s %-20s %-15s %-12s %s\n",
				l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.ValidLife, l.ExpireTime)
		}
	}
	if len(leases6) > 0 {
		buf.WriteString("DHCPv6 Leases:\n")
		// #5328 (A8-b2-F6): label the column "HWAddress", not "DUID". Kea's
		// GetLeases6 populates Lease.HWAddress (the link-layer address), not the
		// client DUID/IAID, so a "DUID" header mislabeled the rendered value.
		// This mirrors the pkg/cli fix (#4908) that the remote gRPC renderer,
		// reached by `cmd/cli`, previously missed.
		fmt.Fprintf(buf, "  %-40s %-20s %-15s %-12s %s\n", "Address", "HWAddress", "Hostname", "Lifetime", "Expires")
		for _, l := range leases6 {
			fmt.Fprintf(buf, "  %-40s %-20s %-15s %-12s %s\n",
				l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.ValidLife, l.ExpireTime)
		}
	}
}

// showDHCPServerDetail renders the configured DHCP pools plus the live
// lease tables annotated with subnet IDs.
func (s *Server) showDHCPServerDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || (cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil) {
		buf.WriteString("No DHCP server configured\n")
		return
	}
	// Pool configuration
	if srv := cfg.System.DHCPServer.DHCPLocalServer; srv != nil && len(srv.Groups) > 0 {
		buf.WriteString("DHCPv4 Server Configuration:\n")
		for name, group := range srv.Groups {
			fmt.Fprintf(buf, "  Group: %s\n", name)
			if len(group.Interfaces) > 0 {
				fmt.Fprintf(buf, "    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
			}
			for _, pool := range group.Pools {
				fmt.Fprintf(buf, "    Pool: %s\n", pool.Name)
				if pool.Subnet != "" {
					fmt.Fprintf(buf, "      Subnet: %s\n", pool.Subnet)
				}
				if pool.RangeLow != "" {
					fmt.Fprintf(buf, "      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
				}
				if pool.Router != "" {
					fmt.Fprintf(buf, "      Router: %s\n", pool.Router)
				}
				if len(pool.DNSServers) > 0 {
					fmt.Fprintf(buf, "      DNS: %s\n", strings.Join(pool.DNSServers, ", "))
				}
				if pool.LeaseTime > 0 {
					fmt.Fprintf(buf, "      Lease time: %ds\n", pool.LeaseTime)
				}
			}
		}
		buf.WriteString("\n")
	}
	if srv := cfg.System.DHCPServer.DHCPv6LocalServer; srv != nil && len(srv.Groups) > 0 {
		buf.WriteString("DHCPv6 Server Configuration:\n")
		for name, group := range srv.Groups {
			fmt.Fprintf(buf, "  Group: %s\n", name)
			if len(group.Interfaces) > 0 {
				fmt.Fprintf(buf, "    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
			}
			for _, pool := range group.Pools {
				fmt.Fprintf(buf, "    Pool: %s\n", pool.Name)
				if pool.Subnet != "" {
					fmt.Fprintf(buf, "      Subnet: %s\n", pool.Subnet)
				}
				if pool.RangeLow != "" {
					fmt.Fprintf(buf, "      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
				}
			}
		}
		buf.WriteString("\n")
	}
	// Leases with subnet IDs
	if s.dhcpServer != nil && s.dhcpServer.IsRunning() {
		// #5938 Invariant 2/8: live-socket-preferred read + degraded-source banner.
		leases4, src4 := s.dhcpServer.GetLeasesWithSource4()
		leases6, src6 := s.dhcpServer.GetLeasesWithSource6()
		for _, b := range dhcpserver.DegradedBanners(src4, src6) {
			buf.WriteString(b + "\n")
		}
		if len(leases4) == 0 && len(leases6) == 0 {
			buf.WriteString("Active leases: none\n")
		}
		if len(leases4) > 0 {
			fmt.Fprintf(buf, "DHCPv4 Leases (%d active):\n", len(leases4))
			fmt.Fprintf(buf, "  %-18s %-20s %-15s %-10s %-12s %s\n", "Address", "MAC", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases4 {
				fmt.Fprintf(buf, "  %-18s %-20s %-15s %-10s %-12s %s\n",
					l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		}
		if len(leases6) > 0 {
			fmt.Fprintf(buf, "DHCPv6 Leases (%d active):\n", len(leases6))
			// #5328 (A8-b2-F6): "HWAddress", not "DUID" — see showDHCPServer.
			fmt.Fprintf(buf, "  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "HWAddress", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Fprintf(buf, "  %-40s %-20s %-15s %-10s %-12s %s\n",
					l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		}
	} else {
		buf.WriteString("DHCP server not running (no lease data)\n")
	}
}

// showDHCPDynamicDNS renders the DHCP dynamic-DNS configuration summary +
// runtime counters, and (in detail mode) the records this node owns
// (#1387 inc-2). It reads the daemon's always-on DDNS manager via the
// injected stats/owned-records functions so the gRPC server does not hold
// the manager pointer directly.
func (s *Server) showDHCPDynamicDNS(cfg *config.Config, buf *strings.Builder, detail bool) {
	var ddns *config.DHCPDynamicDNSConfig
	if cfg != nil {
		ddns = cfg.System.DHCPServer.DynamicDNS
	}
	if ddns == nil {
		buf.WriteString("DHCP dynamic-DNS: not configured\n")
		return
	}
	buf.WriteString("DHCP Dynamic DNS:\n")
	fmt.Fprintf(buf, "  Enabled:         %t\n", ddns.Enabled)
	if ddns.Backend != "" {
		fmt.Fprintf(buf, "  Backend:         %s\n", ddns.Backend)
	}
	if ddns.Domain != "" {
		fmt.Fprintf(buf, "  Domain:          %s\n", ddns.Domain)
	}
	if ddns.UpdateServer != "" {
		// #9497: RedactURL, like show configuration / String / MarshalJSON and the
		// #5521 feed-URL render. This topic is PermView, and a userinfo-bearing
		// value would otherwise reach read-only clients and support bundles.
		fmt.Fprintf(buf, "  Update server:   %s\n", config.RedactURL(ddns.UpdateServer))
	}
	if ddns.ConflictPolicy != "" {
		fmt.Fprintf(buf, "  Conflict policy: %s\n", ddns.ConflictPolicy)
	}
	if ddns.TSIGKeyName != "" {
		// Never print the secret — only that a key is configured.
		fmt.Fprintf(buf, "  TSIG key:        %s (secret redacted)\n", ddns.TSIGKeyName)
	}

	if s.ddnsStatsFn == nil {
		buf.WriteString("\n  Runtime counters: unavailable\n")
		return
	}
	st := s.ddnsStatsFn()
	if st == nil {
		buf.WriteString("\n  Runtime counters: unavailable (manager not running)\n")
		return
	}
	if st.Degraded {
		fmt.Fprintf(buf, "\n  ALARM: DDNS DEGRADED (fail-closed) — %s\n", st.DegradedReason)
		buf.WriteString("    Publishing and withdrawals are SUSPENDED until the ownership state is resolved.\n")
	}
	if st.OrphanedBackendChange > 0 {
		// #5814: an update-server/TSIG-key change was detected while the old
		// endpoint was unreachable in-process; ownership is retained but the old
		// server may hold a stale record until an operator resolves it.
		fmt.Fprintf(buf, "\n  ALARM: %d record(s) pending backend-change cleanup — the update-server\n",
			st.OrphanedBackendChange)
		buf.WriteString("    changed while the old endpoint was unreachable; the old server may hold a\n")
		buf.WriteString("    stale record. Ownership is retained (never deleted at the wrong endpoint).\n")
	}
	buf.WriteString("\n  Counters:\n")
	fmt.Fprintf(buf, "    Upserts:    ok=%d fail=%d\n", st.UpsertOK, st.UpsertFail)
	fmt.Fprintf(buf, "    Deletes:    ok=%d fail=%d\n", st.DeleteOK, st.DeleteFail)
	fmt.Fprintf(buf, "    Reconciles: ok=%d fail=%d\n", st.ReconcileOK, st.ReconcileFail)
	fmt.Fprintf(buf, "    Skipped:    no-name=%d no-backend=%d conflict=%d ptr-notauth=%d\n",
		st.SkippedNoName, st.SkippedNoBackend, st.SkippedConflict, st.SkippedPTRNotAuth)
	fmt.Fprintf(buf, "    PTR deferred: %d total (lifetime), %d pending now\n",
		st.PTRDeferred, st.PTRPendingNow)
	fmt.Fprintf(buf, "    Owned records: %d\n", st.OwnedRecords)
	if !st.LastReconcile.IsZero() {
		fmt.Fprintf(buf, "    Last reconcile: %s (%d leases)\n",
			st.LastReconcile.Format(time.RFC3339), st.LastReconcileN)
	}

	if detail && s.ddnsOwnedRecordsFn != nil {
		recs := s.ddnsOwnedRecordsFn()
		buf.WriteString("\n  Owned records:\n")
		if len(recs) == 0 {
			buf.WriteString("    none\n")
		} else {
			fmt.Fprintf(buf, "    %-32s %-6s %-39s %-26s %s\n", "FQDN", "Type", "Address", "PTR", "Pending")
			for _, r := range recs {
				pending := "-"
				if r.PTRPending {
					pending = "PTR"
				}
				fmt.Fprintf(buf, "    %-32s %-6s %-39s %-26s %s\n",
					termsafe.SanitizeForDisplay(r.FQDN), r.ForwardType, r.Address, r.PTRName, pending)
			}
		}
	}
}

// showServicesDynamicDNS renders the Surface A (router/interface-address) DDNS
// status: the configured provider catalog, the runtime counters, and (detail)
// the per-scope last-published state (#2691 P2).
func (s *Server) showServicesDynamicDNS(cfg *config.Config, buf *strings.Builder, detail bool) {
	buf.WriteString("Dynamic DNS (Surface A — router/interface-address publish):\n")
	if cfg != nil && cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		cat := cfg.System.Services.DynamicDNS
		if len(cat.Providers) > 0 {
			buf.WriteString("  Providers:\n")
			names := make([]string, 0, len(cat.Providers))
			for n := range cat.Providers {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				p := cat.Providers[n]
				backend := p.Backend
				if backend == "" {
					backend = "rfc2136"
				}
				fmt.Fprintf(buf, "    %s: backend=%s update-server=%s", n, backend, config.RedactURL(p.UpdateServer)) // #9497
				if p.TSIGKeyName != "" {
					fmt.Fprintf(buf, " tsig-key=%s (secret redacted)", p.TSIGKeyName)
				}
				buf.WriteString("\n")
			}
		}
		if cat.ForcedRefreshSeconds > 0 {
			fmt.Fprintf(buf, "  Forced-refresh: %ds\n", cat.ForcedRefreshSeconds)
		}
		if cat.ErrorBackoffMaxSeconds > 0 {
			fmt.Fprintf(buf, "  Error-backoff-max: %ds\n", cat.ErrorBackoffMaxSeconds)
		}
	} else {
		buf.WriteString("  No provider catalog configured\n")
	}

	if s.surfaceADDNSStatsFn == nil {
		buf.WriteString("\n  Runtime counters: unavailable\n")
		return
	}
	st := s.surfaceADDNSStatsFn()
	if st == nil {
		buf.WriteString("\n  Runtime counters: unavailable (manager not running)\n")
		return
	}
	if st.Degraded {
		fmt.Fprintf(buf, "\n  ALARM: Surface A DDNS DEGRADED (fail-closed) — %s\n", st.DegradedReason)
		buf.WriteString("    Publishing and withdrawals are SUSPENDED until the ownership state is resolved.\n")
	}
	buf.WriteString("\n  Counters:\n")
	fmt.Fprintf(buf, "    Publishes: ok=%d fail=%d\n", st.UpsertOK, st.UpsertFail)
	fmt.Fprintf(buf, "    Withdraws: ok=%d fail=%d\n", st.DeleteOK, st.DeleteFail)
	fmt.Fprintf(buf, "    Skipped:   unchanged=%d backoff=%d no-backend=%d\n", st.Skipped, st.BackedOff, st.SkippedNoBackend)
	fmt.Fprintf(buf, "    Published records: %d\n", st.Scopes)

	if detail && s.surfaceADDNSStatusFn != nil {
		views := s.surfaceADDNSStatusFn()
		buf.WriteString("\n  Configured scopes:\n")
		if len(views) == 0 {
			buf.WriteString("    none\n")
		} else {
			fmt.Fprintf(buf, "    %-32s %-6s %-15s %-39s %-12s %s\n", "FQDN", "Family", "State", "Address", "Provider", "Last error")
			for _, v := range views {
				fam := "inet"
				if v.Family == 6 {
					fam = "inet6"
				}
				// #6468 D1: LastError can embed a DDNS PROVIDER response body.
				// Cloudflare (backend_cloudflare.go:166) and Route 53
				// (backend_route53.go:195,277) embed the provider's own message with
				// %s, so a hostile or compromised provider can land raw ESC bytes on
				// the operator terminal. The other backends do not: dyndns2 and
				// duckdns wrap the response token in %q, generic OMITS the body
				// entirely (it reports only the configured success tokens), and
				// rfc2136 reports a fixed rcode string. Sanitizing at the display site
				// covers the class regardless of which backend produced the string,
				// and survives a backend changing its format verb.
				lastErr := termsafe.SanitizeForDisplay(v.LastError)
				if lastErr == "" {
					lastErr = "-"
				}
				addr := v.Published
				if addr == "" {
					addr = "-"
				}
				fmt.Fprintf(buf, "    %-32s %-6s %-15s %-39s %-12s %s\n",
					v.FQDN, fam, v.State, addr, v.Provider, lastErr)
			}
		}
	}
}

// showDHCPRelay renders the configured DHCP relay server-groups and
// relay-groups.
func (s *Server) showDHCPRelay(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
		buf.WriteString("No DHCP relay configured\n")
		return
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if len(relay.ServerGroups) > 0 {
		buf.WriteString("Server groups:\n")
		for name, sg := range relay.ServerGroups {
			fmt.Fprintf(buf, "  %s: %s\n", name, strings.Join(sg.Servers, ", "))
		}
	}
	if len(relay.Groups) > 0 {
		buf.WriteString("Relay groups:\n")
		for name, g := range relay.Groups {
			fmt.Fprintf(buf, "  %s:\n", name)
			fmt.Fprintf(buf, "    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
			fmt.Fprintf(buf, "    Active server group: %s\n", g.ActiveServerGroup)
		}
	}
}

// showLLDP renders the configured LLDP transmit interval, hold
// multiplier, hold time, monitored interfaces, and current neighbor
// count.
func (s *Server) showLLDP(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.Protocols.LLDP == nil {
		buf.WriteString("LLDP not configured\n")
		return
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg.Disable {
		buf.WriteString("LLDP: disabled\n")
		return
	}
	interval := lldpCfg.Interval
	if interval <= 0 {
		interval = 30
	}
	holdMult := lldpCfg.HoldMultiplier
	if holdMult <= 0 {
		holdMult = 4
	}
	buf.WriteString("LLDP:\n")
	fmt.Fprintf(buf, "  Transmit interval: %ds\n", interval)
	fmt.Fprintf(buf, "  Hold multiplier:   %d\n", holdMult)
	fmt.Fprintf(buf, "  Hold time:         %ds\n", interval*holdMult)
	if len(lldpCfg.Interfaces) > 0 {
		var ifNames []string
		for _, iface := range lldpCfg.Interfaces {
			if iface.Disable {
				ifNames = append(ifNames, iface.Name+" (disabled)")
			} else {
				ifNames = append(ifNames, iface.Name)
			}
		}
		fmt.Fprintf(buf, "  Interfaces:        %s\n", strings.Join(ifNames, ", "))
	}
	if s.lldpNeighborsFn != nil {
		neighbors := s.lldpNeighborsFn()
		fmt.Fprintf(buf, "  Neighbors:         %d\n", len(neighbors))
	}
}

// showLLDPNeighbors renders the live LLDP neighbor table.
func (s *Server) showLLDPNeighbors(buf *strings.Builder) {
	if s.lldpNeighborsFn == nil {
		buf.WriteString("LLDP not running\n")
		return
	}
	neighbors := s.lldpNeighborsFn()
	if len(neighbors) == 0 {
		buf.WriteString("No LLDP neighbors discovered\n")
		return
	}
	fmt.Fprintf(buf, "%-12s %-20s %-16s %-20s %-6s %s\n",
		"Interface", "Chassis ID", "Port ID", "System Name", "TTL", "Age")
	for _, n := range neighbors {
		age := time.Since(n.LastSeen).Truncate(time.Second)
		fmt.Fprintf(buf, "%-12s %-20s %-16s %-20s %-6d %s\n",
			n.Interface, n.ChassisID, n.PortID, n.SystemName, n.TTL, age)
	}
}
