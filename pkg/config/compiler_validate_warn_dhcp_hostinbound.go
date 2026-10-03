package config

import (
	"fmt"
	"sort"
)

// compiler_validate_warn_dhcp_hostinbound.go carries the #6460 commit-time
// WARNING that a configured DHCP server is reachable on an interface whose
// security zone's `host-inbound-traffic system-services` set does NOT admit the
// matching DHCP token.
//
// WHY THIS IS ITS OWN ARM, AND NOT PART OF #11571. The #11571 enforcement gate
// scopes host-bound multicast by routing-protocol token, destination group,
// family, and ingress zone. DHCP server admission uses the separate
// `system-services` grammar: DHCP is neither a routing protocol nor rendered
// into FRR, so the managed-routing check cannot inspect it. In addition,
// DHCPv4 and DHCPv6 bypass these enforcement surfaces for different reasons
// described below, so this check needs its own diagnostics.
//
// THE MECHANISM, PER FAMILY. The two families are unenforced for DIFFERENT
// reasons, and the message says which, because an operator who is told the wrong
// reason will reach for the wrong remedy.
//
//   - DHCPv4 (`system services dhcp-local-server`) — TWO planes have to be
//     accounted for, and #7489 corrected this entry because it originally named
//     only one.
//
//     Plane 1, the XDP shim: a client's DISCOVER/REQUEST is addressed to the
//     255.255.255.255 BROADCAST, and `should_fallback_early`
//     (userspace-xdp/src/lib.rs) hands `dst_v4 == 0xffff_ffff` straight to the
//     kernel. So the request never enters the AF_XDP userspace dataplane and
//     never reaches its host-inbound gate.
//
//     Plane 2, netfilter: xpf renders Kea's Dhcp4 with no `dhcp-socket-type`
//     key (pkg/dhcpserver/dhcpserver.go builds `interfaces-config` with an
//     `interfaces` list and nothing else), so Kea's default `raw` applies and
//     the server receives on an AF_PACKET socket. AF_PACKET delivery happens
//     BEFORE the netfilter input hook, so the `xpf_hostinbound` chain cannot
//     gate it either.
//
//     Both planes are bypassed, so the token really does gate nothing for THIS
//     traffic — but the reason is the broadcast destination as much as the
//     socket type, and the two are not interchangeable. See the scope note
//     below before reusing this argument.
//
//   - DHCPv6 (`system services dhcpv6-local-server`) — Kea's Dhcp6 has no raw
//     mode; it receives on UDP. But a client's Solicit/Request is addressed to
//     the All_DHCP_Relay_Agents_and_Servers multicast group ff02::1:2, and every
//     per-zone host-inbound rule — the accepts AND the #3361 catch-all deny — is
//     scoped `<fam> daddr <zone unicast addrs>` (pkg/nftables/netlink_hostinbound.go,
//     emitHostInboundZoneNetlink). A multicast destination matches NEITHER, so it
//     falls through the base chain's `policy accept`
//     (pkg/nftables/netlink_installer.go) to the host stack. Same
//     fall-through the #4455 routing-multicast gap rides, applied to a service
//     rather than a routing protocol.
//
// WARN-ONLY, ZERO DATAPLANE SURFACE. No nft rule changes, no Rust change, no
// `iifname` predicate. The config is valid Junos and the box already serves it;
// rejecting would brick a commit on a working DHCP deployment for a condition
// that has been true since the feature shipped (#1960 no-brick). This function
// has no error return and takes no `lenient` flag, so the no-brick property is
// structural rather than a convention a later edit could quietly invert — the
// same posture the #5619 secure-tunnel-plaintext advisory takes for the same
// reason.
//
// WHY THE OPERATOR NEEDS TELLING. `host-inbound-traffic system-services` is the
// knob a Junos operator reaches for to bound which segments a host service
// answers on, and on Junos it DOES bound DHCP. Here the zone stanza commits
// cleanly, renders, and reads as enforced while the DHCP server answers on every
// interface its `dhcp-local-server` group binds regardless. An operator who
// tightens a zone and sees the commit accepted has been told something specific
// and untrue about their posture — the #5619 doctrine. The concrete exposure is
// a rogue-lease surface: a group bound to an interface in a zone that omits the
// token serves addresses, gateway and DNS to anything on that segment.
//
// THE REMEDY IS DELIBERATELY NOT "ADD THE TOKEN". Adding the token silences
// nothing real FOR THE DHCP SERVER'S REQUEST PATH — both planes above are
// bypassed — so telling the operator to add it as a FIX would be the same false
// signal in a new place. The message names both moves and labels them: remove
// the interface from the group (the move that actually stops serving that
// segment), or add the token to record the intent that the segment IS served.
//
// SCOPE, and do not generalise past it (#7489). "The AF_PACKET tap is upstream
// of netfilter" is an argument about ONE plane and does NOT establish that a
// host-inbound token is inert for v4 traffic at large. The AF_XDP userspace
// dataplane enforces host-inbound itself, fail-closed, on the local-delivery
// path (`host_inbound_gated_lo0_action`, userspace-dp poll_descriptor/filter.rs),
// and a packet dropped there never reaches the kernel on any device — so
// AF_PACKET cannot rescue it. MEASURED on the loss userspace cluster: 20
// unicast datagrams to an interface-mode-SNAT address on a port the arrival
// zone did not admit produced +22 host-inbound denies and ZERO packets on
// `tcpdump -ni any`, with a same-host ping (admitted) answering normally.
//
// What decides which plane applies is the DESTINATION, not the port: on a
// session miss the shim steers on address alone (`should_fallback_early`, then
// `is_local_destination`, which deliberately returns false for an address in
// `USERSPACE_INTERFACE_NAT_V4` — "the common WAN case"). A broadcast DISCOVER
// goes to the kernel; a unicast to an interface-mode-SNAT address is redirected
// into userspace and IS gated. That second case is not this advisory's subject,
// but the sentence above was being read as covering it.
//
// SCOPE. Interfaces only; a group with no interfaces binds nothing. An interface
// in no zone has no host-inbound dimension and is not reported (the zone lookup
// simply misses) — that is the same treatment the #4455 Component B arm gives it.

// dhcpHostInboundFamily is one DHCP family's advisory inputs: the stanza the
// operator authored, the `system-services` token Junos gates it with, and the
// per-family sentence explaining why the token is not enforced here.
type dhcpHostInboundFamily struct {
	srv     *DHCPLocalServerConfig
	stanza  string // authored stanza name, for the message
	token   string // host-inbound system-services token Junos gates this with
	whyOpen string // family-specific mechanism sentence
}

// validateDHCPServerHostInboundBypassWarnings emits the #6460 advisory. One
// warning per (group, interface) pair whose zone omits the family's token,
// sorted for deterministic commit output.
func validateDHCPServerHostInboundBypassWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	ifZone := dhcpHostInboundZoneMap(cfg)
	if len(ifZone) == 0 {
		return nil
	}

	families := []dhcpHostInboundFamily{
		{
			srv:    cfg.System.DHCPServer.DHCPLocalServer,
			stanza: "dhcp-local-server",
			token:  "dhcp",
			whyOpen: "a DHCPv4 client addresses the server at the 255.255.255.255 broadcast, " +
				"which the XDP shim hands to the kernel without entering the userspace " +
				"dataplane, and Kea then receives it on an AF_PACKET raw socket delivered " +
				"BEFORE the netfilter input hook — so neither host-inbound plane sees the " +
				"request",
		},
		{
			srv:    cfg.System.DHCPServer.DHCPv6LocalServer,
			stanza: "dhcpv6-local-server",
			token:  "dhcpv6",
			whyOpen: "a DHCPv6 client addresses the server at the ff02::1:2 multicast group, " +
				"and every per-zone host-inbound rule is scoped to the zone's UNICAST " +
				"addresses, so the request matches no rule and falls through the input " +
				"chain's accept policy",
		},
	}

	var warnings []string
	for _, fam := range families {
		if fam.srv == nil {
			continue
		}
		gnames := make([]string, 0, len(fam.srv.Groups))
		for name := range fam.srv.Groups {
			gnames = append(gnames, name)
		}
		sort.Strings(gnames)
		for _, gname := range gnames {
			g := fam.srv.Groups[gname]
			if g == nil { // #3494: tolerant/HA-sync path may carry a nil value
				continue
			}
			for _, ifn := range g.Interfaces {
				zname, ok := ifZone[ifn]
				if !ok {
					continue
				}
				z := cfg.Security.Zones[zname]
				if z == nil {
					continue
				}
				// EFFECTIVE host-inbound system-services for this interface: the
				// per-interface override where declared REPLACES the zone-level
				// set (#6515/#3362), with #3720 physical-parent inheritance for a
				// logical unit. Reuse the InterfaceHostInboundEffective SSOT so
				// the advisory resolves admission exactly as the dataplane does —
				// a parent `reth0` override admitting dhcp must cover unit
				// `reth0.80`, else this warns falsely.
				effSvc, _, _ := z.InterfaceHostInboundEffective(ifn)
				if hostInboundAdmitsSystemService(effSvc, fam.token) {
					continue
				}
				warnings = append(warnings, fmt.Sprintf(
					"system services %s group %q serves interface %q (security zone %q) but "+
						"that zone's host-inbound-traffic system-services set omits %q — the "+
						"DHCP server answers on that interface REGARDLESS of the zone's "+
						"host-inbound set, because %s (#6460). The zone stanza does not bound "+
						"it. To stop serving that segment, remove %q from group %q; to record "+
						"that the segment IS meant to be served, add "+
						"`host-inbound-traffic system-services %s` to zone %q.",
					fam.stanza, gname, ifn, zname, fam.token, fam.whyOpen,
					ifn, gname, fam.token, zname))
			}
		}
	}
	sort.Strings(warnings)
	return warnings
}

// dhcpHostInboundZoneMap builds interface-ref -> zone-name exactly as the #4455
// Component B advisory does, mirroring the dataplane's buildInterfaceZoneMap
// (#3072) through the zoneIfaceLogicalKeys SSOT: bare zone members claim the
// physical key and configured units, while unit-qualified entries claim one
// logical unit. Quarantined zones and ambiguous keys are omitted so an advisory
// never attributes behavior to a sorted-name winner.
func dhcpHostInboundZoneMap(cfg *Config) map[string]string {
	ifZone := make(map[string]string)
	znames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		znames = append(znames, name)
	}
	sort.Strings(znames)
	excludedZones := ZoneQuarantineExclusions(znames)
	conflictedInterfaces := QuarantinedZoneInterfaceKeys(cfg)
	for _, zname := range znames {
		if _, excluded := excludedZones[zname]; excluded {
			continue
		}
		z := cfg.Security.Zones[zname]
		if z == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifEntry := range z.Interfaces {
			for _, key := range zoneIfaceLogicalKeys(cfg, ifEntry) {
				if _, conflicted := conflictedInterfaces[key]; conflicted {
					continue
				}
				if _, seen := ifZone[key]; !seen {
					ifZone[key] = zname
				}
			}
		}
	}
	return ifZone
}

// hostInboundAdmitsSystemService reports whether a host-inbound-traffic
// `system-services` token set admits the given service token.
//
// It goes through HostInboundServiceTokenExpansion rather than comparing
// strings, per that helper's stated contract: `all` (#3226) expands to the
// concrete service union, so `system-services all` admits dhcp/dhcpv6 and must
// not warn. `any-service` is the full-admit token — it is not a per-service
// union at all, so it is checked separately via HostInboundFullAdmitService
// (its expansion stands only for itself and would never match "dhcp").
//
// This is the system-services twin of hostInboundAdmitsRoutingProtocol
// (compiler_validate_warn_host_inbound.go), which does the same job for
// `protocols` tokens.
func hostInboundAdmitsSystemService(services []string, token string) bool {
	for _, s := range services {
		if HostInboundFullAdmitService(s) {
			return true
		}
		for _, e := range HostInboundServiceTokenExpansion(s) {
			if e == token {
				return true
			}
		}
	}
	return false
}
