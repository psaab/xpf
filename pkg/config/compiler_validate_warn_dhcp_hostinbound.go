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
// DHCPv4's raw AF_PACKET receive path remains outside netfilter; DHCPv6 uses a
// UDP socket and its ff02::1:2 destination is now covered by the #13925
// per-ingress-zone non-unicast gate. The same advisory therefore reports a v4
// bypass but a v6 default-deny when the matching service token is absent.

// THE MECHANISM, PER FAMILY. The two families have different enforcement
// outcomes, and the diagnostic names the relevant path and remedy.
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
//     mode and receives on UDP. A client's Solicit/Request is addressed to the
//     All_DHCP_Relay_Agents_and_Servers multicast group ff02::1:2. #13925 adds
//     `ff02::/16` to per-ingress-zone host-inbound enforcement, where the
//     `dhcpv6` token admits UDP 546/547. Without that token the request is
//     default-denied before reaching Kea; with it, the service is admitted.
//
// WARN-ONLY DIAGNOSTIC. The advisory does not install nft or Rust rules and
// never rejects a valid DHCP configuration. DHCPv4's existing raw path remains
// a known bypass; DHCPv6 now follows the configured host-inbound posture and
// the warning helps operators avoid accidentally blocking their server.
// This function has no error return and takes no `lenient` flag, so its no-brick
// property is structural rather than a convention a later edit could invert.
//
// `host-inbound-traffic system-services` is the Junos knob that bounds host
// services by zone. For v4, the raw socket means adding `dhcp` records intent
// but cannot constrain direct clients; remove an interface from the server
// group to stop serving that segment. For v6, omitting `dhcpv6` now makes the
// host-inbound gate deny the request, while adding it admits UDP delivery.
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
// simply misses) — the managed-routing migration gate likewise has no zone token
// to cross-check for that interface.

// dhcpHostInboundFamily is one DHCP family's advisory inputs: the stanza the
// operator authored, the `system-services` token Junos gates it with, and the
// family-specific enforcement outcome.
type dhcpHostInboundFamily struct {
	srv                         *DHCPLocalServerConfig
	stanza                      string // authored stanza name, for the message
	token                       string // host-inbound system-services token Junos gates this with
	mechanism                   string
	servesDespiteMissingService bool
}

// validateDHCPServerHostInboundBypassWarnings emits the #6460 advisory. One
// warning per (group, interface) pair whose effective services omit the family's
// token, except where #7490 withheld an already-configured zone-level DHCP token
// and the #6519 advisory covers the same condition.
// Warnings are sorted for deterministic commit output.
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
			mechanism:                   "the client sends to the 255.255.255.255 broadcast, which the XDP shim passes to the kernel without entering the AF_XDP userspace dataplane, while Kea's AF_PACKET raw socket receives before the netfilter input hook",
			servesDespiteMissingService: true,
		},
		{
			srv:    cfg.System.DHCPServer.DHCPv6LocalServer,
			stanza: "dhcpv6-local-server",
			token:  "dhcpv6",
			mechanism:                   "the client sends to the ff02::1:2 multicast group, which the #13925 per-zone link-scope gate admits on UDP 546/547 only when this zone permits dhcpv6",
			servesDespiteMissingService: false,
		},
	}

	var warnings []string
	lifelines := HostInboundLifelineSet(cfg)
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
				// Resolve a bare server binding as unit 0 when that logical
				// unit has a zone assignment, matching the server's interface
				// scope with zone ownership and per-unit overrides.
				ifRef := cfg.SplitInterfaceUnitRef(ifn)
				ifKey := ifRef.Literal
				if !ifRef.HasUnit {
					unit0 := ifRef.Base + ".0"
					if _, ok := ifZone[unit0]; ok {
						ifKey = unit0
					}
				}
				if HostInboundLifelineInterface(ifn, lifelines) ||
					HostInboundLifelineInterface(ifKey, lifelines) {
					continue
				}
				zname, ok := ifZone[ifKey]
				if !ok {
					continue
				}
				z := cfg.Security.Zones[zname]
				if z == nil {
					continue
				}
				// #7490 deliberately removes zone-level dhcp/bootp from effective
				// services on server/relay interfaces. When the zone authored the
				// token but this interface has no override, the resulting absence
				// is not a zone omission: #6519 already reports the withholding
				// and its interface-level remedy. Do not emit #6460 with a
				// contradictory instruction to add a token the zone already has.
				// A declared interface override remains significant: it replaces
				// the zone set (#6515), so if it omits dhcp the operator must
				// restore the token on that interface.
				// Authored spelling first — an override keyed by that exact
				// spelling still applies on a stamp-free config (#12843) —
				// then the canonical Literal the zone lookup resolved through.
				probes := []string{ifn}
				if ifKey != ifn {
					probes = append(probes, ifKey)
				}
				var overridden bool
				for _, p := range probes {
					if _, _, d := z.InterfaceHostInboundOverride(p); d {
						overridden = true
						break
					}
				}
				zoneAdmits := z.HostInboundTraffic != nil &&
					hostInboundAdmitsSystemService(z.HostInboundTraffic.SystemServices, fam.token)
				if !overridden && zoneAdmits &&
					!hostInboundAdmitsSystemService(z.ZoneLevelSystemServicesFor(z.HostInboundTraffic.SystemServices, ifKey), fam.token) {
					continue
				}
				// An override declared under either spelling REPLACES the zone
				// set (#6515), and same-identity declarations union exactly as
				// the compiled stamp unions them; with no declaring spelling
				// the zone-level set (as #7490 applies it here) answers.
				var effSvc []string
				var overrideDeclared bool
				for _, p := range probes {
					svc, _, o := z.InterfaceHostInboundEffective(p)
					if !o {
						continue
					}
					overrideDeclared = true
					effSvc = UnionHostInboundTokens(effSvc, svc)
				}
				if !overrideDeclared {
					effSvc, _, _ = z.InterfaceHostInboundEffective(probes[0])
				}
				if hostInboundAdmitsSystemService(effSvc, fam.token) {
					continue
				}
				remedy := fmt.Sprintf("add `host-inbound-traffic system-services %s` to zone %q.", fam.token, zname)
				explanation := fmt.Sprintf("that zone's host-inbound-traffic system-services set omits %q", fam.token)
				if overridden && zoneAdmits {
					explanation = fmt.Sprintf("the per-interface host-inbound-traffic system-services override omits %q", fam.token)
					remedy = fmt.Sprintf("add `host-inbound-traffic system-services %s` to interface %q in zone %q.", fam.token, ifn, zname)
				}
				effect := "the DHCP server answers on that interface REGARDLESS of the zone's host-inbound set"
				guidance := fmt.Sprintf("To stop serving that segment, remove %q from group %q; to record that the segment is meant to be served, %s", ifn, gname, remedy)
				if !fam.servesDespiteMissingService {
					effect = "host-inbound drops these requests before the DHCP server receives them"
					guidance = fmt.Sprintf("To admit DHCP service, %s; to stop serving that segment, remove %q from group %q", remedy, ifn, gname)
				}
				warnings = append(warnings, fmt.Sprintf(
					"system services %s group %q serves interface %q (security zone %q) but %s because %s (#6460). %s",
					fam.stanza, gname, ifn, zname, effect, explanation+" — "+fam.mechanism, guidance))
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
	excludedZones := ZoneQuarantineExclusionsForConfig(cfg)
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
