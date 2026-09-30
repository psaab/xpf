package userspace

import (
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func buildZoneSnapshots(cfg *config.Config) []ZoneSnapshot {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	// Sorted only for a deterministic wire ORDER (stable snapshot/fixture
	// output). The zone ID is NOT positional — see below.
	sort.Strings(names)
	out := make([]ZoneSnapshot, 0, len(names))
	for _, name := range names {
		zs := ZoneSnapshot{
			Name: name,
			// #3704: the wire zone ID is the STABLE name-hash
			// config.StableZoneID(name) — the SAME namespace the compiler
			// (pkg/dataplane.assignZoneIDs -> CompileResult.ZoneIDs), the HA
			// name fallback (pkg/daemon.buildZoneIDs), the zone→RG map
			// (buildZoneRGMap key space), and every CLI/API session
			// zone-name display use. Before #3704 this builder assigned a
			// SORTED-POSITIONAL uint16(i+1), which #3075 (StableZoneID) left
			// behind, splitting the live dataplane/session/HA wire ID
			// namespace from the name-hash namespace everything else moved
			// to. For any >=2-zone config the two disagreed, so: session
			// zone-name display reverse-mapped a positional id through the
			// name-hash map and missed (wrong "zone-N" labels), and
			// SessionSync.ShouldSyncZone(session.IngressZone) queried the
			// name-hash zoneRGMap with a positional id and always missed,
			// collapsing per-RG active/active session-sync ownership to the
			// global primary. Assigning StableZoneID here makes the wire ID
			// equal CompileResult.ZoneIDs[name] by construction, so all four
			// consumers share ONE namespace. The id is a pure function of the
			// zone NAME (never the zone set, sort order, or a nil sibling), so
			// a nil zone entry on one HA peer can no longer shift another
			// zone's id (Codex C131-M01), and both peers plus a cold-booting
			// node agree with zero synced/persisted state.
			ID: config.StableZoneID(name),
		}
		// #3070: carry the zone's host-inbound-traffic admission set onto the
		// wire so the dataplane can enforce it for host-bound (local-delivery)
		// traffic.
		//
		// #3405: EVERY configured security zone is host-inbound-ENFORCING (Junos
		// default-deny parity). A zone with NO `host-inbound-traffic` stanza
		// carries HostInboundConfigured=true with EMPTY token sets, so the Rust
		// classifier inserts it into `zone_host_inbound` with an empty
		// `ZoneHostInbound` -> `admits()` returns false for every
		// service/protocol -> default-deny, identical to an empty
		// `host-inbound-traffic { }` stanza and to the kernel-nft catch-all DROP
		// (BuildZoneHostInboundViews). Before #3405 a no-stanza zone stayed
		// unconfigured (absent from the table -> `None => true` admit-all), a
		// permit-all management-plane exposure on any zone the operator never
		// locked down. The global ICMP/ND/PMTUD accepts (#3171) still precede the
		// per-zone deny on the Rust path, and lifeline interfaces (fxp0 plus
		// explicitly configured cluster-control/fabric links) never reach the AF_XDP
		// local-delivery classifier, so the flip cannot strand management or break HA.
		//
		// #3362: the zone-keyed set stays the zone-level set (possibly EMPTY ->
		// fail-closed deny-all for any interface in the zone WITHOUT an override),
		// and overridden interfaces are admitted via the per-interface ifindex map
		// (InterfaceSnapshot.HostInbound*).
		//
		// #3705: HostInboundConfigured is set UNCONDITIONALLY for every emitted
		// snapshot — it must NOT be gated on `zone != nil`. A tolerant / HA-loaded
		// config can carry a NIL zone value (cfg.Security.Zones[name] == nil, the
		// #3493 shape; api/sessions.go:809 and buildZoneRGMap both guard it). Before
		// #3705 a nil zone shipped a snapshot with a valid name+id but
		// HostInboundConfigured=false, so the Rust build path left it ABSENT from
		// `zone_host_inbound` and the classifier's `None => true` admit-all arm made
		// that KNOWN configured zone admit ALL host-bound traffic — reopening the
		// #3405 default-deny guarantee on the nil-object shape (management-plane
		// fail-open). Emitting configured=true with EMPTY token sets makes a nil zone
		// default-DENY exactly like a no-stanza zone (#3405): the Rust classifier
		// inserts an empty ZoneHostInbound -> `admits()` returns false for every
		// service/protocol. Lifeline interfaces (fxp0 plus explicitly configured
		// cluster-control/fabric links) never reach the AF_XDP local-delivery
		// classifier (#3682), so the flip cannot strand management or break HA.
		zs.HostInboundConfigured = true
		if zone := cfg.Security.Zones[name]; zone != nil && zone.HostInboundTraffic != nil {
			zs.HostInboundSystemServices = lowerTokens(zone.HostInboundTraffic.SystemServices)
			zs.HostInboundProtocols = lowerTokens(zone.HostInboundTraffic.Protocols)
		}
		// #3071: carry the per-zone `tcp-rst` knob to the dataplane so a
		// non-SYN TCP transit packet dropped for a session miss whose ingress
		// (from) zone has tcp-rst enabled may receive a TCP RST.
		if z := cfg.Security.Zones[name]; z != nil && z.TCPRst {
			zs.TCPRst = true
		}
		out = append(out, zs)
	}
	return out
}

// lowerTokens returns a lower-cased, trimmed copy of the host-inbound token
// slice (system-services / protocols). Empty/whitespace tokens are dropped.
// The Rust classifier lower-cases on its side too, but normalizing here keeps
// the wire canonical and the Go emit test deterministic.
func lowerTokens(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
