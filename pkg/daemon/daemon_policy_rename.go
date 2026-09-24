package daemon

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

type policyRenameBinding struct {
	sourceRuleID        string
	destinationRuleID   string
	sourceFromZone      string
	sourceToZone        string
	destinationFromZone string
	destinationToZone   string
	oldPolicyID         uint32
	policyInactiveFn    func(string) bool
	feedOverlay         map[string][]string
}

func policyRulePathKey(path []string) (string, string, string, bool) {
	for i := 0; i+5 < len(path); i++ {
		if i+6 != len(path) ||
			path[i] != "from-zone" ||
			path[i+2] != "to-zone" ||
			path[i+4] != "policy" {
			continue
		}
		from, to, name := path[i+1], path[i+3], path[i+5]
		if from == "" || to == "" || name == "" {
			return "", "", "", false
		}
		return from, to, name, true
	}
	for i := 0; i+2 < len(path); i++ {
		if i+3 == len(path) && path[i] == "global" && path[i+1] == "policy" && path[i+2] != "" {
			return config.JunosGlobalZoneName, config.JunosGlobalZoneName, path[i+2], true
		}
	}
	return "", "", "", false
}

func zoneRenamePath(path []string) (string, bool) {
	for i := 0; i+2 < len(path); i++ {
		if path[i] != "zones" || path[i+1] != "security-zone" || i+2 != len(path)-1 {
			continue
		}
		if path[i+2] == "" {
			return "", false
		}
		return path[i+2], true
	}
	return "", false
}

type policyIdentity struct {
	from, to, name string
}

func policyIdentities(cfg *config.Config) []policyIdentity {
	if cfg == nil {
		return nil
	}
	var out []policyIdentity
	for _, pair := range cfg.Security.Policies {
		if pair == nil {
			continue
		}
		for _, policy := range pair.Policies {
			if policy != nil {
				out = append(out, policyIdentity{pair.FromZone, pair.ToZone, policy.Name})
			}
		}
	}
	for _, policy := range cfg.Security.GlobalPolicies {
		if policy != nil {
			out = append(out, policyIdentity{
				config.JunosGlobalZoneName, config.JunosGlobalZoneName, policy.Name,
			})
		}
	}
	return out
}

func policyRuleIDs(cfg *config.Config) map[string]uint32 {
	if cfg == nil {
		return nil
	}
	return dpuserspace.PolicyIDsByStableKey(cfg)
}

// expandPolicyRenameAncestry validates and expands provenance records against
// both policy generations. Any ambiguity deliberately returns no bindings so
// the caller takes the existing teardown path.
func expandPolicyRenameAncestry(
	oldCfg, newCfg *config.Config,
	descriptors []configstore.RenameDescriptor,
) (map[uint32]policyRenameBinding, []dpuserspace.PolicyRenameAncestry, bool) {
	if len(descriptors) == 0 || oldCfg == nil || newCfg == nil {
		return nil, nil, false
	}
	oldIDs, newIDs := policyRuleIDs(oldCfg), policyRuleIDs(newCfg)
	if len(oldIDs) == 0 || len(newIDs) == 0 {
		return nil, nil, false
	}
	oldFingerprints := dpuserspace.PolicyResolvedIdentityStrippedFingerprints(oldCfg)
	newFingerprints := dpuserspace.PolicyResolvedIdentityStrippedFingerprints(newCfg)
	if len(oldFingerprints) == 0 || len(newFingerprints) == 0 {
		return nil, nil, false
	}
	oldZoneNames, oldZoneOK := zoneNamesByID(oldCfg)
	newZoneNames, newZoneOK := zoneNamesByID(newCfg)
	if !oldZoneOK || !newZoneOK {
		return nil, nil, false
	}
	bindings := make(map[uint32]policyRenameBinding, len(descriptors))
	wire := make([]dpuserspace.PolicyRenameAncestry, 0, len(descriptors))
	type ancestryPair struct {
		sf, st, sn string
		df, dt, dn string
	}
	var pairs []ancestryPair
	for _, descriptor := range descriptors {
		sf, st, sn, sok := policyRulePathKey(descriptor.SourcePath)
		df, dt, dn, dok := policyRulePathKey(descriptor.DestinationPath)
		if sok || dok {
			if !sok || !dok {
				return nil, nil, false
			}
			pairs = append(pairs, ancestryPair{sf, st, sn, df, dt, dn})
			continue
		}
		sourceZone, sourceOK := zoneRenamePath(descriptor.SourcePath)
		destinationZone, destinationOK := zoneRenamePath(descriptor.DestinationPath)
		if !sourceOK || !destinationOK || sourceZone == destinationZone {
			return nil, nil, false
		}
		for _, identity := range policyIdentities(oldCfg) {
			if identity.from != sourceZone && identity.to != sourceZone {
				continue
			}
			df, dt := identity.from, identity.to
			if df == sourceZone {
				df = destinationZone
			}
			if dt == sourceZone {
				dt = destinationZone
			}
			pairs = append(pairs, ancestryPair{
				sf: identity.from, st: identity.to, sn: identity.name,
				df: df, dt: dt, dn: identity.name,
			})
		}
	}
	if len(pairs) == 0 {
		return nil, nil, false
	}
	seenSource := make(map[string]struct{}, len(pairs))
	seenDestination := make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		sf, st, sn := pair.sf, pair.st, pair.sn
		df, dt, dn := pair.df, pair.dt, pair.dn
		sourceFromZoneID, sourceFromZoneAny, sourceFromOK :=
			renameZoneWireIdentity(sf, oldZoneNames)
		sourceToZoneID, sourceToZoneAny, sourceToOK :=
			renameZoneWireIdentity(st, oldZoneNames)
		destinationFromZoneID, destinationFromZoneAny, destinationFromOK :=
			renameZoneWireIdentity(df, newZoneNames)
		destinationToZoneID, destinationToZoneAny, destinationToOK :=
			renameZoneWireIdentity(dt, newZoneNames)
		if !sourceFromOK || !sourceToOK || !destinationFromOK || !destinationToOK {
			return nil, nil, false
		}
		sourceID := dpuserspace.StablePolicyRuleID(sf, st, sn)
		destinationID := dpuserspace.StablePolicyRuleID(df, dt, dn)
		oldID, oldOK := oldIDs[sourceID]
		_, newOK := newIDs[destinationID]
		if !oldOK || !newOK || sourceID == destinationID {
			return nil, nil, false
		}
		if oldFingerprints[sourceID] == "" || oldFingerprints[sourceID] != newFingerprints[destinationID] {
			return nil, nil, false
		}
		if _, duplicate := seenSource[sourceID]; duplicate {
			return nil, nil, false
		}
		if _, duplicate := seenDestination[destinationID]; duplicate {
			return nil, nil, false
		}
		seenSource[sourceID] = struct{}{}
		seenDestination[destinationID] = struct{}{}
		// A global-only first policy yields ID 0 here (PolicySetID 0 with no
		// zone-pair sets; with N sets globals bind at N*256+idx like zone-pair
		// rules), so its renames expand wire-only. INTENDED per #10621: policy_id 0
		// is overloaded (first policy + host/fabric/tunnel/unbound zeros), so Go
		// cannot key bindings on it; Rust retains id-0 renames via wire ancestry
		// + bound-counter discrimination (extensive) or deterministic purge
		// (default/plain parity). See daemon_policy_invalidate.go (id-0
		// exclusion) + session_glue README (Deleted first-policy purge).
		if oldID != 0 {
			bindings[oldID] = policyRenameBinding{
				sourceRuleID: sourceID, destinationRuleID: destinationID,
				sourceFromZone: sf, sourceToZone: st,
				destinationFromZone: df, destinationToZone: dt,
				oldPolicyID: oldID,
			}
		}
		wire = append(wire, dpuserspace.PolicyRenameAncestry{
			SourceRuleID: sourceID, DestinationRuleID: destinationID,
			SourceFromZone: sf, SourceToZone: st,
			DestinationFromZone: df, DestinationToZone: dt,
			SourceFromZoneID: sourceFromZoneID, SourceToZoneID: sourceToZoneID,
			DestinationFromZoneID: destinationFromZoneID, DestinationToZoneID: destinationToZoneID,
			SourceFromZoneAny: sourceFromZoneAny, SourceToZoneAny: sourceToZoneAny,
			DestinationFromZoneAny: destinationFromZoneAny, DestinationToZoneAny: destinationToZoneAny,
		})
	}
	// A chain means the source/destination relation is not one-to-one in this
	// apply and cannot safely prove continuity from one old row to one new row.
	for source := range seenSource {
		if _, chained := seenDestination[source]; chained {
			return nil, nil, false
		}
	}
	return bindings, wire, true
}

func policyQueryProtocol(proto uint8) string {
	if name := appid.ProtocolName(proto); name != "" {
		return name
	}
	return strconv.Itoa(int(proto))
}

func networkPort(port uint16) int {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], port)
	return int(binary.BigEndian.Uint16(raw[:]))
}

func permittedRenameResult(cfg *config.Config, binding policyRenameBinding, q policymatch.Query) (dpuserspace.PolicySessionRebind, bool) {
	q.PolicyInactiveFn = binding.policyInactiveFn
	q.FeedOverlay = binding.feedOverlay
	result := policymatch.Match(cfg, q)
	if !result.Matched || result.Action != config.PolicyPermit || result.RuleID == "" {
		return dpuserspace.PolicySessionRebind{}, false
	}
	// Defensive and currently unreachable via Match: no configured rule carries
	// the sentinel (excluded by #9584's validator), and default-path results
	// carry PolicyID 0 with RuleID "" (rejected above; probed in #10592 N3b).
	// Kept as belt-and-suspenders against a corrupt result ever retaining
	// under the default identity.
	if result.PolicyID == dataplane.DefaultPolicySentinelID {
		return dpuserspace.PolicySessionRebind{}, false
	}
	return dpuserspace.PolicySessionRebind{
		Family: q.SrcFamily,
		SrcIP:  q.SrcIP.String(), DstIP: q.DstIP.String(),
		SrcPort: uint16(q.SrcPort), DstPort: uint16(q.DstPort),
		Protocol: qProtocol(q.Protocol), PolicyID: result.PolicyID, RuleID: result.RuleID,
	}, true
}

func qProtocol(proto string) uint8 {
	if n, ok := appid.ProtocolNumber(proto); ok {
		return n
	}
	n, _ := strconv.Atoi(strings.TrimSpace(proto))
	return uint8(n)
}

func renameZoneWireIdentity(name string, zoneNames map[uint16]string) (uint16, bool, bool) {
	switch name {
	case "any":
		return 0, true, true
	case config.JunosGlobalZoneName:
		return ^uint16(0), false, true
	case "junos-host":
		return config.ZoneIDReservedMin, false, true
	default:
		id := config.StableZoneID(name)
		return id, false, id != 0 && zoneNames[id] == name
	}
}

func zoneNamesByID(cfg *config.Config) (map[uint16]string, bool) {
	if cfg == nil {
		return nil, false
	}
	out := make(map[uint16]string, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		id := config.StableZoneID(name)
		if prior, exists := out[id]; exists && prior != name {
			return nil, false
		}
		out[id] = name
	}
	return out, true
}

func remappedQueryZones(
	oldCfg, newCfg *config.Config,
	binding policyRenameBinding,
	ingressID, egressID uint16,
) (string, string, uint16, uint16, bool) {
	oldNames, oldOK := zoneNamesByID(oldCfg)
	newNames, newOK := zoneNamesByID(newCfg)
	if !oldOK || !newOK {
		return "", "", 0, 0, false
	}
	from, fromOK := oldNames[ingressID]
	to, toOK := oldNames[egressID]
	if !fromOK || !toOK {
		return "", "", 0, 0, false
	}
	if from == binding.sourceFromZone {
		from = binding.destinationFromZone
	}
	if to == binding.sourceToZone {
		to = binding.destinationToZone
	}
	newIngress := config.StableZoneID(from)
	newEgress := config.StableZoneID(to)
	if newNames[newIngress] != from || newNames[newEgress] != to {
		return "", "", 0, 0, false
	}
	return from, to, newIngress, newEgress, true
}

// BPF conntrack mirrors intentionally omit TunnelDiscriminator: a production
// SessionValue read therefore returns zero even for a keyed GRE row. Zero is
// the valid non-tunnel/WireGuard None class, but it cannot identify GRE
// Unkeyed/Keyed/PPTP sessions, so those rows are deleted rather than aliased.
func capturedTunnelDiscriminatorValid(protocol uint8, discriminator uint64) bool {
	return protocol != 47 || discriminator != 0
}

// Translated-dst rematch consults SessFlagDNAT only, and that covers inbound
// NPTv6 too: NPTv6 populates decision.nat.rewrite_dst with the translated
// internal dst (no port rewrite), and helper session flags derive solely from
// rewrite_src/rewrite_dst — no SESS_FLAG_NPTV6 exists on the helper, and the Go
// constant is ABI width documentation nothing stamps. An NPTv6 row therefore
// reaches the capture as DNAT-flagged with a translated NATDstIP and zero port.
func rematchRenamedV4(oldCfg, newCfg *config.Config, binding policyRenameBinding, key dataplane.SessionKey, value dataplane.SessionValue) (dpuserspace.PolicySessionRebind, bool) {
	if !capturedTunnelDiscriminatorValid(key.Protocol, value.TunnelDiscriminator) {
		return dpuserspace.PolicySessionRebind{}, false
	}
	from, to, newIngress, newEgress, ok := remappedQueryZones(oldCfg, newCfg, binding, value.IngressZone, value.EgressZone)
	if !ok {
		return dpuserspace.PolicySessionRebind{}, false
	}
	dst := net.IPv4(key.DstIP[0], key.DstIP[1], key.DstIP[2], key.DstIP[3])
	if value.Flags&dataplane.SessFlagDNAT != 0 && value.NATDstIP != 0 {
		var raw [4]byte
		binary.NativeEndian.PutUint32(raw[:], value.NATDstIP)
		dst = net.IP(raw[:])
	}
	q := policymatch.Query{
		FromZone: from, ToZone: to,
		SrcIP: net.IPv4(key.SrcIP[0], key.SrcIP[1], key.SrcIP[2], key.SrcIP[3]), DstIP: dst,
		Protocol: policyQueryProtocol(key.Protocol), SrcPort: networkPort(key.SrcPort), DstPort: networkPort(key.DstPort),
		SrcFamily: "v4", DstFamily: "v4",
	}
	if value.Flags&dataplane.SessFlagDNAT != 0 && value.NATDstPort != 0 {
		q.DstPort = networkPort(value.NATDstPort)
	}
	record, permitted := permittedRenameResult(newCfg, binding, q)
	if permitted {
		record.SrcIP = net.IPv4(key.SrcIP[0], key.SrcIP[1], key.SrcIP[2], key.SrcIP[3]).String()
		record.DstIP = net.IPv4(key.DstIP[0], key.DstIP[1], key.DstIP[2], key.DstIP[3]).String()
		record.SrcPort, record.DstPort = uint16(networkPort(key.SrcPort)), uint16(networkPort(key.DstPort))
		record.IngressZone, record.EgressZone = newIngress, newEgress
		record.RoutingDomain = value.RoutingDomain
		record.TunnelDiscriminator = value.TunnelDiscriminator
	}
	return record, permitted
}
func rematchRenamedV6(oldCfg, newCfg *config.Config, binding policyRenameBinding, key dataplane.SessionKeyV6, value dataplane.SessionValueV6) (dpuserspace.PolicySessionRebind, bool) {
	if !capturedTunnelDiscriminatorValid(key.Protocol, value.TunnelDiscriminator) {
		return dpuserspace.PolicySessionRebind{}, false
	}
	from, to, newIngress, newEgress, ok := remappedQueryZones(oldCfg, newCfg, binding, value.IngressZone, value.EgressZone)
	if !ok {
		return dpuserspace.PolicySessionRebind{}, false
	}
	src := net.IP(append([]byte(nil), key.SrcIP[:]...))
	dst := net.IP(append([]byte(nil), key.DstIP[:]...))
	if value.Flags&dataplane.SessFlagDNAT != 0 && value.NATDstIP != ([16]byte{}) {
		dst = net.IP(append([]byte(nil), value.NATDstIP[:]...))
	}
	q := policymatch.Query{
		FromZone: from, ToZone: to,
		SrcIP: src, DstIP: dst, Protocol: policyQueryProtocol(key.Protocol),
		SrcPort: networkPort(key.SrcPort), DstPort: networkPort(key.DstPort), SrcFamily: "v6", DstFamily: "v6",
	}
	if value.Flags&dataplane.SessFlagDNAT != 0 && value.NATDstPort != 0 {
		q.DstPort = networkPort(value.NATDstPort)
	}
	record, permitted := permittedRenameResult(newCfg, binding, q)
	if permitted {
		record.SrcIP = net.IP(append([]byte(nil), key.SrcIP[:]...)).String()
		record.DstIP = net.IP(append([]byte(nil), key.DstIP[:]...)).String()
		record.SrcPort, record.DstPort = uint16(networkPort(key.SrcPort)), uint16(networkPort(key.DstPort))
		record.IngressZone, record.EgressZone = newIngress, newEgress
		record.RoutingDomain = value.RoutingDomain
		record.TunnelDiscriminator = value.TunnelDiscriminator
	}
	return record, permitted
}

// #10626: rename-rematch for a HELPER READ match — the helper-path twin of
// rematchRenamedV4/V6, which consume legacy store keys+values. The match
// carries the tuple as STRINGS plus the live zone IDs and DNAT inputs the
// Rust scan stamped (SessionPolicyMatch.ingress_zone_id et al). Validity
// mirrors policyTupleV4/V6 exactly (v4: To4() on both addrs; v6: To16() with
// v4-mapped rejected), and zero/unknown zones fail CLOSED to the denied
// bucket: an older helper omits the additive fields, and retaining on unknown
// zones would keep a session the new policy may deny.
func rematchRenamedMatch(oldCfg, newCfg *config.Config, binding policyRenameBinding, match dpuserspace.SessionPolicyMatch) (dpuserspace.PolicySessionRebind, bool) {
	if !capturedTunnelDiscriminatorValid(match.Tuple.Protocol, match.Tuple.TunnelDiscriminator) {
		return dpuserspace.PolicySessionRebind{}, false
	}
	from, to, newIngress, newEgress, ok := remappedQueryZones(oldCfg, newCfg, binding, match.IngressZoneID, match.EgressZoneID)
	if !ok {
		return dpuserspace.PolicySessionRebind{}, false
	}
	family := match.AddrFamily
	if family == 0 {
		family = match.Tuple.AddrFamily
	}
	var src, dst net.IP
	var srcFam, dstFam string
	// Parse once: the v6 mapped check below reuses these (ParseIP is
	// deterministic, so this is identical to re-parsing).
	srcRaw, dstRaw := net.ParseIP(match.Tuple.SrcIP), net.ParseIP(match.Tuple.DstIP)
	switch family {
	case 4:
		src, dst = srcRaw.To4(), dstRaw.To4()
		srcFam, dstFam = "v4", "v4"
	case 6:
		src, dst = srcRaw.To16(), dstRaw.To16()
		srcFam, dstFam = "v6", "v6"
	default:
		return dpuserspace.PolicySessionRebind{}, false
	}
	if src == nil || dst == nil {
		return dpuserspace.PolicySessionRebind{}, false
	}
	if family == 6 && (srcRaw.To4() != nil || dstRaw.To4() != nil) {
		return dpuserspace.PolicySessionRebind{}, false
	}
	if match.DNAT && match.NATDstIP != "" {
		translated := net.ParseIP(match.NATDstIP)
		if family == 4 {
			translated = translated.To4()
		} else {
			translated = translated.To16()
			if translated == nil || translated.To4() != nil {
				translated = nil
			}
		}
		if translated == nil {
			return dpuserspace.PolicySessionRebind{}, false
		}
		dst = translated
	}
	// Helper-wire ports are HOST order (the Rust SessionKey holds host order
	// and policy_tuple_from_key copies them raw), so — unlike the BPF-keyed
	// V4/V6 twins — no networkPort() conversion applies on this path.
	q := policymatch.Query{
		FromZone: from, ToZone: to,
		SrcIP: src, DstIP: dst,
		Protocol: policyQueryProtocol(match.Tuple.Protocol),
		SrcPort:  int(match.Tuple.SrcPort), DstPort: int(match.Tuple.DstPort),
		SrcFamily: srcFam, DstFamily: dstFam,
	}
	if match.DNAT && match.NATDstPort != 0 {
		q.DstPort = int(match.NATDstPort)
	}
	record, permitted := permittedRenameResult(newCfg, binding, q)
	if !permitted {
		return dpuserspace.PolicySessionRebind{}, false
	}
	// The record keeps the ORIGINAL tuple (like the V4/V6 twins): the
	// translated dst fed only the query. Host-order wire ports pass through
	// raw — Rust rebuilds its lookup key from the record without conversion.
	record.SrcIP = match.Tuple.SrcIP
	record.DstIP = match.Tuple.DstIP
	record.SrcPort, record.DstPort = match.Tuple.SrcPort, match.Tuple.DstPort
	record.IngressZone, record.EgressZone = newIngress, newEgress
	record.RoutingDomain = match.RoutingDomain
	if record.RoutingDomain == 0 {
		record.RoutingDomain = match.Tuple.RoutingDomain
	}
	record.TunnelDiscriminator = match.Tuple.TunnelDiscriminator
	return record, true
}
