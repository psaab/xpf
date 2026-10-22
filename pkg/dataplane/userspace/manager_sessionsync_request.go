package userspace

// Session-sync request construction for the userspace dataplane: resolves a
// BPF session key/value into the SessionSyncRequest wire shape, including
// egress interface / owner-RG / tunnel-endpoint resolution against
// m.lastSnapshot, zone-name lookup, and the address/port/MAC encoders.
// Every function here is a pure snapshot read — no control-socket I/O.

import (
	"encoding/binary"
	"net"

	"github.com/psaab/xpf/pkg/dataplane"
)

// sessionSyncView is the #16172 family-neutral BORROWED view of one
// session value: pointers into the caller's value, never copies, never
// slices into the caller's storage. It carries RAW references (not
// pre-rendered strings) so that (a) all value rendering stays
// single-sourced in fillSessionSyncValue and (b) merely adapting a
// request cannot move the caller's key or value to the heap: the view
// is a stack local in buildSessionSyncRequest{V4,V6}, filled in place
// by viewV4/viewV6, and consumed before the wrapper returns. The NAT
// addresses stay in their native storage (native-endian uint32 for V4,
// [16]byte for V6) and are read only through the accessors below;
// nat64SnatV4 is exposed (by pointer) only by viewV6.
//
// INVARIANT: a view is valid only for the duration of one
// buildSessionSyncRequest{V4,V6} call. Never store or return one.
type sessionSyncView struct {
	// value storage — exactly one arm set; both nil would mean "no
	// value", but the wrappers only build a view when val != nil.
	val4 *dataplane.SessionValue
	val6 *dataplane.SessionValueV6
	// nat64SnatV4 borrows SessionValueV6.Nat64SnatV4; nil for V4.
	nat64SnatV4 *[4]byte
}

func (v *sessionSyncView) ingressZone() uint16 {
	if v.val4 != nil {
		return v.val4.IngressZone
	}
	return v.val6.IngressZone
}

func (v *sessionSyncView) egressZone() uint16 {
	if v.val4 != nil {
		return v.val4.EgressZone
	}
	return v.val6.EgressZone
}

func (v *sessionSyncView) ingressIfaceFold() uint32 {
	if v.val4 != nil {
		return v.val4.IngressIfaceFold
	}
	return v.val6.IngressIfaceFold
}

func (v *sessionSyncView) natScopeFold() uint32 {
	if v.val4 != nil {
		return v.val4.NatScopeFold
	}
	return v.val6.NatScopeFold
}

func (v *sessionSyncView) routingDomain() uint32 {
	if v.val4 != nil {
		return v.val4.RoutingDomain
	}
	return v.val6.RoutingDomain
}

func (v *sessionSyncView) fibIfindex() uint32 {
	if v.val4 != nil {
		return v.val4.FibIfindex
	}
	return v.val6.FibIfindex
}

func (v *sessionSyncView) fibVlanID() uint16 {
	if v.val4 != nil {
		return v.val4.FibVlanID
	}
	return v.val6.FibVlanID
}

func (v *sessionSyncView) fibGen() uint16 {
	if v.val4 != nil {
		return v.val4.FibGen
	}
	return v.val6.FibGen
}

func (v *sessionSyncView) logFlags() uint8 {
	if v.val4 != nil {
		return v.val4.LogFlags
	}
	return v.val6.LogFlags
}

func (v *sessionSyncView) flags() uint16 {
	if v.val4 != nil {
		return v.val4.Flags
	}
	return v.val6.Flags
}

// fibDmac/fibSmac hand macString borrowed bytes into the caller's value;
// no MAC array is ever copied into or out of the view.
func (v *sessionSyncView) fibDmac() []byte {
	if v.val4 != nil {
		return v.val4.FibDmac[:]
	}
	return v.val6.FibDmac[:]
}

func (v *sessionSyncView) fibSmac() []byte {
	if v.val4 != nil {
		return v.val4.FibSmac[:]
	}
	return v.val6.FibSmac[:]
}

// natSrcIP/natDstIP render the NAT addresses from their NATIVE storage:
// V4 widens its native-endian uint32 in a stack local (the pre-collapse
// nativeUint32ToIP hop), V6 borrows its [16]byte in place. Neither path
// stores an address slice, so nothing about the caller's value escapes.
func (v *sessionSyncView) natSrcIP() string {
	if v.val4 != nil {
		return ipString(nativeUint32ToIP(v.val4.NATSrcIP))
	}
	return ipString(net.IP(v.val6.NATSrcIP[:]))
}

func (v *sessionSyncView) natDstIP() string {
	if v.val4 != nil {
		return ipString(nativeUint32ToIP(v.val4.NATDstIP))
	}
	return ipString(net.IP(v.val6.NATDstIP[:]))
}

func (v *sessionSyncView) natSrcPort() uint16 {
	if v.val4 != nil {
		return networkUint16ToHost(v.val4.NATSrcPort)
	}
	return networkUint16ToHost(v.val6.NATSrcPort)
}

func (v *sessionSyncView) natDstPort() uint16 {
	if v.val4 != nil {
		return networkUint16ToHost(v.val4.NATDstPort)
	}
	return networkUint16ToHost(v.val6.NATDstPort)
}

func (v *sessionSyncView) egressIfaceFold() uint32 {
	if v.val4 != nil {
		return v.val4.EgressIfaceFold
	}
	return v.val6.EgressIfaceFold
}

// viewV4 borrows the V4 value into view (the wrapper renders the key
// itself). No copy and no allocation: lifetimes stay the caller's.
func viewV4(view *sessionSyncView, val *dataplane.SessionValue) {
	view.val4 = val
	// nat64SnatV4 stays nil: NAT64 pool state is V6-only (#4565), so a V4
	// request can never carry nat64_snat_v4 by construction.
}

// viewV6 borrows the V6 value into view and is the only adapter that
// exposes the NAT64 pool source (#4565).
func viewV6(view *sessionSyncView, val *dataplane.SessionValueV6) {
	view.val6 = val
	if val != nil {
		view.nat64SnatV4 = &val.Nat64SnatV4
	}
}

func (m *Manager) buildSessionSyncRequestV4(op string, key dataplane.SessionKey, val *dataplane.SessionValue) SessionSyncRequest {
	var req SessionSyncRequest
	req.Operation = op
	req.AddrFamily = dataplane.AFInet
	req.Protocol = key.Protocol
	req.SrcIP = net.IP(key.SrcIP[:]).String()
	req.DstIP = net.IP(key.DstIP[:]).String()
	req.SrcPort = networkUint16ToHost(key.SrcPort)
	req.DstPort = networkUint16ToHost(key.DstPort)
	// NOTE: the hasValue test stays in the wrapper, not in the fill:
	// passing a nil value through the view made the (non-inlined) fill
	// force the key to the heap even on deletes. Guarding here keeps
	// the delete path allocation-identical to the twins.
	if val == nil {
		return req
	}
	var view sessionSyncView
	viewV4(&view, val)
	m.fillSessionSyncValue(&view, &req)
	return req
}

func (m *Manager) buildSessionSyncRequestV6(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) SessionSyncRequest {
	var req SessionSyncRequest
	req.Operation = op
	req.AddrFamily = dataplane.AFInet6
	req.Protocol = key.Protocol
	req.SrcIP = net.IP(key.SrcIP[:]).String()
	req.DstIP = net.IP(key.DstIP[:]).String()
	req.SrcPort = networkUint16ToHost(key.SrcPort)
	req.DstPort = networkUint16ToHost(key.DstPort)
	if val == nil {
		return req
	}
	var view sessionSyncView
	viewV6(&view, val)
	m.fillSessionSyncValue(&view, &req)
	return req
}

// scopedRoutingDomain4/6 extract the delete scope from a possibly-nil
// scoped value without materialising a view (see the wrappers below).
func scopedRoutingDomain(val *dataplane.SessionValue) uint32 {
	if val == nil {
		return 0
	}
	return val.RoutingDomain
}

func scopedRoutingDomainV6(val *dataplane.SessionValueV6) uint32 {
	if val == nil {
		return 0
	}
	return val.RoutingDomain
}

// buildSessionSyncScopedDeleteV4/V6 build the scoped-delete request
// (mirror_delete with a domain-only value, #9146/#9364) WITHOUT routing
// the value through the borrowed view: the value is synthetic and
// carries only RoutingDomain, so the full fill would read a dozen zero
// fields for nothing — and, measurably, routing even this value through
// the view moves the caller's key to the heap (272 B/op vs the twins'
// 16 B/op on the delete path). These wrappers keep the delete path
// allocation-identical to the twins while the upsert path shares the
// single fill.
func (m *Manager) buildSessionSyncScopedDeleteV4(op string, key dataplane.SessionKey, domain uint32) SessionSyncRequest {
	var req SessionSyncRequest
	req.Operation = op
	req.AddrFamily = dataplane.AFInet
	req.Protocol = key.Protocol
	req.SrcIP = net.IP(key.SrcIP[:]).String()
	req.DstIP = net.IP(key.DstIP[:]).String()
	req.SrcPort = networkUint16ToHost(key.SrcPort)
	req.DstPort = networkUint16ToHost(key.DstPort)
	if domain != 0 {
		req.RoutingDomain = domain
	}
	return req
}

func (m *Manager) buildSessionSyncScopedDeleteV6(op string, key dataplane.SessionKeyV6, domain uint32) SessionSyncRequest {
	var req SessionSyncRequest
	req.Operation = op
	req.AddrFamily = dataplane.AFInet6
	req.Protocol = key.Protocol
	req.SrcIP = net.IP(key.SrcIP[:]).String()
	req.DstIP = net.IP(key.DstIP[:]).String()
	req.SrcPort = networkUint16ToHost(key.SrcPort)
	req.DstPort = networkUint16ToHost(key.DstPort)
	if domain != 0 {
		req.RoutingDomain = domain
	}
	return req
}

// fillSessionSyncValue is the value half of the single builder behind
// both family entry points (#16172); the wrappers render the key half
// inline from their by-value key parameter. Splitting the halves this
// way — key rendering never flows through a function that also holds
// the borrowed view — is what keeps the view from forcing the caller's
// key, and (for V6) the caller's stack value, onto the heap: measured
// allocs/B/op match the pre-collapse twins exactly (see the benchmarks
// in manager_sessionsync_alloc_16172_test.go). All value rendering and
// snapshot resolution happens here, once; the characterization goldens
// pin its byte output for both families.
func (m *Manager) fillSessionSyncValue(view *sessionSyncView, req *SessionSyncRequest) {
	// Every field below reads the value through the borrowed view; the
	// field list is the union of the two pre-collapse twin bodies, in
	// the twins' original order (NAT64 is the one V6-only insertion).
	req.IngressZone = m.zoneNameByID(view.ingressZone())
	req.EgressZone = m.zoneNameByID(view.egressZone())
	// #919/#922: forward the raw u16 IDs alongside the legacy
	// strings; the Rust daemon prefers IDs when nonzero.
	req.IngressZoneID = view.ingressZone()
	// #7095: resolve the peer's cluster-stable ingress fold to THIS node's
	// ifindex. The sender could not ship its own ifindex — it is node-local
	// — so it shipped a fold of the reth-relative name both nodes agree on,
	// and this is where it becomes a local number again. Unresolvable (0, an
	// unknown fold, or a collision) leaves both fields 0 and the consumer
	// falls back to the #4792 zone approximation, exactly as before #7095.
	if ifindex, vlan, ok := m.resolveIngressFoldLocked(view.ingressIfaceFold()); ok {
		req.IngressIfindex = int(ifindex)
		req.IngressVLANID = vlan
	}
	// #15176: resolve the NAT-scope fold to this node's logical unit.
	if ifindex, _, ok := m.resolveIngressFoldLocked(view.natScopeFold()); ok {
		req.NatScopeIfindex = int32(ifindex)
	}
	// #7239 (#7160/#2387): hand the helper the domain the SENDER stamped at
	// install, so it does not have to re-derive one from the fold resolved
	// just above. The fold is computed on the sender's SEND path against
	// its CURRENT config, so an ifindex recycled onto a sibling between
	// install and sync resolves here to the sibling — and deriving the
	// domain from that files the session in the sibling's routing instance.
	// A carried domain cannot drift that way; 0 means the default instance,
	// which is what a peer predating the field sends.
	req.RoutingDomain = view.routingDomain()
	req.EgressZoneID = view.egressZone()
	var peerEgress bool
	req.EgressIfindex, req.TXIfindex, req.OwnerRGID, req.TXVLANID, peerEgress =
		m.sessionSyncEgressIdentityLocked(view.fibIfindex(), view.fibVlanID(), view.egressIfaceFold(), req.EgressZone)
	req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
	if view.logFlags()&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && view.fibGen() != 0 {
		req.TunnelEndpointID = view.fibGen()
	}
	if req.TunnelEndpointID != 0 {
		if endpoint, ok := m.sessionSyncTunnelEndpointLocked(req.TunnelEndpointID); ok {
			req.EgressIfindex = endpoint.Ifindex
			req.OwnerRGID = endpoint.RedundancyGroup
		} else {
			req.EgressIfindex = 0
			req.OwnerRGID = 0
		}
		req.TXIfindex = 0
		req.TXVLANID = 0
		req.NeighborMAC = ""
		req.SrcMAC = ""
	} else if !peerEgress {
		// A nonzero egress fold identifies a peer row. Its cached MACs
		// belong to the sender and MUST NOT become a cached local result;
		// the helper performs a fresh FIB/neighbor lookup on import.
		req.NeighborMAC = macString(view.fibDmac())
		req.SrcMAC = macString(view.fibSmac())
	}
	req.NATSrcIP = view.natSrcIP()
	req.NATDstIP = view.natDstIP()
	req.NATSrcPort = view.natSrcPort()
	req.NATDstPort = view.natDstPort()
	// #12187: derive the numeric wire value from the known marker and
	// static bit; marker-clear legacy rows remain omitted/unknown.
	req.SourceNatProvenance = dataplane.SourceNatProvenanceFromFlags(view.flags())
	req.FabricIngress = view.logFlags()&dataplane.LogFlagUserspaceFabricIngress != 0
	// #2785: carry the per-policy `then log` selection to the peer helper
	// so the synced session logs the same RT_FLOW records after failover.
	req.LogSessionInit = view.logFlags()&dataplane.LogFlagSessionInit != 0
	req.LogSessionClose = view.logFlags()&dataplane.LogFlagSessionClose != 0
	// The scalar tail is family-identical in names, types, and order in
	// both BPF value structs, so it is read through the view's value arm
	// exactly once here. Keeping it in the twins' original assignment
	// order is what lets the characterization goldens double as an
	// assignment-order check.
	if view.val4 != nil {
		req.IsReverse = view.val4.IsReverse != 0
		// #2170: mirror the install generation to the helper so its in-memory
		// SyncedSessionEntry can enforce the same generation guard.
		req.Generation = view.val4.Generation
		// #3301: carry the admitting policy's firewall metadata so a
		// peer-PROMOTED session resolves the admitting policy (PolicyID),
		// increments the correct per-rule hit counter (PolicyCounterIdx), and
		// ages on the per-application idle timeout (AppTimeout, seconds) after
		// failover. 0 => unattributed / no counter / global timeout, the
		// pre-#3301 behavior an old helper still applies via serde(default).
		req.PolicyID = view.val4.PolicyID
		req.PolicyCounterIdx = view.val4.PolicyCounterIdx
		req.PolicyRuleID = view.val4.PolicyRuleID
		req.InactivityTimeout = view.val4.AppTimeout
		// #4565: NAT64 pool source is V6-only; viewV4 leaves nat64SnatV4
		// nil, so the shared NAT64 block below is inert on this arm.
		// #5212: carry the originating node's stable RT_FLOW session id so the
		// peer helper adopts it on import instead of minting a fresh local id.
		// #9752 round 5 item 2: fall back to the mirror-preserved SessionID
		// when RTFlow is absent (mirror-sourced sweep resends lose the
		// sync-only tail). Post-convert SessionID is the adopted stable id
		// (or a per-incarnation-unique mint), so the fallback preserves
		// incarnation identity the helper's preserve rules key on — without
		// it a reused tuple's new incarnation arrives id-less and the old
		// PBR table is wrongly retained. Double-zero still omits (unknown).
		req.RTFlowSessionID = view.val4.RTFlowSessionID
		if req.RTFlowSessionID == 0 {
			req.RTFlowSessionID = view.val4.SessionID
		}
		// #7188: carry the tunnel session-identity discriminator to the peer
		// helper, which folds it into the key it reconstructs. Two RFC 2890 GRE
		// tunnels between one pair of outer endpoints are ONE Go session key
		// (protocol 47 has no L4 ports), so without this the helper rebuilt both
		// records as the same key and the second install evicted the first.
		//
		// A "delete" request is built with no value and therefore carries 0 —
		// the RESERVED "not carried" tag. That is deliberate and safe: a delete
		// reconstructs the key with Delete intent on the helper, which resolves
		// an absent discriminator to the None class, so it can only under-match.
		// A keyed-GRE synced session is retracted by its idle timeout rather
		// than by an explicit delete.
		req.TunnelDiscriminator = view.val4.TunnelDiscriminator
		req.PptpCallIDs = view.val4.PptpCallIDs
		// #9412: forward the close class so the standby imports the close state.
		req.TCPCloseClass = view.val4.TCPCloseClass
		// #10888: forward handshake state separately from the close class.
		req.TCPHandshakeState = dataplane.NormalizeTCPHandshakeState(view.val4.TCPHandshakeState)
		// #9752: forward the installing-table identity so the standby imports
		// a PBR-steered session with the table its steer installed.
		req.InstallTableDomain = view.val4.InstallTableDomain
		req.InstallTableCheck = view.val4.InstallTableCheck
		// #11064: preserve typed source-NAT rule identity on the install leg.
		req.SourceNatICMPValid = view.val4.SourceNatICMPValid
		req.SourceNatICMPType = view.val4.SourceNatICMPType
		req.SourceNatICMPCode = view.val4.SourceNatICMPCode
	} else {
		req.IsReverse = view.val6.IsReverse != 0
		req.Generation = view.val6.Generation
		req.PolicyID = view.val6.PolicyID
		req.PolicyCounterIdx = view.val6.PolicyCounterIdx
		req.PolicyRuleID = view.val6.PolicyRuleID
		req.InactivityTimeout = view.val6.AppTimeout
		// #4565: carry the NAT64 translated pool SOURCE (non-zero marks a
		// NAT64 cross-family session) so the peer helper rebuilds the reverse
		// (v4->v6) BIB after promotion. Only viewV6 exposes nat64SnatV4, so
		// this block is inert on V4 by construction. The generic
		// nat_src/nat_dst fields cannot carry a v4 pool source in a v6
		// session's slot unambiguously — this dedicated dotted-quad is the
		// helper's authoritative snat_v4.
		if view.nat64SnatV4 != nil && *view.nat64SnatV4 != ([4]byte{}) {
			req.Nat64SnatV4 = net.IP(view.nat64SnatV4[:]).String()
		}
		req.RTFlowSessionID = view.val6.RTFlowSessionID
		if req.RTFlowSessionID == 0 {
			req.RTFlowSessionID = view.val6.SessionID
		}
		req.TunnelDiscriminator = view.val6.TunnelDiscriminator
		req.PptpCallIDs = view.val6.PptpCallIDs
		req.TCPCloseClass = view.val6.TCPCloseClass
		req.TCPHandshakeState = dataplane.NormalizeTCPHandshakeState(view.val6.TCPHandshakeState)
		req.InstallTableDomain = view.val6.InstallTableDomain
		req.InstallTableCheck = view.val6.InstallTableCheck
		req.SourceNatICMPValid = view.val6.SourceNatICMPValid
		req.SourceNatICMPType = view.val6.SourceNatICMPType
		req.SourceNatICMPCode = view.val6.SourceNatICMPCode
	}
	if view.flags()&dataplane.SessFlagSNAT == 0 {
		req.NATSrcIP = ""
		req.NATSrcPort = 0
	}
	if view.flags()&dataplane.SessFlagDNAT == 0 {
		req.NATDstIP = ""
		req.NATDstPort = 0
	}
}

func (m *Manager) sessionSyncTunnelEndpointIDLocked(egressIfindex int) uint16 {
	snapshot := m.lastSnapshot
	if snapshot == nil || egressIfindex <= 0 {
		return 0
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.Ifindex == egressIfindex {
			return endpoint.ID
		}
	}
	return 0
}

func (m *Manager) sessionSyncTunnelEndpointLocked(id uint16) (TunnelEndpointSnapshot, bool) {
	snapshot := m.lastSnapshot
	if snapshot == nil || id == 0 {
		return TunnelEndpointSnapshot{}, false
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == id {
			return endpoint, true
		}
	}
	return TunnelEndpointSnapshot{}, false
}

func (m *Manager) zoneNameByID(zoneID uint16) string {
	if zoneID == 0 {
		return ""
	}
	cr := m.bpfShim.LastCompileResult()
	if cr == nil {
		return ""
	}
	// #3719: a StableZoneID collision maps two zone names to the same id in
	// ZoneIDs. The dataplane installs only the sorted-FIRST name (the survivor
	// config.QuarantinedZoneNames keeps), so resolve deterministically to that
	// name instead of returning whichever name a map-iteration coin flip yields
	// — which could name the QUARANTINED zone that forwards nothing.
	owner := ""
	for name, id := range cr.ZoneIDs {
		if id != zoneID {
			continue
		}
		if owner == "" || name < owner {
			owner = name
		}
	}
	return owner
}

func nativeUint32ToIP(v uint32) net.IP {
	if v == 0 {
		return nil
	}
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], v)
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).To4()
}

func networkUint16ToHost(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil && v4.Equal(net.IPv4zero) {
		return ""
	}
	if v6 := ip.To16(); v6 != nil && v6.Equal(net.IPv6zero) {
		return ""
	}
	return ip.String()
}

func macString(raw []byte) string {
	if len(raw) < 6 {
		return ""
	}
	allZero := true
	for i := 0; i < 6; i++ {
		if raw[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return net.HardwareAddr(raw[:6]).String()
}

func (m *Manager) sessionSyncEgressLocked(fibIfindex int, fibVlanID uint16, egressZone string) (egressIfindex, txIfindex, ownerRGID int) {
	snapshot := m.lastSnapshot
	if snapshot == nil {
		return fibIfindex, fibIfindex, 0
	}
	if fibIfindex <= 0 {
		// FibIfindex is unresolved but we can still derive owner_rg_id
		// from the session's egress zone so the sync peer doesn't have
		// to fall back to the imprecise any_rg_active heuristic.
		return fibIfindex, fibIfindex, resolveOwnerRGFromZone(snapshot, egressZone)
	}
	if iface, ok := findUserspaceEgressInterfaceSnapshot(snapshot, fibIfindex, fibVlanID); ok {
		egress := iface.Ifindex
		if egress <= 0 {
			egress = fibIfindex
		}
		tx := iface.ParentIfindex
		if tx <= 0 {
			tx = egress
		}
		return egress, tx, iface.RedundancyGroup
	}
	return fibIfindex, fibIfindex, 0
}

// resolveOwnerRGFromZone returns the RedundancyGroup for the first interface
// in the given egress zone. This is used as a fallback when FibIfindex is 0
// so the sync sender can still propagate a meaningful owner_rg_id to the peer.
func resolveOwnerRGFromZone(snapshot *ConfigSnapshot, egressZone string) int {
	if snapshot == nil || egressZone == "" {
		return 0
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == egressZone && iface.RedundancyGroup > 0 {
			return iface.RedundancyGroup
		}
	}
	return 0
}

func findUserspaceEgressInterfaceSnapshot(snapshot *ConfigSnapshot, fibIfindex int, fibVlanID uint16) (InterfaceSnapshot, bool) {
	if snapshot == nil {
		return InterfaceSnapshot{}, false
	}
	if fibVlanID != 0 {
		for _, iface := range snapshot.Interfaces {
			if iface.ParentIfindex == fibIfindex && iface.VLANID == int(fibVlanID) {
				return iface, true
			}
		}
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Ifindex == fibIfindex {
			return iface, true
		}
	}
	for _, iface := range snapshot.Interfaces {
		if iface.ParentIfindex == fibIfindex {
			return iface, true
		}
	}
	return InterfaceSnapshot{}, false
}

// resolveIngressFoldLocked maps a peer's #7095 cluster-stable ingress fold to this
// node's own {ifindex, vlan}.
//
// The resolver is injected (the daemon owns the config and the ifindex
// snapshot); an unset one resolves nothing, which is the pre-#7095 behaviour and
// not an error. Returning ok=false for an unknown or ambiguous fold is
// deliberate: naming no interface costs the zone approximation, while naming the
// wrong one is the confidently-wrong rendering #6928 refused to ship.
// The caller MUST already hold m.mu. Both call sites are
// buildSessionSyncRequest{V4,V6}, which are themselves `...Locked`-contract
// helpers reached with the manager mutex held — from SetClusterSyncedSessionV4/V6
// (the peer-import path, via syncSessionV{4,6}Locked) and from
// mirrorSessionV{4,6} (the local-install path). An earlier revision took
// m.mu here, which SELF-DEADLOCKED on the non-reentrant sync.Mutex the moment a
// session carried a non-zero fold — and it locked before reading the resolver,
// so a nil resolver did not save it. The lock was never needed at this depth:
// every caller already holds it, which is exactly what makes the read safe.
func (m *Manager) resolveIngressFoldLocked(fold uint32) (uint32, uint16, bool) {
	if m == nil || fold == 0 {
		return 0, 0, false
	}
	fn := m.ingressFoldResolver
	if fn == nil {
		return 0, 0, false
	}
	ifindex, vlan, ok := fn(fold)
	if !ok {
		return 0, 0, false
	}
	// #15263 (B05-02): the injected resolver is built from a net.Interfaces()
	// snapshot taken once per config apply. A member netdev recreated without
	// a commit (VF reset, re-probe) gets a NEW ifindex while the daemon
	// closures still name the dead one; RefreshInterfaceRowsForLink rebuilds
	// lastSnapshot's rows but never the closures. Without this check the
	// importer confidently installs the session on the dead ifindex and
	// owner RG 0 (sessionSyncEgressLocked misses the row). Fail closed to
	// the zone approximation — naming no interface — when the resolved
	// ifindex is absent from the CURRENT snapshot. A nil snapshot preserves
	// the pre-existing behaviour (nothing published yet to check against).
	if snap := m.lastSnapshot; snap != nil {
		if _, present := findUserspaceEgressInterfaceSnapshot(snap, int(ifindex), vlan); !present {
			return 0, 0, false
		}
	}
	return ifindex, vlan, true
}

// resolveEgressFoldLocked maps the #12075 cluster-stable egress fold to this
// node's local {ifindex, vlan}. Ingress and egress use the same reth-relative
// name fold and injected resolver; the distinction is the session direction,
// not the mapping.
func (m *Manager) resolveEgressFoldLocked(fold uint32) (uint32, uint16, bool) {
	return m.resolveIngressFoldLocked(fold)
}

// sessionSyncEgressIdentityLocked resolves a session's egress identity. A
// nonzero fold marks a peer value: the raw FibIfindex is then sender-local and
// MUST NOT be resolved on this node. Unknown or ambiguous folds fail closed to
// the egress-zone approximation. Fold-zero rows retain the legacy/local path,
// where FibIfindex is this node's number (or has already been scrubbed to zero).
func (m *Manager) sessionSyncEgressIdentityLocked(
	fibIfindex uint32,
	fibVlanID uint16,
	egressFold uint32,
	egressZone string,
) (egressIfindex, txIfindex, ownerRGID int, txVlanID uint16, peerEgress bool) {
	peerEgress = egressFold != 0
	if peerEgress {
		if localIfindex, localVLAN, ok := m.resolveEgressFoldLocked(egressFold); ok {
			fibIfindex, fibVlanID = localIfindex, localVLAN
		} else {
			fibIfindex, fibVlanID = 0, 0
		}
	}
	egressIfindex, txIfindex, ownerRGID = m.sessionSyncEgressLocked(int(fibIfindex), fibVlanID, egressZone)
	return egressIfindex, txIfindex, ownerRGID, fibVlanID, peerEgress
}

// SetIngressFoldResolver wires the shared cluster-stable fold -> local
// {ifindex, vlan} lookup used for both ingress and egress peer identities.
// Passing nil leaves either fold unresolved and preserves the zone fallback.
func (m *Manager) SetIngressFoldResolver(fn func(uint32) (uint32, uint16, bool)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.ingressFoldResolver = fn
	m.mu.Unlock()
}
