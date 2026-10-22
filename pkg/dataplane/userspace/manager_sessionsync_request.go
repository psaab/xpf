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

// sessionSyncView is the #16172 family-neutral view of one session-sync
// request: every field the shared builder consumes, carried as RAW values
// (net.IP, network-order ports, raw MAC bytes) so rendering stays
// single-sourced in buildSessionSyncRequest. The V4/V6 adapters below only
// copy their family structs into this view — about fifteen lines each, no
// logic — and the exported-by-convention entry points
// buildSessionSyncRequestV4/V6 keep their names and signatures.
//
// hasValue distinguishes a delete (val == nil: key-only request) from an
// upsert. nat64SnatV4 is the ONE family-specific field: only the V6
// adapter sets it (non-zero marks a NAT64 cross-family session, #4565);
// the V4 adapter leaves it zero, so it can never appear on a V4 request.
type sessionSyncView struct {
	addrFamily uint8
	protocol   uint8
	srcIP      net.IP
	dstIP      net.IP
	srcPort    uint16 // network order; converted once in the builder
	dstPort    uint16 // network order

	hasValue bool

	ingressZone uint16
	egressZone  uint16

	ingressIfaceFold uint32
	natScopeFold     uint32
	egressIfaceFold  uint32
	routingDomain    uint32

	fibIfindex uint32
	fibVlanID  uint16
	fibDmac    [6]byte
	fibSmac    [6]byte
	fibGen     uint16
	logFlags   uint8

	natSrcIP   net.IP // raw; nil/zero renders "" in the builder
	natDstIP   net.IP
	natSrcPort uint16 // network order
	natDstPort uint16 // network order

	flags               uint16
	isReverse           uint8
	generation          uint64
	policyID            uint32
	policyCounterIdx    uint32
	policyRuleID        string
	appTimeout          uint32
	rtFlowSessionID     uint64
	sessionID           uint64
	tunnelDiscriminator uint64
	pptpCallIDs         uint64
	tcpCloseClass       uint8
	tcpHandshakeState   uint8
	installTableDomain  uint32
	installTableCheck   uint32
	sourceNatICMPValid  bool
	sourceNatICMPType   uint8
	sourceNatICMPCode   uint8

	nat64SnatV4 [4]byte // V6 adapter only (#4565); zero on V4
}

// viewV4 adapts the V4 BPF structs to the shared view. NAT addresses arrive
// as native-endian uint32s and are widened to raw net.IP here — the only
// family-specific rendering input; the builder renders them identically.
func viewV4(key dataplane.SessionKey, val *dataplane.SessionValue) sessionSyncView {
	v := sessionSyncView{
		addrFamily: dataplane.AFInet,
		protocol:   key.Protocol,
		srcIP:      net.IP(key.SrcIP[:]),
		dstIP:      net.IP(key.DstIP[:]),
		srcPort:    key.SrcPort,
		dstPort:    key.DstPort,
	}
	if val == nil {
		return v
	}
	v.hasValue = true
	v.ingressZone = val.IngressZone
	v.egressZone = val.EgressZone
	v.ingressIfaceFold = val.IngressIfaceFold
	v.natScopeFold = val.NatScopeFold
	v.egressIfaceFold = val.EgressIfaceFold
	v.routingDomain = val.RoutingDomain
	v.fibIfindex = val.FibIfindex
	v.fibVlanID = val.FibVlanID
	v.fibDmac = val.FibDmac
	v.fibSmac = val.FibSmac
	v.fibGen = val.FibGen
	v.logFlags = val.LogFlags
	v.natSrcIP = nativeUint32ToIP(val.NATSrcIP)
	v.natDstIP = nativeUint32ToIP(val.NATDstIP)
	v.natSrcPort = val.NATSrcPort
	v.natDstPort = val.NATDstPort
	v.flags = val.Flags
	v.isReverse = val.IsReverse
	v.generation = val.Generation
	v.policyID = val.PolicyID
	v.policyCounterIdx = val.PolicyCounterIdx
	v.policyRuleID = val.PolicyRuleID
	v.appTimeout = val.AppTimeout
	v.rtFlowSessionID = val.RTFlowSessionID
	v.sessionID = val.SessionID
	v.tunnelDiscriminator = val.TunnelDiscriminator
	v.pptpCallIDs = val.PptpCallIDs
	v.tcpCloseClass = val.TCPCloseClass
	v.tcpHandshakeState = val.TCPHandshakeState
	v.installTableDomain = val.InstallTableDomain
	v.installTableCheck = val.InstallTableCheck
	v.sourceNatICMPValid = val.SourceNatICMPValid
	v.sourceNatICMPType = val.SourceNatICMPType
	v.sourceNatICMPCode = val.SourceNatICMPCode
	// nat64SnatV4 deliberately unset: NAT64 pool state is V6-only (#4565).
	return v
}

// viewV6 adapts the V6 BPF structs to the shared view, and is the only
// adapter that sets nat64SnatV4 (#4565).
func viewV6(key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) sessionSyncView {
	v := sessionSyncView{
		addrFamily: dataplane.AFInet6,
		protocol:   key.Protocol,
		srcIP:      net.IP(key.SrcIP[:]),
		dstIP:      net.IP(key.DstIP[:]),
		srcPort:    key.SrcPort,
		dstPort:    key.DstPort,
	}
	if val == nil {
		return v
	}
	v.hasValue = true
	v.ingressZone = val.IngressZone
	v.egressZone = val.EgressZone
	v.ingressIfaceFold = val.IngressIfaceFold
	v.natScopeFold = val.NatScopeFold
	v.egressIfaceFold = val.EgressIfaceFold
	v.routingDomain = val.RoutingDomain
	v.fibIfindex = val.FibIfindex
	v.fibVlanID = val.FibVlanID
	v.fibDmac = val.FibDmac
	v.fibSmac = val.FibSmac
	v.fibGen = val.FibGen
	v.logFlags = val.LogFlags
	v.natSrcIP = net.IP(val.NATSrcIP[:])
	v.natDstIP = net.IP(val.NATDstIP[:])
	v.natSrcPort = val.NATSrcPort
	v.natDstPort = val.NATDstPort
	v.flags = val.Flags
	v.isReverse = val.IsReverse
	v.generation = val.Generation
	v.policyID = val.PolicyID
	v.policyCounterIdx = val.PolicyCounterIdx
	v.policyRuleID = val.PolicyRuleID
	v.appTimeout = val.AppTimeout
	v.rtFlowSessionID = val.RTFlowSessionID
	v.sessionID = val.SessionID
	v.tunnelDiscriminator = val.TunnelDiscriminator
	v.pptpCallIDs = val.PptpCallIDs
	v.tcpCloseClass = val.TCPCloseClass
	v.tcpHandshakeState = val.TCPHandshakeState
	v.installTableDomain = val.InstallTableDomain
	v.installTableCheck = val.InstallTableCheck
	v.sourceNatICMPValid = val.SourceNatICMPValid
	v.sourceNatICMPType = val.SourceNatICMPType
	v.sourceNatICMPCode = val.SourceNatICMPCode
	v.nat64SnatV4 = val.Nat64SnatV4
	return v
}

func (m *Manager) buildSessionSyncRequestV4(op string, key dataplane.SessionKey, val *dataplane.SessionValue) SessionSyncRequest {
	return m.buildSessionSyncRequest(op, viewV4(key, val))
}

func (m *Manager) buildSessionSyncRequestV6(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) SessionSyncRequest {
	return m.buildSessionSyncRequest(op, viewV6(key, val))
}

// buildSessionSyncRequest is the single builder behind both family entry
// points (#16172). All rendering (address/port/MAC strings) and all
// snapshot resolution happens here, once; the characterization goldens in
// manager_sessionsync_characterization_16172_test.go pin its byte output
// for both families.
func (m *Manager) buildSessionSyncRequest(op string, view sessionSyncView) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: view.addrFamily,
		Protocol:   view.protocol,
		SrcIP:      view.srcIP.String(),
		DstIP:      view.dstIP.String(),
		SrcPort:    networkUint16ToHost(view.srcPort),
		DstPort:    networkUint16ToHost(view.dstPort),
	}
	if view.hasValue {
		req.IngressZone = m.zoneNameByID(view.ingressZone)
		req.EgressZone = m.zoneNameByID(view.egressZone)
		// #919/#922: forward the raw u16 IDs alongside the legacy
		// strings; the Rust daemon prefers IDs when nonzero.
		req.IngressZoneID = view.ingressZone
		// #7095: resolve the peer's cluster-stable ingress fold to THIS node's
		// ifindex. The sender could not ship its own ifindex — it is node-local
		// — so it shipped a fold of the reth-relative name both nodes agree on,
		// and this is where it becomes a local number again. Unresolvable (0, an
		// unknown fold, or a collision) leaves both fields 0 and the consumer
		// falls back to the #4792 zone approximation, exactly as before #7095.
		if ifindex, vlan, ok := m.resolveIngressFoldLocked(view.ingressIfaceFold); ok {
			req.IngressIfindex = int(ifindex)
			req.IngressVLANID = vlan
		}
		// #15176: resolve the NAT-scope fold to this node's logical unit.
		if ifindex, _, ok := m.resolveIngressFoldLocked(view.natScopeFold); ok {
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
		req.RoutingDomain = view.routingDomain
		req.EgressZoneID = view.egressZone
		var peerEgress bool
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID, req.TXVLANID, peerEgress =
			m.sessionSyncEgressIdentityLocked(view.fibIfindex, view.fibVlanID, view.egressIfaceFold, req.EgressZone)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if view.logFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && view.fibGen != 0 {
			req.TunnelEndpointID = view.fibGen
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
			req.NeighborMAC = macString(view.fibDmac[:])
			req.SrcMAC = macString(view.fibSmac[:])
		}
		req.NATSrcIP = ipString(view.natSrcIP)
		req.NATDstIP = ipString(view.natDstIP)
		req.NATSrcPort = networkUint16ToHost(view.natSrcPort)
		req.NATDstPort = networkUint16ToHost(view.natDstPort)
		// #12187: derive the numeric wire value from the known marker and
		// static bit; marker-clear legacy rows remain omitted/unknown.
		req.SourceNatProvenance = dataplane.SourceNatProvenanceFromFlags(view.flags)
		req.FabricIngress = view.logFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = view.isReverse != 0
		// #2785: carry the per-policy `then log` selection to the peer helper
		// so the synced session logs the same RT_FLOW records after failover.
		req.LogSessionInit = view.logFlags&dataplane.LogFlagSessionInit != 0
		req.LogSessionClose = view.logFlags&dataplane.LogFlagSessionClose != 0
		// #2170: mirror the install generation to the helper so its in-memory
		// SyncedSessionEntry can enforce the same generation guard.
		req.Generation = view.generation
		// #3301: carry the admitting policy's firewall metadata so a
		// peer-PROMOTED session resolves the admitting policy (PolicyID),
		// increments the correct per-rule hit counter (PolicyCounterIdx), and
		// ages on the per-application idle timeout (AppTimeout, seconds) after
		// failover. 0 => unattributed / no counter / global timeout, the
		// pre-#3301 behavior an old helper still applies via serde(default).
		req.PolicyID = view.policyID
		req.PolicyCounterIdx = view.policyCounterIdx
		req.PolicyRuleID = view.policyRuleID
		req.InactivityTimeout = view.appTimeout
		// #4565: carry the NAT64 translated pool SOURCE (non-zero marks a NAT64
		// cross-family session) so the peer helper rebuilds the reverse (v4->v6)
		// BIB after promotion. Only the V6 adapter sets nat64SnatV4, so this
		// block is inert on V4 by construction. The generic nat_src/nat_dst
		// fields cannot carry a v4 pool source in a v6 session's slot
		// unambiguously — this dedicated dotted-quad is the helper's
		// authoritative snat_v4.
		if view.nat64SnatV4 != ([4]byte{}) {
			req.Nat64SnatV4 = net.IP(view.nat64SnatV4[:]).String()
		}
		// #5212: carry the originating node's stable RT_FLOW session id so the
		// peer helper adopts it on import instead of minting a fresh local id.
		// #9752 round 5 item 2: fall back to the mirror-preserved SessionID
		// when RTFlow is absent (mirror-sourced sweep resends lose the
		// sync-only tail). Post-convert SessionID is the adopted stable id
		// (or a per-incarnation-unique mint), so the fallback preserves
		// incarnation identity the helper's preserve rules key on — without
		// it a reused tuple's new incarnation arrives id-less and the old
		// PBR table is wrongly retained. Double-zero still omits (unknown).
		req.RTFlowSessionID = view.rtFlowSessionID
		if req.RTFlowSessionID == 0 {
			req.RTFlowSessionID = view.sessionID
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
		req.TunnelDiscriminator = view.tunnelDiscriminator
		req.PptpCallIDs = view.pptpCallIDs
		// #9412: forward the close class so the standby imports the close state.
		req.TCPCloseClass = view.tcpCloseClass
		// #10888: forward handshake state separately from the close class.
		req.TCPHandshakeState = dataplane.NormalizeTCPHandshakeState(view.tcpHandshakeState)
		// #9752: forward the installing-table identity so the standby imports
		// a PBR-steered session with the table its steer installed.
		req.InstallTableDomain = view.installTableDomain
		req.InstallTableCheck = view.installTableCheck
		// #11064: preserve typed source-NAT rule identity on the install leg.
		req.SourceNatICMPValid = view.sourceNatICMPValid
		req.SourceNatICMPType = view.sourceNatICMPType
		req.SourceNatICMPCode = view.sourceNatICMPCode
		if view.flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if view.flags&dataplane.SessFlagDNAT == 0 {
			req.NATDstIP = ""
			req.NATDstPort = 0
		}
	}
	return req
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
