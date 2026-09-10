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

func (m *Manager) buildSessionSyncRequestV4(op string, key dataplane.SessionKey, val *dataplane.SessionValue) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    networkUint16ToHost(key.SrcPort),
		DstPort:    networkUint16ToHost(key.DstPort),
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		// #919/#922: forward the raw u16 IDs alongside the legacy
		// strings; the Rust daemon prefers IDs when nonzero.
		req.IngressZoneID = val.IngressZone
		// #7095: resolve the peer's cluster-stable ingress fold to THIS node's
		// ifindex. The sender could not ship its own ifindex — it is node-local
		// — so it shipped a fold of the reth-relative name both nodes agree on,
		// and this is where it becomes a local number again. Unresolvable (0, an
		// unknown fold, or a collision) leaves both fields 0 and the consumer
		// falls back to the #4792 zone approximation, exactly as before #7095.
		if ifindex, vlan, ok := m.resolveIngressFoldLocked(val.IngressIfaceFold); ok {
			req.IngressIfindex = int(ifindex)
			req.IngressVLANID = vlan
		}
		// #7239 (#7160/#2387): hand the helper the domain the SENDER stamped at
		// install, so it does not have to re-derive one from the fold resolved
		// just above. The fold is computed on the sender's SEND path against
		// its CURRENT config, so an ifindex recycled onto a sibling between
		// install and sync resolves here to the sibling — and deriving the
		// domain from that files the session in the sibling's routing instance.
		// A carried domain cannot drift that way; 0 means the default instance,
		// which is what a peer predating the field sends.
		req.RoutingDomain = val.RoutingDomain
		req.EgressZoneID = val.EgressZone
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID, req.EgressZone)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && val.FibGen != 0 {
			req.TunnelEndpointID = val.FibGen
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
		} else {
			req.TXVLANID = val.FibVlanID
			req.NeighborMAC = macString(val.FibDmac[:])
			req.SrcMAC = macString(val.FibSmac[:])
		}
		req.NATSrcIP = ipString(nativeUint32ToIP(val.NATSrcIP))
		req.NATDstIP = ipString(nativeUint32ToIP(val.NATDstIP))
		req.NATSrcPort = networkUint16ToHost(val.NATSrcPort)
		req.NATDstPort = networkUint16ToHost(val.NATDstPort)
		req.FabricIngress = val.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = val.IsReverse != 0
		// #2785: carry the per-policy `then log` selection to the peer helper
		// so the synced session logs the same RT_FLOW records after failover.
		req.LogSessionInit = val.LogFlags&dataplane.LogFlagSessionInit != 0
		req.LogSessionClose = val.LogFlags&dataplane.LogFlagSessionClose != 0
		// #2170: mirror the install generation to the helper so its in-memory
		// SyncedSessionEntry can enforce the same generation guard.
		req.Generation = val.Generation
		// #3301: carry the admitting policy's firewall metadata so a
		// peer-PROMOTED session resolves the admitting policy (PolicyID),
		// increments the correct per-rule hit counter (PolicyCounterIdx), and
		// ages on the per-application idle timeout (AppTimeout, seconds) after
		// failover. 0 => unattributed / no counter / global timeout, the
		// pre-#3301 behavior an old helper still applies via serde(default).
		req.PolicyID = val.PolicyID
		req.PolicyCounterIdx = val.PolicyCounterIdx
		req.InactivityTimeout = val.AppTimeout
		// #5212: carry the originating node's stable RT_FLOW session id so the
		// peer helper adopts it on import instead of minting a fresh local id.
		req.RTFlowSessionID = val.RTFlowSessionID
		// #7188: carry the tunnel session-identity discriminator to the peer
		// helper, which folds it into the key it reconstructs. Two RFC 2890 GRE
		// tunnels between one pair of outer endpoints are ONE Go session key
		// (protocol 47 has no L4 ports), so without this the helper rebuilt both
		// records as the same key and the second install evicted the first.
		//
		// A "delete" request is built with val == nil and therefore carries 0 —
		// the RESERVED "not carried" tag. That is deliberate and safe: a delete
		// reconstructs the key with Delete intent on the helper, which resolves
		// an absent discriminator to the None class, so it can only under-match.
		// A keyed-GRE synced session is retracted by its idle timeout rather
		// than by an explicit delete.
		req.TunnelDiscriminator = val.TunnelDiscriminator
		// #9412: forward the close class so the standby imports the close state.
		req.TCPCloseClass = val.TCPCloseClass
		if val.Flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if val.Flags&dataplane.SessFlagDNAT == 0 {
			req.NATDstIP = ""
			req.NATDstPort = 0
		}
	}
	return req
}

func (m *Manager) buildSessionSyncRequestV6(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet6,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    networkUint16ToHost(key.SrcPort),
		DstPort:    networkUint16ToHost(key.DstPort),
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		// #919/#922: forward the raw u16 IDs alongside the legacy
		// strings; the Rust daemon prefers IDs when nonzero.
		req.IngressZoneID = val.IngressZone
		// #7095: resolve the peer's cluster-stable ingress fold to THIS node's
		// ifindex. The sender could not ship its own ifindex — it is node-local
		// — so it shipped a fold of the reth-relative name both nodes agree on,
		// and this is where it becomes a local number again. Unresolvable (0, an
		// unknown fold, or a collision) leaves both fields 0 and the consumer
		// falls back to the #4792 zone approximation, exactly as before #7095.
		if ifindex, vlan, ok := m.resolveIngressFoldLocked(val.IngressIfaceFold); ok {
			req.IngressIfindex = int(ifindex)
			req.IngressVLANID = vlan
		}
		// #7239 (#7160/#2387): hand the helper the domain the SENDER stamped at
		// install, so it does not have to re-derive one from the fold resolved
		// just above. The fold is computed on the sender's SEND path against
		// its CURRENT config, so an ifindex recycled onto a sibling between
		// install and sync resolves here to the sibling — and deriving the
		// domain from that files the session in the sibling's routing instance.
		// A carried domain cannot drift that way; 0 means the default instance,
		// which is what a peer predating the field sends.
		req.RoutingDomain = val.RoutingDomain
		req.EgressZoneID = val.EgressZone
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID, req.EgressZone)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && val.FibGen != 0 {
			req.TunnelEndpointID = val.FibGen
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
		} else {
			req.TXVLANID = val.FibVlanID
			req.NeighborMAC = macString(val.FibDmac[:])
			req.SrcMAC = macString(val.FibSmac[:])
		}
		req.NATSrcIP = ipString(net.IP(val.NATSrcIP[:]))
		req.NATDstIP = ipString(net.IP(val.NATDstIP[:]))
		req.NATSrcPort = networkUint16ToHost(val.NATSrcPort)
		req.NATDstPort = networkUint16ToHost(val.NATDstPort)
		req.FabricIngress = val.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = val.IsReverse != 0
		// #2785: carry the per-policy `then log` selection to the peer helper
		// so the synced session logs the same RT_FLOW records after failover.
		req.LogSessionInit = val.LogFlags&dataplane.LogFlagSessionInit != 0
		req.LogSessionClose = val.LogFlags&dataplane.LogFlagSessionClose != 0
		// #2170: mirror the install generation to the helper.
		req.Generation = val.Generation
		// #3301: carry the admitting policy's firewall metadata (see V4).
		req.PolicyID = val.PolicyID
		req.PolicyCounterIdx = val.PolicyCounterIdx
		req.InactivityTimeout = val.AppTimeout
		// #4565: carry the NAT64 translated pool SOURCE (non-zero marks a NAT64
		// cross-family session) so the peer helper rebuilds the reverse (v4->v6)
		// BIB after promotion. The generic nat_src/nat_dst fields cannot carry a
		// v4 pool source in a v6 session's slot unambiguously — this dedicated
		// dotted-quad is the helper's authoritative snat_v4.
		if val.Nat64SnatV4 != ([4]byte{}) {
			req.Nat64SnatV4 = net.IP(val.Nat64SnatV4[:]).String()
		}
		// #5212: carry the originating node's stable RT_FLOW session id (see V4).
		req.RTFlowSessionID = val.RTFlowSessionID
		// #7188: carry the tunnel session-identity discriminator (see V4).
		req.TunnelDiscriminator = val.TunnelDiscriminator
		// #9412: forward the close class so the standby imports the close state.
		req.TCPCloseClass = val.TCPCloseClass
		if val.Flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if val.Flags&dataplane.SessFlagDNAT == 0 {
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
	return fn(fold)
}

// SetIngressFoldResolver wires the #7095 fold -> local {ifindex, vlan} lookup.
// Passing nil restores the pre-#7095 behaviour of importing no ingress identity.
func (m *Manager) SetIngressFoldResolver(fn func(uint32) (uint32, uint16, bool)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.ingressFoldResolver = fn
	m.mu.Unlock()
}
