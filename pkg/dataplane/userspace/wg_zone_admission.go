package userspace

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

const (
	userspaceWGIngressZoneMapCapacity = 65_536
	userspaceWGAdmissionMapCapacity   = 2 * userspaceLocalAddressMapCapacity * config.MaxSteeredWireGuardPorts
	userspaceWGUnTaggedVLANID         = uint16(0xffff)
)

// These key layouts mirror UserspaceWgIngressZoneKey and
// UserspaceWgAdmissionKey in userspace-xdp/src/lib.rs.
type userspaceWGIngressZoneKey struct {
	Ifindex  uint32
	VLANID   uint16
	Reserved uint16
}

type userspaceWGAdmissionKey struct {
	ZoneID     uint16
	Port       uint16
	AddrFamily uint8
	Pad        [3]byte
	Addr       [16]byte
}
type userspaceWGAddressKey struct {
	AddrFamily uint8
	Pad        [3]byte
	Addr       [16]byte
}

type userspaceWGZoneMaps struct {
	ingress   map[userspaceWGIngressZoneKey]uint16
	admission map[userspaceWGAdmissionKey]uint8
}

func userspaceWGZoneIDByName(snapshot *ConfigSnapshot) (map[string]uint16, error) {
	ids := make(map[string]uint16, len(snapshot.Zones))
	byID := make(map[uint16]string, len(snapshot.Zones))
	for _, zone := range snapshot.Zones {
		if zone.Name == "" || zone.ID == 0 {
			return nil, fmt.Errorf("invalid WG zone identity: name=%q id=%d", zone.Name, zone.ID)
		}
		if prior, ok := ids[zone.Name]; ok && prior != zone.ID {
			return nil, fmt.Errorf("WG zone %q has conflicting ids %d and %d", zone.Name, prior, zone.ID)
		}
		if prior, ok := byID[zone.ID]; ok && prior != zone.Name {
			return nil, fmt.Errorf("WG zones %q and %q share id %d", prior, zone.Name, zone.ID)
		}
		ids[zone.Name] = zone.ID
		byID[zone.ID] = zone.Name
	}
	return ids, nil
}

func addUserspaceWGIngressZone(dst map[userspaceWGIngressZoneKey]uint16, key userspaceWGIngressZoneKey, zoneID uint16) {
	if prior, exists := dst[key]; !exists {
		dst[key] = zoneID
	} else if prior != zoneID {
		dst[key] = 0
	}
}

func buildUserspaceWGZoneMaps(snapshot *ConfigSnapshot) (userspaceWGZoneMaps, error) {
	plan := userspaceWGZoneMaps{
		ingress:   make(map[userspaceWGIngressZoneKey]uint16),
		admission: make(map[userspaceWGAdmissionKey]uint8),
	}
	if snapshot == nil || !snapshot.ZoneSetValidated {
		return plan, nil
	}
	zoneIDs, err := userspaceWGZoneIDByName(snapshot)
	if err != nil {
		return userspaceWGZoneMaps{}, err
	}
	ingressIfindexes := make(map[uint32]struct{})
	for _, ifindex := range buildUserspaceIngressIfindexes(snapshot) {
		ingressIfindexes[ifindex] = struct{}{}
	}
	zoneID := func(name string) uint16 { return zoneIDs[name] }

	// Direct netdev arrivals and tagged parent arrivals are separate keys. An
	// untagged packet uses VLANID=0xffff so a priority-tagged VID 0 cannot alias
	// it. Conflicting logical owners poison the key to zone 0.
	for _, iface := range snapshot.Interfaces {
		if iface.Ifindex > 0 {
			if _, managed := ingressIfindexes[uint32(iface.Ifindex)]; managed {
				if !(iface.ParentIfindex == 0 && iface.NativeVLANID > 0) && iface.Zone != "" {
					addUserspaceWGIngressZone(plan.ingress, userspaceWGIngressZoneKey{
						Ifindex: uint32(iface.Ifindex), VLANID: userspaceWGUnTaggedVLANID,
					}, zoneID(iface.Zone))
				}
			}
		}
		if iface.ParentIfindex > 0 && iface.VLANID > 0 {
			parent := uint32(iface.ParentIfindex)
			if _, managed := ingressIfindexes[parent]; managed && iface.Zone != "" {
				addUserspaceWGIngressZone(plan.ingress, userspaceWGIngressZoneKey{
					Ifindex: parent, VLANID: uint16(iface.VLANID),
				}, zoneID(iface.Zone))
			}
		}
	}

	// A native VLAN is the logical owner of untagged arrivals on its parent.
	for _, base := range snapshot.Interfaces {
		if base.ParentIfindex != 0 || base.NativeVLANID <= 0 || base.Ifindex <= 0 {
			continue
		}
		parent := uint32(base.Ifindex)
		if _, managed := ingressIfindexes[parent]; !managed {
			continue
		}
		matches := 0
		var nativeZone uint16
		for _, unit := range snapshot.Interfaces {
			if unit.ParentIfindex == base.Ifindex && unit.VLANID == base.NativeVLANID && unit.Zone != "" {
				matches++
				nativeZone = zoneID(unit.Zone)
			}
		}
		if matches != 1 {
			nativeZone = 0
		}
		addUserspaceWGIngressZone(plan.ingress, userspaceWGIngressZoneKey{
			Ifindex: parent, VLANID: userspaceWGUnTaggedVLANID,
		}, nativeZone)
	}

	// Destination-address ownership must be unique. A duplicate address in two
	// zones is not sufficient authority for either one to claim the WG record.
	type addressOwner struct {
		zoneID    uint16
		seen      bool
		ambiguous bool
	}
	owners := make(map[userspaceWGAddressKey]addressOwner)
	// WG ownership follows configured address ownership, independently of
	// NAT's local-delivery exclusion. A primary WAN address remains the
	// listener's owner when interface SNAT routes it out of local_v*.
	for _, iface := range snapshot.Interfaces {
		if iface.AdminDisabled || unresolvedLo0LocalAddressOwner(iface) {
			continue
		}
		ownerZone := zoneID(iface.Zone)
		for _, address := range iface.Addresses {
			ip, _, parseErr := net.ParseCIDR(address.Address)
			if parseErr != nil || ip == nil {
				continue
			}
			key := userspaceWGAddressKey{}
			if v4 := ip.To4(); v4 != nil {
				key.AddrFamily = 2
				copy(key.Addr[:4], v4)
			} else if v6 := ip.To16(); v6 != nil {
				key.AddrFamily = 10
				copy(key.Addr[:], v6)
			} else {
				continue
			}
			owner, exists := owners[key]
			if !exists {
				owners[key] = addressOwner{zoneID: ownerZone, seen: true}
			} else if owner.zoneID != ownerZone {
				owner.ambiguous = true
				owners[key] = owner
			}
		}
	}

	selectedPorts := make(map[uint16]struct{}, len(snapshot.WgSteeredListenPorts))
	for _, port := range snapshotWgListenPorts(snapshot) {
		if port != 0 {
			selectedPorts[port] = struct{}{}
		}
	}
	// TunnelEndpoint.Zone is the logical tunnel's inner-policy zone, not the
	// underlay zone receiving its UDP listener. Attribute the listener through
	// its local Source address, then admit that port only for destinations
	// uniquely owned by the same underlay zone.
	portsByZone := make(map[uint16]map[uint16]struct{})
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.Mode != "wireguard" || endpoint.WgListenPort == 0 {
			continue
		}
		if _, selected := selectedPorts[endpoint.WgListenPort]; !selected {
			continue
		}
		sourceIP := net.ParseIP(endpoint.Source)
		if sourceIP == nil {
			continue
		}
		source := userspaceWGAddressKey{}
		if v4 := sourceIP.To4(); v4 != nil {
			source.AddrFamily = 2
			copy(source.Addr[:4], v4)
		} else if v6 := sourceIP.To16(); v6 != nil {
			source.AddrFamily = 10
			copy(source.Addr[:], v6)
		} else {
			continue
		}
		sourceOwner, exists := owners[source]
		if !exists || !sourceOwner.seen || sourceOwner.ambiguous || sourceOwner.zoneID == 0 {
			continue
		}
		if portsByZone[sourceOwner.zoneID] == nil {
			portsByZone[sourceOwner.zoneID] = make(map[uint16]struct{})
		}
		portsByZone[sourceOwner.zoneID][endpoint.WgListenPort] = struct{}{}
	}
	for address, owner := range owners {
		if !owner.seen || owner.ambiguous || owner.zoneID == 0 {
			continue
		}
		for port := range portsByZone[owner.zoneID] {
			key := userspaceWGAdmissionKey{
				ZoneID: owner.zoneID, Port: port, AddrFamily: address.AddrFamily,
				Pad: address.Pad, Addr: address.Addr,
			}
			plan.admission[key] = 1
		}
	}
	if len(plan.ingress) > userspaceWGIngressZoneMapCapacity {
		return userspaceWGZoneMaps{}, fmt.Errorf("userspace WG ingress-zone map needs %d entries, capacity %d", len(plan.ingress), userspaceWGIngressZoneMapCapacity)
	}
	if len(plan.admission) > userspaceWGAdmissionMapCapacity {
		return userspaceWGZoneMaps{}, fmt.Errorf("userspace WG admission map needs %d entries, capacity %d", len(plan.admission), userspaceWGAdmissionMapCapacity)
	}
	return plan, nil
}

func userspaceLocalAddressV4Key(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func (m *Manager) syncUserspaceWGZoneMapsLocked(snapshot *ConfigSnapshot) error {
	plan, err := buildUserspaceWGZoneMaps(snapshot)
	if err != nil {
		return err
	}
	ingressMap := m.bpfShim.Map(mapNameUserspaceWgIngressZones)
	if ingressMap == nil {
		return errors.New("userspace_wg_ingress_zones map not loaded")
	}
	admissionMap := m.bpfShim.Map(mapNameUserspaceWgZoneAdmission)
	if admissionMap == nil {
		return errors.New("userspace_wg_zone_admission map not loaded")
	}

	currentIngress := make(map[userspaceWGIngressZoneKey]uint16)
	var ingressKey userspaceWGIngressZoneKey
	var ingressValue uint16
	ingressIter := ingressMap.Iterate()
	for ingressIter.Next(&ingressKey, &ingressValue) {
		currentIngress[ingressKey] = ingressValue
	}
	if err := ingressIter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_wg_ingress_zones: %w", err)
	}
	currentAdmission := make(map[userspaceWGAdmissionKey]uint8)
	var admissionKey userspaceWGAdmissionKey
	var admissionValue uint8
	admissionIter := admissionMap.Iterate()
	for admissionIter.Next(&admissionKey, &admissionValue) {
		currentAdmission[admissionKey] = admissionValue
	}
	if err := admissionIter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_wg_zone_admission: %w", err)
	}
	if sameUserspaceWGIngressZones(currentIngress, plan.ingress) &&
		sameUserspaceWGAdmission(currentAdmission, plan.admission) {
		return nil
	}

	// Close the claim gate before changing its resolver. Any failure leaves the
	// caller's existing fail-closed ctrl path to disable XDP until a full retry.
	for key := range currentAdmission {
		if err := admissionMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale userspace_wg_zone_admission entry: %w", err)
		}
	}
	for key, value := range plan.ingress {
		if err := ingressMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_wg_ingress_zones ifindex=%d vlan=%d: %w", key.Ifindex, key.VLANID, err)
		}
	}
	for key := range currentIngress {
		if _, keep := plan.ingress[key]; keep {
			continue
		}
		if err := ingressMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale userspace_wg_ingress_zones ifindex=%d vlan=%d: %w", key.Ifindex, key.VLANID, err)
		}
	}
	for key, value := range plan.admission {
		if err := admissionMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_wg_zone_admission zone=%d port=%d family=%d: %w", key.ZoneID, key.Port, key.AddrFamily, err)
		}
	}
	return nil
}

func sameUserspaceWGIngressZones(a, b map[userspaceWGIngressZoneKey]uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		got, ok := b[key]
		if !ok || got != value {
			return false
		}
	}
	return true
}

func sameUserspaceWGAdmission(a, b map[userspaceWGAdmissionKey]uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		got, ok := b[key]
		if !ok || got != value {
			return false
		}
	}
	return true
}
