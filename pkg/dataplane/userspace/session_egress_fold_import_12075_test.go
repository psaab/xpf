package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #12075: the peer's FibIfindex may alias a different local interface. The
// cluster-stable fold, not that sender-local number, must select the local
// egress unit and its owner RG.
func TestSessionSyncRequestResolvesEgressFold12075(t *testing.T) {
	const (
		fold        = uint32(0x12075001)
		peerIfindex = 42
	)
	newManager := func() *Manager {
		m := &Manager{lastSnapshot: &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
			{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			},
			{
				Name:            "ge-0-0-9",
				Ifindex:         peerIfindex,
				RedundancyGroup: 2,
			},
		}}}
		m.SetIngressFoldResolver(func(got uint32) (uint32, uint16, bool) {
			if got != fold {
				return 0, 0, false
			}
			// The fold resolves to the receiving node's parent and VLAN unit.
			return 6, 80, true
		})
		return m
	}

	t.Run("v4", func(t *testing.T) {
		m := newManager()
		req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, &dataplane.SessionValue{
			FibIfindex:      peerIfindex,
			EgressIfaceFold: fold,
		})
		if req.EgressIfindex != 12 || req.TXIfindex != 6 || req.TXVLANID != 80 || req.OwnerRGID != 1 {
			t.Fatalf("v4 egress = (%d,%d) vlan %d owner RG %d; want local WAN unit (12,6,80), RG 1; sender ifindex %d aliases RG 2",
				req.EgressIfindex, req.TXIfindex, req.TXVLANID, req.OwnerRGID, peerIfindex)
		}
	})

	t.Run("v6", func(t *testing.T) {
		m := newManager()
		req := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, &dataplane.SessionValueV6{
			FibIfindex:      peerIfindex,
			EgressIfaceFold: fold,
		})
		if req.EgressIfindex != 12 || req.TXIfindex != 6 || req.TXVLANID != 80 || req.OwnerRGID != 1 {
			t.Fatalf("v6 egress = (%d,%d) vlan %d owner RG %d; want local WAN unit (12,6,80), RG 1; sender ifindex %d aliases RG 2",
				req.EgressIfindex, req.TXIfindex, req.TXVLANID, req.OwnerRGID, peerIfindex)
		}
	})
}

func TestSessionSyncRequestRejectsUnknownPeerEgressFold12075(t *testing.T) {
	const peerIfindex = 42
	m := &Manager{lastSnapshot: &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0-0-9", Ifindex: peerIfindex, RedundancyGroup: 2},
	}}}
	m.SetIngressFoldResolver(func(uint32) (uint32, uint16, bool) {
		return 0, 0, false
	})
	check := func(name string, req SessionSyncRequest) {
		t.Helper()
		if req.EgressIfindex == peerIfindex || req.TXIfindex == peerIfindex || req.OwnerRGID == 2 {
			t.Errorf("%s unknown peer fold used sender-local egress: egress=%d tx=%d owner RG=%d",
				name, req.EgressIfindex, req.TXIfindex, req.OwnerRGID)
		}
		if req.NeighborMAC != "" || req.SrcMAC != "" {
			t.Errorf("%s unknown peer fold carried sender-local MACs: neighbor=%q source=%q",
				name, req.NeighborMAC, req.SrcMAC)
		}
	}
	check("v4", m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, &dataplane.SessionValue{
		FibIfindex:      peerIfindex,
		EgressIfaceFold: 0xDEADBEEF,
		FibDmac:         [6]byte{1, 2, 3, 4, 5, 6},
		FibSmac:         [6]byte{6, 5, 4, 3, 2, 1},
	}))
	check("v6", m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, &dataplane.SessionValueV6{
		FibIfindex:      peerIfindex,
		EgressIfaceFold: 0xDEADBEEF,
		FibDmac:         [6]byte{1, 2, 3, 4, 5, 6},
		FibSmac:         [6]byte{6, 5, 4, 3, 2, 1},
	}))
}

func TestSessionSyncRequestKeepsFoldZeroLocalEgress12075(t *testing.T) {
	const localIfindex = 42
	m := &Manager{lastSnapshot: &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0-0-9", Ifindex: localIfindex, RedundancyGroup: 2},
	}}}
	check := func(name string, req SessionSyncRequest) {
		t.Helper()
		if req.EgressIfindex != localIfindex || req.TXIfindex != localIfindex || req.OwnerRGID != 2 {
			t.Errorf("%s fold-zero local egress = (%d,%d) owner RG %d, want (%d,%d) RG 2",
				name, req.EgressIfindex, req.TXIfindex, req.OwnerRGID, localIfindex, localIfindex)
		}
		if req.NeighborMAC != "01:02:03:04:05:06" || req.SrcMAC != "06:05:04:03:02:01" {
			t.Errorf("%s fold-zero local MACs = (%q,%q), want local cached FIB MACs",
				name, req.NeighborMAC, req.SrcMAC)
		}
	}
	check("v4", m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, &dataplane.SessionValue{
		FibIfindex: localIfindex,
		FibDmac:    [6]byte{1, 2, 3, 4, 5, 6},
		FibSmac:    [6]byte{6, 5, 4, 3, 2, 1},
	}))
	check("v6", m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, &dataplane.SessionValueV6{
		FibIfindex: localIfindex,
		FibDmac:    [6]byte{1, 2, 3, 4, 5, 6},
		FibSmac:    [6]byte{6, 5, 4, 3, 2, 1},
	}))
}
