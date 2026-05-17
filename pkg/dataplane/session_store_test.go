package dataplane

import (
	"fmt"
	"testing"
)

type sessionStoreTestDP struct {
	DataPlane
	v4           map[SessionKey]SessionValue
	v6           map[SessionKeyV6]SessionValueV6
	deletedDNAT  []DNATKey
	deletedDNAT6 []DNATKeyV6
}

func (m *sessionStoreTestDP) IterateSessions(fn func(SessionKey, SessionValue) bool) error {
	for key, val := range m.v4 {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (m *sessionStoreTestDP) IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	for key, val := range m.v6 {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (m *sessionStoreTestDP) GetSessionV4(key SessionKey) (SessionValue, error) {
	if val, ok := m.v4[key]; ok {
		return val, nil
	}
	return SessionValue{}, fmt.Errorf("not found")
}

func (m *sessionStoreTestDP) GetSessionV6(key SessionKeyV6) (SessionValueV6, error) {
	if val, ok := m.v6[key]; ok {
		return val, nil
	}
	return SessionValueV6{}, fmt.Errorf("not found")
}

func (m *sessionStoreTestDP) DeleteSession(key SessionKey) error {
	delete(m.v4, key)
	return nil
}

func (m *sessionStoreTestDP) DeleteSessionV6(key SessionKeyV6) error {
	delete(m.v6, key)
	return nil
}

func (m *sessionStoreTestDP) DeleteDNATEntry(key DNATKey) error {
	m.deletedDNAT = append(m.deletedDNAT, key)
	return nil
}

func (m *sessionStoreTestDP) DeleteDNATEntryV6(key DNATKeyV6) error {
	m.deletedDNAT6 = append(m.deletedDNAT6, key)
	return nil
}

func TestDeleteWithCompanionsV4RemovesReverseAndDNAT(t *testing.T) {
	forward := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80}
	reverse := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 80, DstPort: 1234}
	dp := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{
			forward: {
				ReverseKey: reverse,
				Flags:      SessFlagSNAT,
				NATSrcIP:   0x0a0200c0,
				NATSrcPort: 40000,
			},
			reverse: {IsReverse: 1},
		},
	}
	store := NewDataPlaneSessionStore(dp)

	if err := store.DeleteWithCompanionsV4(forward, DeleteReasonClusterStale); err != nil {
		t.Fatalf("DeleteWithCompanionsV4: %v", err)
	}
	if _, ok := dp.v4[forward]; ok {
		t.Fatal("forward session still present")
	}
	if _, ok := dp.v4[reverse]; ok {
		t.Fatal("reverse session still present")
	}
	wantDNAT := DNATKey{Protocol: 6, DstIP: 0x0a0200c0, DstPort: 40000}
	if len(dp.deletedDNAT) != 1 || dp.deletedDNAT[0] != wantDNAT {
		t.Fatalf("deleted DNAT = %+v, want [%+v]", dp.deletedDNAT, wantDNAT)
	}
}

func TestDeleteWithCompanionsV6RemovesReverseAndDNAT(t *testing.T) {
	forward := SessionKeyV6{Protocol: 17, SrcPort: 1234, DstPort: 53}
	forward.SrcIP[15] = 1
	forward.DstIP[15] = 2
	reverse := SessionKeyV6{Protocol: 17, SrcPort: 53, DstPort: 1234}
	reverse.SrcIP[15] = 2
	reverse.DstIP[15] = 1
	natIP := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	dp := &sessionStoreTestDP{
		v6: map[SessionKeyV6]SessionValueV6{
			forward: {
				ReverseKey: reverse,
				Flags:      SessFlagSNAT,
				NATSrcIP:   natIP,
				NATSrcPort: 53000,
			},
			reverse: {IsReverse: 1},
		},
	}
	store := NewDataPlaneSessionStore(dp)

	if err := store.DeleteWithCompanionsV6(forward, DeleteReasonClusterStale); err != nil {
		t.Fatalf("DeleteWithCompanionsV6: %v", err)
	}
	if _, ok := dp.v6[forward]; ok {
		t.Fatal("forward session still present")
	}
	if _, ok := dp.v6[reverse]; ok {
		t.Fatal("reverse session still present")
	}
	wantDNAT := DNATKeyV6{Protocol: 17, DstIP: natIP, DstPort: 53000}
	if len(dp.deletedDNAT6) != 1 || dp.deletedDNAT6[0] != wantDNAT {
		t.Fatalf("deleted DNATv6 = %+v, want [%+v]", dp.deletedDNAT6, wantDNAT)
	}
}
