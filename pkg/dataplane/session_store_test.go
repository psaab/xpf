package dataplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type sessionStoreTestDP struct {
	DataPlane
	v4           map[SessionKey]SessionValue
	v6           map[SessionKeyV6]SessionValueV6
	deletedDNAT  []DNATKey
	deletedDNAT6 []DNATKeyV6
	setDNAT      []DNATKey
	setDNAT6     []DNATKeyV6
	pnat         *PersistentNATTable
	failSetV4    map[SessionKey]error
	failSetV6    map[SessionKeyV6]error
	failSetDNAT  error
	failSetDNAT6 error
	failDelV4    map[SessionKey]error
	failDelV6    map[SessionKeyV6]error
	failDelDNAT  map[DNATKey]error
	failDelDNAT6 map[DNATKeyV6]error
	batchDelV4   int
	batchDelV6   int
	forceGetMiss bool
}

func (m *sessionStoreTestDP) IterateSessions(fn func(SessionKey, SessionValue) bool) error {
	for key, val := range m.v4 {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (m *sessionStoreTestDP) BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error {
	return m.IterateSessions(fn)
}

func (m *sessionStoreTestDP) IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	for key, val := range m.v6 {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (m *sessionStoreTestDP) BatchIterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	return m.IterateSessionsV6(fn)
}

func (m *sessionStoreTestDP) GetSessionV4(key SessionKey) (SessionValue, error) {
	if m.forceGetMiss {
		return SessionValue{}, ebpf.ErrKeyNotExist
	}
	if val, ok := m.v4[key]; ok {
		return val, nil
	}
	return SessionValue{}, ebpf.ErrKeyNotExist
}

func (m *sessionStoreTestDP) GetSessionV6(key SessionKeyV6) (SessionValueV6, error) {
	if m.forceGetMiss {
		return SessionValueV6{}, ebpf.ErrKeyNotExist
	}
	if val, ok := m.v6[key]; ok {
		return val, nil
	}
	return SessionValueV6{}, ebpf.ErrKeyNotExist
}

func (m *sessionStoreTestDP) SetSessionV4(key SessionKey, val SessionValue) error {
	if err, ok := m.failSetV4[key]; ok {
		return err
	}
	if m.v4 == nil {
		m.v4 = make(map[SessionKey]SessionValue)
	}
	m.v4[key] = val
	return nil
}

func (m *sessionStoreTestDP) SetSessionV6(key SessionKeyV6, val SessionValueV6) error {
	if err, ok := m.failSetV6[key]; ok {
		return err
	}
	if m.v6 == nil {
		m.v6 = make(map[SessionKeyV6]SessionValueV6)
	}
	m.v6[key] = val
	return nil
}

func (m *sessionStoreTestDP) DeleteSession(key SessionKey) error {
	if err, ok := m.failDelV4[key]; ok {
		return err
	}
	delete(m.v4, key)
	return nil
}

func (m *sessionStoreTestDP) DeleteSessionV6(key SessionKeyV6) error {
	if err, ok := m.failDelV6[key]; ok {
		return err
	}
	delete(m.v6, key)
	return nil
}

func (m *sessionStoreTestDP) BatchDeleteSessions(keys []SessionKey) (int, error) {
	m.batchDelV4++
	for i, key := range keys {
		if err := m.DeleteSession(key); err != nil {
			return i, err
		}
	}
	return len(keys), nil
}

func (m *sessionStoreTestDP) BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error) {
	m.batchDelV6++
	for i, key := range keys {
		if err := m.DeleteSessionV6(key); err != nil {
			return i, err
		}
	}
	return len(keys), nil
}

func (m *sessionStoreTestDP) DeleteDNATEntry(key DNATKey) error {
	if err, ok := m.failDelDNAT[key]; ok {
		return err
	}
	m.deletedDNAT = append(m.deletedDNAT, key)
	return nil
}

func (m *sessionStoreTestDP) DeleteDNATEntryV6(key DNATKeyV6) error {
	if err, ok := m.failDelDNAT6[key]; ok {
		return err
	}
	m.deletedDNAT6 = append(m.deletedDNAT6, key)
	return nil
}

func (m *sessionStoreTestDP) SetDNATEntry(key DNATKey, _ DNATValue) error {
	if m.failSetDNAT != nil {
		return m.failSetDNAT
	}
	m.setDNAT = append(m.setDNAT, key)
	return nil
}

func (m *sessionStoreTestDP) SetDNATEntryV6(key DNATKeyV6, _ DNATValueV6) error {
	if m.failSetDNAT6 != nil {
		return m.failSetDNAT6
	}
	m.setDNAT6 = append(m.setDNAT6, key)
	return nil
}

func (m *sessionStoreTestDP) GetPersistentNAT() *PersistentNATTable { return m.pnat }

func TestPutClusterSyncedV4RollsBackForwardWhenReverseInstallFails(t *testing.T) {
	forward := SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1234,
		DstPort:  80,
	}
	reverse := SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 2},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  80,
		DstPort:  1234,
	}
	reverseErr := errors.New("reverse install failed")
	dp := &sessionStoreTestDP{
		v4:        map[SessionKey]SessionValue{},
		failSetV4: map[SessionKey]error{reverse: reverseErr},
	}
	store := NewDataPlaneSessionStore(dp)

	err := store.PutClusterSyncedV4(forward, SessionValue{
		State:      SessStateEstablished,
		ReverseKey: reverse,
	})
	if !errors.Is(err, reverseErr) {
		t.Fatalf("PutClusterSyncedV4 error = %v, want reverse error", err)
	}
	if _, ok := dp.v4[forward]; ok {
		t.Fatal("forward session remained after reverse install failure")
	}
	if _, ok := dp.v4[reverse]; ok {
		t.Fatal("reverse session unexpectedly installed")
	}
}

func TestPutClusterSyncedV4RollsBackForwardAndReverseWhenDNATFails(t *testing.T) {
	forward := SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1234,
		DstPort:  80,
	}
	reverse := SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 2},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  80,
		DstPort:  1234,
	}
	dnatErr := errors.New("dnat install failed")
	dp := &sessionStoreTestDP{
		v4:          map[SessionKey]SessionValue{},
		failSetDNAT: dnatErr,
	}
	store := NewDataPlaneSessionStore(dp)

	err := store.PutClusterSyncedV4(forward, SessionValue{
		State:      SessStateEstablished,
		ReverseKey: reverse,
		Flags:      SessFlagSNAT,
		NATSrcIP:   0x0a0200c0,
		NATSrcPort: 40000,
	})
	if !errors.Is(err, dnatErr) {
		t.Fatalf("PutClusterSyncedV4 error = %v, want DNAT error", err)
	}
	if _, ok := dp.v4[forward]; ok {
		t.Fatal("forward session remained after DNAT install failure")
	}
	if _, ok := dp.v4[reverse]; ok {
		t.Fatal("reverse session remained after DNAT install failure")
	}
	if len(dp.setDNAT) != 0 {
		t.Fatalf("DNAT entries installed despite failure: %+v", dp.setDNAT)
	}
}

func TestPutClusterSyncedV6RollsBackForwardWhenReverseInstallFails(t *testing.T) {
	forward := SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 80}
	forward.SrcIP[15] = 1
	forward.DstIP[15] = 2
	reverse := SessionKeyV6{Protocol: 6, SrcPort: 80, DstPort: 1234}
	reverse.SrcIP[15] = 2
	reverse.DstIP[15] = 1

	reverseErr := errors.New("reverse v6 install failed")
	dp := &sessionStoreTestDP{
		v6:        map[SessionKeyV6]SessionValueV6{},
		failSetV6: map[SessionKeyV6]error{reverse: reverseErr},
	}
	store := NewDataPlaneSessionStore(dp)

	err := store.PutClusterSyncedV6(forward, SessionValueV6{
		State:      SessStateEstablished,
		ReverseKey: reverse,
	})
	if !errors.Is(err, reverseErr) {
		t.Fatalf("PutClusterSyncedV6 error = %v, want reverse error", err)
	}
	if _, ok := dp.v6[forward]; ok {
		t.Fatal("forward v6 session remained after reverse install failure")
	}
	if _, ok := dp.v6[reverse]; ok {
		t.Fatal("reverse v6 session unexpectedly installed")
	}
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

func TestDeleteKnownV4StopsBeforeSessionsWhenDNATDeleteFails(t *testing.T) {
	forward := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80}
	reverse := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 80, DstPort: 1234}
	val := SessionValue{
		ReverseKey: reverse,
		Flags:      SessFlagSNAT,
		NATSrcIP:   0x0a0200c0,
		NATSrcPort: 40000,
	}
	dnatErr := errors.New("dnat delete failed")
	dp := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{
			forward: val,
			reverse: {IsReverse: 1},
		},
		failDelDNAT: map[DNATKey]error{
			dnatKeyForSessionV4(forward, val): dnatErr,
		},
	}
	store := NewDataPlaneSessionStore(dp)

	err := store.DeleteKnownV4(forward, val, DeleteReasonGCExpired)
	if !errors.Is(err, dnatErr) {
		t.Fatalf("DeleteKnownV4 error = %v, want DNAT error", err)
	}
	if _, ok := dp.v4[forward]; !ok {
		t.Fatal("forward session was deleted after DNAT cleanup failure")
	}
	if _, ok := dp.v4[reverse]; !ok {
		t.Fatal("reverse session was deleted after DNAT cleanup failure")
	}
}

func TestDeleteKnownV4StopsBeforeForwardWhenReverseDeleteFails(t *testing.T) {
	forward := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80}
	reverse := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 80, DstPort: 1234}
	val := SessionValue{ReverseKey: reverse}
	reverseErr := errors.New("reverse delete failed")
	dp := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{
			forward: val,
			reverse: {IsReverse: 1},
		},
		failDelV4: map[SessionKey]error{reverse: reverseErr},
	}
	store := NewDataPlaneSessionStore(dp)

	err := store.DeleteKnownV4(forward, val, DeleteReasonGCExpired)
	if !errors.Is(err, reverseErr) {
		t.Fatalf("DeleteKnownV4 error = %v, want reverse error", err)
	}
	if _, ok := dp.v4[forward]; !ok {
		t.Fatal("forward session was deleted after reverse cleanup failure")
	}
}

func TestDeleteBatchKnownV4UsesBatchSessionDeletes(t *testing.T) {
	const n = sessionDeleteBatchSize + 6
	dp := &sessionStoreTestDP{
		v4: make(map[SessionKey]SessionValue),
	}
	entries := make([]SessionEntryV4, 0, n)
	for i := 0; i < n; i++ {
		forward := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, byte(i + 1)}, DstIP: [4]byte{10, 0, 1, 1}, SrcPort: uint16(1000 + i), DstPort: 80}
		reverse := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 0, byte(i + 1)}, SrcPort: 80, DstPort: uint16(1000 + i)}
		val := SessionValue{ReverseKey: reverse}
		dp.v4[forward] = val
		dp.v4[reverse] = SessionValue{IsReverse: 1}
		entries = append(entries, SessionEntryV4{Key: forward, Value: val})
	}
	store := NewDataPlaneSessionStore(dp)

	deleted, err := store.DeleteBatchKnownV4(entries, DeleteReasonGCExpired)
	if err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if deleted != n {
		t.Fatalf("deleted = %d, want %d", deleted, n)
	}
	if dp.batchDelV4 != 4 {
		t.Fatalf("BatchDeleteSessions calls = %d, want 4", dp.batchDelV4)
	}
	if len(dp.v4) != 0 {
		t.Fatalf("sessions remaining = %d, want 0", len(dp.v4))
	}
}

func TestDeleteBatchKnownV4ReturnsPartialForwardDeletesOnBatchError(t *testing.T) {
	const n = sessionDeleteBatchSize + 3
	dp := &sessionStoreTestDP{
		v4:        make(map[SessionKey]SessionValue),
		failDelV4: make(map[SessionKey]error),
	}
	entries := make([]SessionEntryV4, 0, n)
	var failKey SessionKey
	for i := 0; i < n; i++ {
		key := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, byte(i + 1)}, DstIP: [4]byte{10, 0, 1, 1}, SrcPort: uint16(1000 + i), DstPort: 80}
		dp.v4[key] = SessionValue{}
		entries = append(entries, SessionEntryV4{Key: key})
		if i == sessionDeleteBatchSize+1 {
			failKey = key
		}
	}
	batchErr := errors.New("batch delete failed")
	dp.failDelV4[failKey] = batchErr
	store := NewDataPlaneSessionStore(dp)

	deleted, err := store.DeleteBatchKnownV4(entries, DeleteReasonGCExpired)
	if !errors.Is(err, batchErr) {
		t.Fatalf("DeleteBatchKnownV4 error = %v, want batch error", err)
	}
	wantDeleted := sessionDeleteBatchSize + 1
	if deleted != wantDeleted {
		t.Fatalf("deleted = %d, want %d", deleted, wantDeleted)
	}
	if dp.batchDelV4 != 2 {
		t.Fatalf("BatchDeleteSessions calls = %d, want 2", dp.batchDelV4)
	}
	if _, ok := dp.v4[failKey]; !ok {
		t.Fatal("failed key was deleted despite batch error")
	}
}

func TestDeleteBatchKnownV6ReturnsPartialForwardDeletesOnBatchError(t *testing.T) {
	const n = sessionDeleteBatchSize + 3
	dp := &sessionStoreTestDP{
		v6:        make(map[SessionKeyV6]SessionValueV6),
		failDelV6: make(map[SessionKeyV6]error),
	}
	entries := make([]SessionEntryV6, 0, n)
	var failKey SessionKeyV6
	for i := 0; i < n; i++ {
		key := SessionKeyV6{Protocol: 6, SrcPort: uint16(1000 + i), DstPort: 80}
		key.SrcIP[15] = byte(i + 1)
		key.DstIP[15] = 1
		dp.v6[key] = SessionValueV6{}
		entries = append(entries, SessionEntryV6{Key: key})
		if i == sessionDeleteBatchSize+1 {
			failKey = key
		}
	}
	batchErr := errors.New("batch delete failed")
	dp.failDelV6[failKey] = batchErr
	store := NewDataPlaneSessionStore(dp)

	deleted, err := store.DeleteBatchKnownV6(entries, DeleteReasonGCExpired)
	if !errors.Is(err, batchErr) {
		t.Fatalf("DeleteBatchKnownV6 error = %v, want batch error", err)
	}
	wantDeleted := sessionDeleteBatchSize + 1
	if deleted != wantDeleted {
		t.Fatalf("deleted = %d, want %d", deleted, wantDeleted)
	}
	if dp.batchDelV6 != 2 {
		t.Fatalf("BatchDeleteSessionsV6 calls = %d, want 2", dp.batchDelV6)
	}
	if _, ok := dp.v6[failKey]; !ok {
		t.Fatal("failed key was deleted despite batch error")
	}
}

func TestReconcileClusterBulkUsesIteratorValueForCompanionDeleteV4(t *testing.T) {
	forward := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80}
	reverse := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 80, DstPort: 1234}
	dp := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{
			forward: {
				IngressZone: 2,
				ReverseKey:  reverse,
				Flags:       SessFlagSNAT,
				NATSrcIP:    0x0a0200c0,
				NATSrcPort:  40000,
			},
			reverse: {IsReverse: 1, IngressZone: 2},
		},
		forceGetMiss: true,
	}
	store := NewDataPlaneSessionStore(dp)

	result, err := store.ReconcileClusterBulk(ClusterBulkReconcileInput{
		ReceivedV4:     map[SessionKey]struct{}{},
		ShouldSyncZone: func(zone uint16) bool { return false },
		DeleteReason:   DeleteReasonClusterStale,
	})
	if err != nil {
		t.Fatalf("ReconcileClusterBulk: %v", err)
	}
	if result.DeletedV4 != 1 {
		t.Fatalf("DeletedV4 = %d, want 1", result.DeletedV4)
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

func TestDeleteWithCompanionsV4PreservesPersistentNATBinding(t *testing.T) {
	forward := SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1234,
		DstPort:  80,
	}
	reverse := SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 2},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  80,
		DstPort:  1234,
	}
	const natIPU32 = 0x0a0200c0
	var natIPBytes [4]byte
	binary.NativeEndian.PutUint32(natIPBytes[:], natIPU32)
	natIP := netip.AddrFrom4(natIPBytes)

	pnat := NewPersistentNATTable()
	pnat.SetPoolConfig("pool-a", PersistentNATPoolInfo{
		Timeout:             time.Hour,
		PermitAnyRemoteHost: true,
	})
	pnat.RegisterNATIP(natIP, "pool-a")

	dp := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{
			forward: {
				ReverseKey: reverse,
				Flags:      SessFlagSNAT,
				NATSrcIP:   natIPU32,
				NATSrcPort: 40000,
			},
			reverse: {IsReverse: 1},
		},
		pnat: pnat,
	}
	store := NewDataPlaneSessionStore(dp)

	if err := store.DeleteWithCompanionsV4(forward, DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteWithCompanionsV4: %v", err)
	}
	binding := pnat.Lookup(netip.AddrFrom4(forward.SrcIP), forward.SrcPort, "pool-a")
	if binding == nil {
		t.Fatal("persistent NAT binding was not preserved")
	}
	if binding.NatIP != natIP || binding.NatPort != 40000 {
		t.Fatalf("binding NAT tuple = %v:%d, want %v:%d",
			binding.NatIP, binding.NatPort, natIP, 40000)
	}
	if !binding.PermitAnyRemoteHost || binding.Timeout != time.Hour {
		t.Fatalf("binding pool metadata = permit=%v timeout=%v",
			binding.PermitAnyRemoteHost, binding.Timeout)
	}
}

func TestDataPlaneSessionStoreReportsNoRuntimeDeltaSource(t *testing.T) {
	store := NewDataPlaneSessionStore(&sessionStoreTestDP{})
	if got := store.SessionDeltas(); got != nil {
		t.Fatalf("SessionDeltas() = %T, want nil for generic dataplane store", got)
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
