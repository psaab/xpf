package dataplane

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

// #14965 — batch-retry and peer-partial-batch regressions.
//
// The non-peer batch leg (batchDeleteExactV4/V6) stops at the first missing
// key and retries the tail per key. Pre-fix that retry called the bare
// DeleteSession/DeleteSessionV6, dropping RoutingDomain and
// PurgeTunnelVariants: the helper then exact-matched (or probed) instead of
// wildcard-deleting the GRE0 row, leaking it. The peer leg
// (deletePeerBatchKnownExactV4/V6) dropped PurgeTunnelVariants on forward
// AND reverse keys, and on a partial-batch error returned early, orphaning
// reverse companions and dynamic dnat_table entries of helper-applied
// forwards.

// scopedRetryDP is a scoped dataplane whose batch leg stops at a missing key
// (cilium/ebpf semantics) so the store's per-key retry runs. It records every
// scoped singular delete; its bare DeleteSession records a bare retry (the
// pre-fix path) so a test can prove the retry never goes bare.
type scopedRetryDP struct {
	DataPlane
	missingV4     ScopedSessionKey
	missingV6     ScopedSessionKeyV6
	scopedRetryV4 []ScopedSessionKey
	scopedRetryV6 []ScopedSessionKeyV6
	bareRetryV4   []SessionKey
	bareRetryV6   []SessionKeyV6
	retryErrV4    error
	retryErrV6    error
}

func (d *scopedRetryDP) BatchDeleteSessionsScoped(s []ScopedSessionKey) (int, error) {
	for i, sk := range s {
		if sk == d.missingV4 {
			return i, ebpf.ErrKeyNotExist
		}
	}
	return len(s), nil
}

func (d *scopedRetryDP) BatchDeleteSessionsScopedV6(s []ScopedSessionKeyV6) (int, error) {
	for i, sk := range s {
		if sk == d.missingV6 {
			return i, ebpf.ErrKeyNotExist
		}
	}
	return len(s), nil
}

func (d *scopedRetryDP) DeleteSessionScoped(sk ScopedSessionKey) error {
	d.scopedRetryV4 = append(d.scopedRetryV4, sk)
	if sk == d.missingV4 {
		return ebpf.ErrKeyNotExist
	}
	return d.retryErrV4
}

func (d *scopedRetryDP) DeleteSessionScopedV6(sk ScopedSessionKeyV6) error {
	d.scopedRetryV6 = append(d.scopedRetryV6, sk)
	if sk == d.missingV6 {
		return ebpf.ErrKeyNotExist
	}
	return d.retryErrV6
}

func (d *scopedRetryDP) DeleteSession(k SessionKey) error {
	d.bareRetryV4 = append(d.bareRetryV4, k)
	return nil
}

func (d *scopedRetryDP) DeleteSessionV6(k SessionKeyV6) error {
	d.bareRetryV6 = append(d.bareRetryV6, k)
	return nil
}

func (d *scopedRetryDP) DeleteDNATEntry(DNATKey) error     { return nil }
func (d *scopedRetryDP) DeleteDNATEntryV6(DNATKeyV6) error { return nil }

func (d *scopedRetryDP) GetPersistentNAT() *PersistentNATTable { return nil }

func TestBatchRetryCarriesScopedKeyV4_14965(t *testing.T) {
	const tenant = uint32(100007)
	fwd0 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 9}, SrcPort: 1111, DstPort: 443}
	missing := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 9}, SrcPort: 2222, DstPort: 443}
	fwd2 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 9}, SrcPort: 3333, DstPort: 443}
	rev0 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 5}, SrcPort: 443, DstPort: 1111}
	revM := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 5}, SrcPort: 443, DstPort: 2222}
	rev2 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 5}, SrcPort: 443, DstPort: 3333}

	scopedMissing := ScopedSessionKey{Key: missing, RoutingDomain: tenant, PurgeTunnelVariants: true}
	dp := &scopedRetryDP{missingV4: scopedMissing}
	store := dataPlaneSessionStore{dp: dp}

	entries := []SessionEntryV4{
		{Key: fwd0, Value: SessionValue{RoutingDomain: tenant, ReverseKey: rev0}, PurgeTunnelVariants: true},
		{Key: missing, Value: SessionValue{RoutingDomain: tenant, ReverseKey: revM}, PurgeTunnelVariants: true},
		{Key: fwd2, Value: SessionValue{RoutingDomain: tenant, ReverseKey: rev2}, PurgeTunnelVariants: true},
	}
	exact, err := store.DeleteBatchKnownExactV4(entries, DeleteReasonPolicyDeleted, false)
	if err != nil {
		t.Fatalf("DeleteBatchKnownExactV4: %v", err)
	}
	if len(exact) != 2 || exact[0] != fwd0 || exact[1] != fwd2 {
		t.Fatalf("exact = %+v, want [%+v %+v] (missing excluded, tail kept)", exact, fwd0, fwd2)
	}
	// The double's missing marker is the FORWARD scoped key, so only the
	// forward batch stops; its retry must carry missing + fwd2 scoped.
	if len(dp.bareRetryV4) != 0 {
		t.Fatalf("per-key retry went BARE for %+v; the scoped key (domain+purge) was dropped (#14965)", dp.bareRetryV4)
	}
	if len(dp.scopedRetryV4) != 2 {
		t.Fatalf("scoped retries = %+v, want 2 (missing-fwd, fwd2)", dp.scopedRetryV4)
	}
	for _, sk := range dp.scopedRetryV4 {
		if sk.RoutingDomain != tenant {
			t.Errorf("retry key %+v carried domain %d, want %d", sk.Key, sk.RoutingDomain, tenant)
		}
		if !sk.PurgeTunnelVariants {
			t.Errorf("retry key %+v lost PurgeTunnelVariants; helper exact-matches and the GRE0 row leaks", sk.Key)
		}
		if sk.Key.Protocol != 47 {
			t.Errorf("retry key %+v protocol = %d, want 47 (GRE premise)", sk.Key, sk.Key.Protocol)
		}
	}
}

func TestBatchRetryCarriesScopedKeyV6_14965(t *testing.T) {
	const tenant = uint32(100008)
	mk := func(last byte, port uint16) SessionKeyV6 {
		return SessionKeyV6{Protocol: 47, SrcIP: [16]byte{0x20, last}, DstIP: [16]byte{0x30, last}, SrcPort: port, DstPort: 443}
	}
	fwd0, missing, fwd2 := mk(1, 1111), mk(2, 2222), mk(3, 3333)
	rev0, revM, rev2 := mk(1, 443), mk(2, 443), mk(3, 443)
	// Reverse companions share the helper's view: distinct keys.
	rev0.DstPort, revM.DstPort, rev2.DstPort = 1111, 2222, 3333
	rev0.SrcPort, revM.SrcPort, rev2.SrcPort = 443, 443, 443

	dp := &scopedRetryDP{missingV6: ScopedSessionKeyV6{Key: missing, RoutingDomain: tenant, PurgeTunnelVariants: true}}
	store := dataPlaneSessionStore{dp: dp}
	entries := []SessionEntryV6{
		{Key: fwd0, Value: SessionValueV6{RoutingDomain: tenant, ReverseKey: rev0}, PurgeTunnelVariants: true},
		{Key: missing, Value: SessionValueV6{RoutingDomain: tenant, ReverseKey: revM}, PurgeTunnelVariants: true},
		{Key: fwd2, Value: SessionValueV6{RoutingDomain: tenant, ReverseKey: rev2}, PurgeTunnelVariants: true},
	}
	exact, err := store.DeleteBatchKnownExactV6(entries, DeleteReasonPolicyDeleted, false)
	if err != nil {
		t.Fatalf("DeleteBatchKnownExactV6: %v", err)
	}
	if len(exact) != 2 {
		t.Fatalf("exact = %+v, want 2 forwards", exact)
	}
	if len(dp.bareRetryV6) != 0 {
		t.Fatalf("V6 per-key retry went BARE for %+v (#14965)", dp.bareRetryV6)
	}
	if len(dp.scopedRetryV6) == 0 {
		t.Fatal("V6 per-key retry never used the scoped singular path")
	}
	for _, sk := range dp.scopedRetryV6 {
		if sk.RoutingDomain != tenant || !sk.PurgeTunnelVariants {
			t.Errorf("V6 retry key %+v = {domain:%d purge:%v}, want {%d true}", sk.Key, sk.RoutingDomain, sk.PurgeTunnelVariants, tenant)
		}
	}
}

// Control: a dataplane WITHOUT the scoped singular capability still retries
// bare and deletes the tail (the fallback is load-bearing for non-userspace
// dataplanes).
func TestBatchRetryWithoutScopedCapabilityFallsBackBare14965(t *testing.T) {
	keys := make([]SessionKey, 3)
	for i := range keys {
		keys[i] = SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, byte(i)}, DstIP: [4]byte{10, 0, 1, byte(i)}, SrcPort: uint16(1000 + i), DstPort: 80}
	}
	dp := &batchDeleteTailDP{missingV4: keys[1], presentV4: map[SessionKey]bool{}}
	for i, k := range keys {
		dp.presentV4[k] = i != 1
	}
	store := dataPlaneSessionStore{dp: dp}
	deleted, err := store.batchDeleteV4(scopedV4(keys))
	if err != nil {
		t.Fatalf("batchDeleteV4: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2 (bare fallback must still retire the tail)", deleted)
	}
}

// --- Peer partial-batch limbs ---

// partialPeerDP applies only the first forward, then fails the batch. It
// records every peer call so the test can prove applied companions/DNAT were
// still retired and refused forwards were left alone.
type partialPeerDP struct {
	DataPlane
	err     error
	calls   [][]ScopedSessionKey
	callsV6 [][]ScopedSessionKeyV6
	dnat    []DNATKey
	dnat6   []DNATKeyV6
}

func (d *partialPeerDP) BatchDeletePeerSyncedSessionsExactScoped(s []ScopedSessionKey, _ bool) ([]ScopedSessionKey, []ScopedSessionKey, error) {
	cp := append([]ScopedSessionKey(nil), s...)
	d.calls = append(d.calls, cp)
	if d.err != nil {
		// First call (forwards): apply only the first key, then fail.
		// Later calls (companions) succeed fully.
		if len(d.calls) == 1 && len(s) > 0 {
			return []ScopedSessionKey{s[0]}, []ScopedSessionKey{s[0]}, d.err
		}
		return append([]ScopedSessionKey(nil), s...), append([]ScopedSessionKey(nil), s...), nil
	}
	return append([]ScopedSessionKey(nil), s...), append([]ScopedSessionKey(nil), s...), nil
}

func (d *partialPeerDP) BatchDeletePeerSyncedSessionsExactScopedV6(s []ScopedSessionKeyV6, _ bool) ([]ScopedSessionKeyV6, []ScopedSessionKeyV6, error) {
	cp := append([]ScopedSessionKeyV6(nil), s...)
	d.callsV6 = append(d.callsV6, cp)
	if d.err != nil && len(d.callsV6) == 1 && len(s) > 0 {
		return []ScopedSessionKeyV6{s[0]}, []ScopedSessionKeyV6{s[0]}, d.err
	}
	return append([]ScopedSessionKeyV6(nil), s...), append([]ScopedSessionKeyV6(nil), s...), nil
}

func (d *partialPeerDP) DeleteDNATEntry(k DNATKey) error {
	d.dnat = append(d.dnat, k)
	return nil
}

func (d *partialPeerDP) DeleteDNATEntryV6(k DNATKeyV6) error {
	d.dnat6 = append(d.dnat6, k)
	return nil
}

func (d *partialPeerDP) GetPersistentNAT() *PersistentNATTable { return nil }

// Remaining peerSyncedSessionDeleter surface (unused on these paths).
func (d *partialPeerDP) BatchDeletePeerSyncedSessionsScoped(s []ScopedSessionKey, _ bool) (int, []ScopedSessionKey, error) {
	return len(s), nil, nil
}
func (d *partialPeerDP) BatchDeletePeerSyncedSessionsScopedV6(s []ScopedSessionKeyV6, _ bool) (int, []ScopedSessionKeyV6, error) {
	return len(s), nil, nil
}
func (d *partialPeerDP) DeletePeerSyncedSession(SessionKey, bool) (bool, error) { return false, nil }
func (d *partialPeerDP) DeletePeerSyncedSessionV6(SessionKeyV6, bool) (bool, error) {
	return false, nil
}
func (d *partialPeerDP) DeletePeerSyncedSessionScoped(SessionKey, uint32, uint64) (bool, error) {
	return false, nil
}
func (d *partialPeerDP) DeletePeerSyncedSessionScopedV6(SessionKeyV6, uint32, uint64) (bool, error) {
	return false, nil
}

func TestPeerPartialBatchRetiresAppliedCompanionsAndDNAT14965(t *testing.T) {
	boom := errors.New("helper batch failed midway")
	dp := &partialPeerDP{err: boom}
	store := dataPlaneSessionStore{dp: dp}

	fwd0 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1111, DstPort: 443}
	fwd1 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 2222, DstPort: 443}
	rev0 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 443, DstPort: 1111}
	rev1 := SessionKey{Protocol: 47, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 443, DstPort: 2222}

	entries := []SessionEntryV4{
		{Key: fwd0, Value: SessionValue{RoutingDomain: 100007, ReverseKey: rev0, Flags: SessFlagSNAT, NATSrcIP: 0x0a000063, NATSrcPort: 0x1234}, PurgeTunnelVariants: true},
		{Key: fwd1, Value: SessionValue{RoutingDomain: 100007, ReverseKey: rev1, Flags: SessFlagSNAT, NATSrcIP: 0x0a000064, NATSrcPort: 0x1235}, PurgeTunnelVariants: true},
	}
	exact, err := store.deletePeerBatchKnownExactV4(dp, entries, false)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the peer batch error preserved", err)
	}
	if len(exact) != 1 || exact[0] != fwd0 {
		t.Fatalf("exact = %+v, want only the applied forward", exact)
	}
	// Forward call must carry PurgeTunnelVariants on both keys.
	if len(dp.calls) == 0 {
		t.Fatal("no peer calls recorded")
	}
	for _, sk := range dp.calls[0] {
		if !sk.PurgeTunnelVariants {
			t.Errorf("peer forward key %+v lost PurgeTunnelVariants (#14965)", sk.Key)
		}
		if sk.RoutingDomain != 100007 {
			t.Errorf("peer forward key %+v domain = %d, want 100007", sk.Key, sk.RoutingDomain)
		}
	}
	// The applied forward's companion must be retired despite the error;
	// the unapplied forward's companion must NOT.
	foundRev0, foundRev1 := false, false
	for _, call := range dp.calls[1:] {
		for _, sk := range call {
			if sk.Key == rev0 {
				foundRev0 = true
				if !sk.PurgeTunnelVariants {
					t.Errorf("peer reverse key %+v lost PurgeTunnelVariants", sk.Key)
				}
			}
			if sk.Key == rev1 {
				foundRev1 = true
			}
		}
	}
	if !foundRev0 {
		t.Error("applied forward's reverse companion was orphaned by the partial-batch early return (#14965)")
	}
	if foundRev1 {
		t.Error("unapplied forward's reverse companion was deleted; only helper-applied forwards license companion retirement")
	}
	// DNAT: only the applied SNAT forward's dynamic entry is deleted.
	if len(dp.dnat) != 1 {
		t.Fatalf("dnat deletes = %d (%+v), want exactly 1 (applied forward only)", len(dp.dnat), dp.dnat)
	}
}

func TestPeerPartialBatchRetiresAppliedCompanionsAndDNATV6_14965(t *testing.T) {
	boom := errors.New("helper v6 batch failed midway")
	dp := &partialPeerDP{err: boom}
	store := dataPlaneSessionStore{dp: dp}

	fwd0 := SessionKeyV6{Protocol: 47, SrcPort: 1111, DstPort: 443}
	fwd1 := SessionKeyV6{Protocol: 47, SrcPort: 2222, DstPort: 443}
	rev0 := SessionKeyV6{Protocol: 47, SrcPort: 443, DstPort: 1111}
	rev1 := SessionKeyV6{Protocol: 47, SrcPort: 443, DstPort: 2222}
	var natIP [16]byte
	natIP[15] = 99
	entries := []SessionEntryV6{
		{Key: fwd0, Value: SessionValueV6{RoutingDomain: 100008, ReverseKey: rev0, Flags: SessFlagSNAT, NATSrcIP: natIP, NATSrcPort: 0x1234}, PurgeTunnelVariants: true},
		{Key: fwd1, Value: SessionValueV6{RoutingDomain: 100008, ReverseKey: rev1, Flags: SessFlagSNAT, NATSrcIP: natIP, NATSrcPort: 0x1235}, PurgeTunnelVariants: true},
	}
	exact, err := store.deletePeerBatchKnownExactV6(dp, entries, false)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the peer batch error preserved", err)
	}
	if len(exact) != 1 || exact[0] != fwd0 {
		t.Fatalf("exact = %+v, want only the applied forward", exact)
	}
	if len(dp.callsV6) == 0 {
		t.Fatal("no V6 peer calls recorded")
	}
	for _, sk := range dp.callsV6[0] {
		if !sk.PurgeTunnelVariants {
			t.Errorf("V6 peer forward key %+v lost PurgeTunnelVariants (#14965)", sk.Key)
		}
	}
	foundRev0, foundRev1 := false, false
	for _, call := range dp.callsV6[1:] {
		for _, sk := range call {
			if sk.Key == rev0 {
				foundRev0 = true
			}
			if sk.Key == rev1 {
				foundRev1 = true
			}
		}
	}
	if !foundRev0 {
		t.Error("V6 applied forward's reverse companion was orphaned (#14965)")
	}
	if foundRev1 {
		t.Error("V6 unapplied forward's reverse companion was deleted")
	}
	if len(dp.dnat6) != 1 {
		t.Fatalf("V6 dnat deletes = %d, want exactly 1 (applied forward only)", len(dp.dnat6))
	}
}

// Control: a fully successful peer batch behaves exactly as before (both
// companions + both DNAT rows, no error).
func TestPeerFullBatchUnchanged14965(t *testing.T) {
	dp := &partialPeerDP{}
	store := dataPlaneSessionStore{dp: dp}
	fwd0 := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1111, DstPort: 443}
	rev0 := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{10, 0, 0, 1}, SrcPort: 443, DstPort: 1111}
	entries := []SessionEntryV4{
		{Key: fwd0, Value: SessionValue{RoutingDomain: 100007, ReverseKey: rev0, Flags: SessFlagSNAT, NATSrcIP: 0x0a000063, NATSrcPort: 0x1234}},
	}
	exact, err := store.deletePeerBatchKnownExactV4(dp, entries, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(exact) != 1 || len(dp.dnat) != 1 {
		t.Fatalf("exact=%+v dnat=%d, want 1/1 on the healthy path", exact, len(dp.dnat))
	}
}
