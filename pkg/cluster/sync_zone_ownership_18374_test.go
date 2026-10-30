package cluster

import (
	"testing"
)

// #18374: a content-equal ownership re-install inside a bulk receive window
// must not void the bulk's reconcile, and every genuine change still must.
//
// The fixture is the #9655 receiver: zone 1 -> RG 1 (this node), zone 5 ->
// RG 5 (the peer), and an established session in zone 5 that the empty
// authoritative bulk does not carry. A reconcile that RUNS deletes it and
// marks the bulk complete; a reconcile voided by a generation change keeps it
// and withholds completion (#11070). The cells drive the real BulkStart /
// BulkEnd handlers, so the assertion is on the reconcile, not on the counter.

var digestA18374 = ResolverDigest{0xa1, 0x83, 0x74}
var digestB18374 = ResolverDigest{0xb1, 0x83, 0x74}

func ownership18374(zone5RG int, foldRG map[uint32]int, digest ResolverDigest) ZoneOwnership {
	return ZoneOwnership{
		ZoneRG: ZoneRGMap{1: {1}, 5: {zone5RG}},
		FoldRG: foldRG,
		// A fresh func value on every call, exactly as the daemon builds a
		// fresh closure on every apply and link refresh: funcs cannot be
		// compared, so only the digest can say the resolver is unchanged.
		IngressFold:    func(ifindex uint32, vlan uint16) uint32 { return ifindex + uint32(vlan) },
		NatScopeFold:   func(ifindex int32) uint32 { return uint32(ifindex) },
		ResolverDigest: digest,
	}
}

// bulkAcross18374 installs `before`, opens a bulk, runs `during` inside the
// receive window, closes it, and reports whether the reconcile ran.
func bulkAcross18374(t *testing.T, before ZoneOwnership, during func(*SessionSync)) (reconciled bool) {
	t.Helper()
	rx, dp := receiver9655(t, false, nil)
	rx.InstallZoneOwnership(before)
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	during(rx)
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	_, kept := dp.v4sessions[stalePeerRG9655]
	if kept == rx.BulkEverCompleted() {
		t.Fatalf("fixture: the stale zone-5 row (kept=%v) and bulk completion (%v) disagree about whether the reconcile ran",
			kept, rx.BulkEverCompleted())
	}
	return !kept
}

// The #18374 regression: the daemon re-installs identical ownership on every
// apply and every interface-link refresh (the 06:17:06.477 em0 refresh in the
// issue's journal). Before the fix every install advanced the generation and
// the cold-prime bulk was discarded.
func TestContentEqualOwnershipReinstallKeepsTheBulkReconcile18374(t *testing.T) {
	folds := map[uint32]int{0xf01d: 1}
	reconciled := bulkAcross18374(t, ownership18374(5, folds, digestA18374), func(rx *SessionSync) {
		// Twice, with fresh maps and closures: an apply and a link refresh.
		rx.InstallZoneOwnership(ownership18374(5, map[uint32]int{0xf01d: 1}, digestA18374))
		rx.InstallZoneOwnership(ownership18374(5, map[uint32]int{0xf01d: 1}, digestA18374))
	})
	if !reconciled {
		t.Fatal("#18374: a content-equal ownership re-install during the bulk voided its reconcile; " +
			"the BulkAck is withheld and the whole bulk is discarded")
	}
}

// #9655 must survive: every change the reconcile can observe still voids it.
func TestOwnershipChangeDuringBulkStillVoidsTheReconcile18374(t *testing.T) {
	folds := map[uint32]int{0xf01d: 1}
	base := ownership18374(5, folds, digestA18374)
	for _, tc := range []struct {
		name   string
		before *ZoneOwnership // nil = base
		during ZoneOwnership
	}{
		{"zone 5 moved to this node's RG 1", nil, ownership18374(1, folds, digestA18374)},
		{"fold->RG map changed", nil, ownership18374(5, map[uint32]int{0xf01d: 5}, digestA18374)},
		{"fold->RG entry added", nil, ownership18374(5, map[uint32]int{0xf01d: 1, 0xbeef: 5}, digestA18374)},
		{"resolver digest changed (recreated netdev or new config)", nil, ownership18374(5, folds, digestB18374)},
		{"resolver digest unknown", nil, ownership18374(5, folds, ResolverDigest{})},
		// Unknown on BOTH sides: equal bytes must still not prove equality.
		{"resolver digest unknown before and during", func() *ZoneOwnership {
			o := ownership18374(5, folds, ResolverDigest{})
			return &o
		}(), ownership18374(5, folds, ResolverDigest{})},
		{"resolver unwired", nil, func() ZoneOwnership {
			o := ownership18374(5, folds, digestA18374)
			o.IngressFold = nil
			return o
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, during := base, tc.during
			if tc.before != nil {
				before = *tc.before
			}
			if bulkAcross18374(t, before, func(rx *SessionSync) { rx.InstallZoneOwnership(during) }) {
				t.Fatalf("#9655: %s during the bulk, and the reconcile still judged by the bulk-start "+
					"snapshot (the stale zone-5 row was deleted and the bulk marked complete)", tc.name)
			}
		})
	}
}

// An unknown digest is never equal to anything, including another unknown:
// a caller that cannot fingerprint its resolver keeps the pre-#18374
// always-advance behaviour.
func TestUnknownResolverDigestAlwaysAdvances18374(t *testing.T) {
	rx, _ := receiver9655(t, false, nil)
	unknown := ownership18374(5, nil, ResolverDigest{})
	rx.InstallZoneOwnership(unknown)
	g := rx.ZoneOwnershipGeneration()
	if !rx.InstallZoneOwnership(unknown) || rx.ZoneOwnershipGeneration() != g+1 {
		t.Fatalf("an unknown-digest re-install must advance the generation: %d -> %d", g, rx.ZoneOwnershipGeneration())
	}
}

// The legacy setters install a resolver with no digest, so the next digest
// install must advance even when its digest matches the one before the
// legacy call: equality is only provable against a digest-carrying install.
func TestLegacySetterInvalidatesTheResolverDigest18374(t *testing.T) {
	for _, legacy := range []struct {
		name string
		set  func(*SessionSync)
	}{
		{"SetZoneOwnership", func(rx *SessionSync) {
			rx.SetZoneOwnership(ZoneRGMap{1: {1}, 5: {5}}, nil, func(uint32, uint16) uint32 { return 0 })
		}},
		{"SetIngressFoldFn", func(rx *SessionSync) {
			rx.SetIngressFoldFn(func(uint32, uint16) uint32 { return 0 })
		}},
	} {
		t.Run(legacy.name, func(t *testing.T) {
			rx, _ := receiver9655(t, false, nil)
			rx.InstallZoneOwnership(ownership18374(5, nil, digestA18374))
			legacy.set(rx)
			g := rx.ZoneOwnershipGeneration()
			if !rx.InstallZoneOwnership(ownership18374(5, nil, digestA18374)) || rx.ZoneOwnershipGeneration() == g {
				t.Fatalf("%s replaced the resolver without a digest, and the next install was judged "+
					"unchanged against the digest from before it", legacy.name)
			}
		})
	}
}

// SetNatScopeFoldFn feeds only the SEND-side stamp; no reconcile snapshot
// captures it, so installing one inside a receive window must not void the
// reconcile (it was the second half of the +2 per apply in the issue).
func TestNatScopeFolderInstallDoesNotVoidTheReconcile18374(t *testing.T) {
	reconciled := bulkAcross18374(t, ownership18374(5, nil, digestA18374), func(rx *SessionSync) {
		rx.SetNatScopeFoldFn(func(ifindex int32) uint32 { return uint32(ifindex) + 1 })
	})
	if !reconciled {
		t.Fatal("#18374: installing the send-side NAT-scope folder voided a received bulk's reconcile, " +
			"which never reads it")
	}
}
