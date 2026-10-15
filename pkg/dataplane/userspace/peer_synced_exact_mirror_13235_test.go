package userspace

import (
	"errors"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #13235 (D5-04): exact peer batches must use helper-applied keys as the
// deleted set, propagate helper errors, and fail closed if no helper exists.
func TestExactPeerBatchHelperError13235(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	removeSessionSocket10513(t, rec)
	keys := scopedKeys9364(100007, 1234, 1235)
	deleted, applied, err := m.BatchDeletePeerSyncedSessionsExactScoped(keys, false)
	if err == nil {
		t.Fatalf("deleted=%v applied=%v err=nil, want helper error", deleted, applied)
	}
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("err=%v want errSessionHelperUnreachable", err)
	}
	if len(applied) != 0 || len(deleted) != 0 {
		t.Fatalf("applied=%v deleted=%v, want both empty on unreachable helper", applied, deleted)
	}
}

func TestExactPeerBatchHelperErrorV6_13235(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	removeSessionSocket10513(t, rec)
	keys := scopedKeys10513V6(100008, 1234)
	deleted, applied, err := m.BatchDeletePeerSyncedSessionsExactScopedV6(keys, false)
	if !errors.Is(err, errSessionHelperUnreachable) || len(applied) != 0 || len(deleted) != 0 {
		t.Fatalf("deleted=%v applied=%v err=%v", deleted, applied, err)
	}
}

func TestExactPeerBatchTreatsLocalOwnedRefusalAsKept13235(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	keys := scopedKeys9364(100007, 1234, 1235, 1236)
	deleted, applied, err := m.BatchDeletePeerSyncedSessionsExactScoped(keys, false)
	if err != nil {
		t.Fatalf("local-owned refusal is a benign keep, got err=%v", err)
	}
	want := keys[1:]
	if !slices.Equal(deleted, want) || !slices.Equal(applied, want) {
		t.Fatalf("deleted=%v applied=%v want=%v", deleted, applied, want)
	}

	m6, rec6 := newSyncOnlyManager9146(t)
	rec6.refuseFirst(peerDeleteRefusedLocalOwned)
	keys6 := scopedKeys10513V6(100008, 1234, 1235, 1236)
	deleted6, applied6, err := m6.BatchDeletePeerSyncedSessionsExactScopedV6(keys6, false)
	want6 := keys6[1:]
	if err != nil || !slices.Equal(deleted6, want6) || !slices.Equal(applied6, want6) {
		t.Fatalf("v6 deleted=%v applied=%v err=%v want=%v", deleted6, applied6, err, want6)
	}
}

func TestExactPeerBatchPreservesAppliedPrefix13235(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseNth(2, "helper-delete-refused:test")
	keys := scopedKeys9364(100007, 1234, 1235, 1236)
	deleted, applied, err := m.BatchDeletePeerSyncedSessionsExactScoped(keys, false)
	if err == nil {
		t.Fatal("want helper refusal error")
	}
	want := []dataplane.ScopedSessionKey{keys[0], keys[2]}
	if !slices.Equal(deleted, want) || !slices.Equal(applied, want) {
		t.Fatalf("deleted=%v applied=%v want=%v", deleted, applied, want)
	}
}

func TestExactPeerBatchHealthyCountsApplied13235(t *testing.T) {
	// Healthy helper, no BPF maps: helper deleted mirror, so shim returns
	// non-ErrKeyNotExist (ErrDataplaneNotArmed). Exact deleted must equal applied.
	m, _ := newSyncOnlyManager9146(t)
	keys := scopedKeys9364(100007, 1234, 1235)
	deleted, applied, err := m.BatchDeletePeerSyncedSessionsExactScoped(keys, false)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(applied) != len(keys) || len(deleted) != len(keys) {
		t.Fatalf("deleted=%d applied=%d want %d each", len(deleted), len(applied), len(keys))
	}
	m6, _ := newSyncOnlyManager9146(t)
	keys6 := scopedKeys10513V6(100008, 1234, 1235)
	d6, a6, err := m6.BatchDeletePeerSyncedSessionsExactScopedV6(keys6, false)
	if err != nil || len(a6) != len(keys6) || len(d6) != len(keys6) {
		t.Fatalf("v6 deleted=%d applied=%d err=%v", len(d6), len(a6), err)
	}
}

func TestExactPeerBatchNilHelperFailsClosed13235(t *testing.T) {
	m := New() // proc == nil
	keys := scopedKeys9364(100007, 1234)
	deleted, applied, err := m.BatchDeletePeerSyncedSessionsExactScoped(keys, false)
	if !errors.Is(err, errSessionHelperUnreachable) || len(applied) != 0 || len(deleted) != 0 {
		t.Fatalf("deleted=%v applied=%v err=%v, want unreachable and empty", deleted, applied, err)
	}
	d6, a6, err := New().BatchDeletePeerSyncedSessionsExactScopedV6(scopedKeys10513V6(100008, 1234), false)
	if !errors.Is(err, errSessionHelperUnreachable) || len(a6) != 0 || len(d6) != 0 {
		t.Fatalf("v6 deleted=%v applied=%v err=%v", d6, a6, err)
	}
}
