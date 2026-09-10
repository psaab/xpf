package dataplane

import (
	"testing"
)

// #9364 — BIND THE WIRING. These cells are about the CALLER, not the derivation.
//
// `pkg/dataplane/userspace/batch_delete_domain_9364_test.go` proves the helper
// request carries the domain it is GIVEN. That says nothing about whether
// `DeleteBatchKnownV4` — the entry point the conntrack GC actually calls — passes
// one. A package's own cells proving a function correct while saying nothing
// about what its caller hands it is the surviving-mutant shape this repo keeps
// hitting, and it is exactly how #9482 happened one interface over.
//
// So these drive `DeleteBatchKnownV4/V6` and record what reaches the dataplane.

// domainRecorderDP records the scoped keys the store hands down. It implements
// the OPTIONAL capability, so it takes the scoped path — unlike
// `batchDeleteTailDP` in the #5448 cells, which does not and therefore now also
// serves as the "a dataplane WITHOUT the capability still works" control.
type domainRecorderDP struct {
	DataPlane
	scopedV4 []ScopedSessionKey
	scopedV6 []ScopedSessionKeyV6
	bareV4   [][]SessionKey
}

func (d *domainRecorderDP) BatchDeleteSessionsScoped(s []ScopedSessionKey) (int, error) {
	d.scopedV4 = append(d.scopedV4, s...)
	return len(s), nil
}

func (d *domainRecorderDP) BatchDeleteSessionsScopedV6(s []ScopedSessionKeyV6) (int, error) {
	d.scopedV6 = append(d.scopedV6, s...)
	return len(s), nil
}

// Recorded so a cell can assert the scoped path was taken INSTEAD of this one.
func (d *domainRecorderDP) BatchDeleteSessions(keys []SessionKey) (int, error) {
	d.bareV4 = append(d.bareV4, keys)
	return len(keys), nil
}

func (d *domainRecorderDP) DeleteDNATEntry(DNATKey) error { return nil }

func key9364(port uint16) SessionKey {
	return SessionKey{
		SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 9},
		SrcPort: port, DstPort: 443, Protocol: 6,
	}
}

// THE ACCEPTANCE CRITERION: a batch delete of tenant sessions carries the domain
// down to the dataplane — forward keys AND their reverse companions.
func TestDeleteBatchKnownCarriesTheRoutingDomain9364(t *testing.T) {
	const tenant = uint32(100007)
	dp := &domainRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}

	fwd := key9364(1234)
	rev := key9364(4321)
	entries := []SessionEntryV4{{
		Key: fwd,
		Value: SessionValue{
			RoutingDomain: tenant,
			ReverseKey:    rev,
		},
	}}

	if _, err := store.DeleteBatchKnownV4(entries, DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}

	if len(dp.bareV4) != 0 {
		t.Fatalf("#9364: the store took the BARE BatchDeleteSessions path (%d chunks) even "+
			"though the dataplane implements the scoped capability — the domain is dropped "+
			"before it can reach the wire", len(dp.bareV4))
	}
	if len(dp.scopedV4) != 2 {
		t.Fatalf("recorded %d scoped keys, want 2 (forward + reverse companion); got %+v",
			len(dp.scopedV4), dp.scopedV4)
	}
	seen := map[SessionKey]uint32{}
	for _, sk := range dp.scopedV4 {
		seen[sk.Key] = sk.RoutingDomain
	}
	for name, k := range map[string]SessionKey{"forward": fwd, "reverse": rev} {
		got, ok := seen[k]
		if !ok {
			t.Errorf("#9364: the %s key never reached the dataplane", name)
			continue
		}
		if got != tenant {
			t.Errorf("#9364: the %s key reached the dataplane with routing_domain=%d, want %d. "+
				"The conntrack GC retires sessions through this entry point continuously, so a "+
				"dropped domain here is the steady-state case, not an edge one", name, got, tenant)
		}
	}
}

// LOAD-BEARING CONTROL — the delete that must still SUCCEED. A default-instance
// batch must reach the dataplane with domain 0, not with an invented one.
func TestDeleteBatchKnownDefaultInstanceStaysDomainZero9364(t *testing.T) {
	dp := &domainRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}

	entries := []SessionEntryV4{{Key: key9364(1234), Value: SessionValue{}}}
	if _, err := store.DeleteBatchKnownV4(entries, DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.scopedV4) != 1 {
		t.Fatalf("recorded %d scoped keys, want 1", len(dp.scopedV4))
	}
	if got := dp.scopedV4[0].RoutingDomain; got != 0 {
		t.Errorf("#9364: a default-instance batch delete reached the dataplane with "+
			"routing_domain=%d, want 0 — every non-VRF deployment would have its deletes "+
			"addressed to an instance that does not hold the row", got)
	}
}

// The V6 twin, for the same reason its wire sibling exists: V6 has its own
// derivation and could drift.
func TestDeleteBatchKnownCarriesTheRoutingDomainV6_9364(t *testing.T) {
	const tenant = uint32(100008)
	dp := &domainRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}

	fwd := SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 443}
	rev := SessionKeyV6{Protocol: 6, SrcPort: 4321, DstPort: 443}
	entries := []SessionEntryV6{{
		Key:   fwd,
		Value: SessionValueV6{RoutingDomain: tenant, ReverseKey: rev},
	}}

	if _, err := store.DeleteBatchKnownV6(entries, DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteBatchKnownV6: %v", err)
	}
	if len(dp.scopedV6) != 2 {
		t.Fatalf("recorded %d scoped V6 keys, want 2 (forward + reverse); got %+v",
			len(dp.scopedV6), dp.scopedV6)
	}
	for _, sk := range dp.scopedV6 {
		if sk.RoutingDomain != tenant {
			t.Errorf("#9364 V6: key %+v reached the dataplane with routing_domain=%d, want %d",
				sk.Key, sk.RoutingDomain, tenant)
		}
	}
}

// CONTROL — a dataplane WITHOUT the capability must still work, bare.
//
// The optional-capability shape means a non-implementing dataplane falls back to
// the key-only call. That fallback is load-bearing for every non-userspace
// dataplane and for `ClearAllSessions`; without this cell "prefer the scoped
// call" could be implemented as "require it", and a dataplane that does not have
// it would delete nothing at all.
type noCapabilityDP9364 struct {
	DataPlane
	bare [][]SessionKey
}

func (d *noCapabilityDP9364) BatchDeleteSessions(keys []SessionKey) (int, error) {
	d.bare = append(d.bare, keys)
	return len(keys), nil
}
func (d *noCapabilityDP9364) DeleteDNATEntry(DNATKey) error { return nil }

func TestDataplaneWithoutTheCapabilityStillDeletesBare9364(t *testing.T) {
	dp := &noCapabilityDP9364{}
	store := dataPlaneSessionStore{dp: dp}

	entries := []SessionEntryV4{{Key: key9364(1234), Value: SessionValue{RoutingDomain: 100007}}}
	deleted, err := store.DeleteBatchKnownV4(entries, DeleteReasonGCExpired)
	if err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 — a dataplane that cannot carry a domain must still "+
			"have its sessions deleted", deleted)
	}
	if len(dp.bare) == 0 {
		t.Fatal("#9364: a dataplane without the scoped capability received NO bare batch " +
			"delete — the optional capability became a requirement, and every non-userspace " +
			"dataplane now deletes nothing")
	}
}
