package daemon

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)
// P1 HA-observed routing: identity-carrying closes from a stated domain
// queue scoped deletes when the peer decodes them. The ss is
// disconnected, so queueing journals — the journal peeks observe the
// exact wire the peer would receive.

func closeDelta10512(t *testing.T, id uint64, domain uint32) dpuserspace.SessionDeltaInfo {
	t.Helper()
	delta := installTableDelta9752(t, "close")
	delta.RTFlowSessionID = id
	delta.RoutingDomain = domain
	return delta
}

func TestCloseRoutesScopedWhenCapable10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := closeDelta10512(t, 0xA11CE, 100007)
	key, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: close delta must convert")
	}
	n := d.walkUserspaceSessionDeltas(ss, zoneIDs,
		[]dpuserspace.SessionDeltaInfo{delta}, queueDeltaSink{ss})
	if n != 1 {
		t.Fatalf("walk synced %d deletes, want 1", n)
	}
	domain, id, ok := ss.ScopedDeleteJournalEntryForTesting(key)
	if !ok || domain != 100007 || id != 0xA11CE {
		t.Fatalf("scoped journal = (%d, %#x, %v), want (100007, 0xA11CE, true)", domain, id, ok)
	}
	if _, ok := ss.DeleteJournalGenerationV4ForTesting(key); ok {
		t.Fatal("capable close must not also journal a bare delete (survivor kill)")
	}
}

func TestCloseFallsBackBareWhenIncapable10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	ss.SetScopedPolicyDeleteCapableForTesting(false)
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := closeDelta10512(t, 0xA11CE, 100007)
	key, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: close delta must convert")
	}
	n := d.walkUserspaceSessionDeltas(ss, zoneIDs,
		[]dpuserspace.SessionDeltaInfo{delta}, queueDeltaSink{ss})
	if n != 1 {
		t.Fatalf("walk synced %d deletes, want 1", n)
	}
	if _, ok := ss.DeleteJournalGenerationV4ForTesting(key); !ok {
		t.Fatal("incapable peer must still get the bare close (current behavior)")
	}
	if _, _, ok := ss.ScopedDeleteJournalEntryForTesting(key); ok {
		t.Fatal("incapable peer must never receive a scoped frame (downgrade ban)")
	}
}

func TestCloseKeepsBareForPurgeMarker10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := closeDelta10512(t, 0xA11CE, 100007)
	delta.PurgeRetirement = true
	key, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: close delta must convert")
	}
	n := d.walkUserspaceSessionDeltas(ss, zoneIDs,
		[]dpuserspace.SessionDeltaInfo{delta}, queueDeltaSink{ss})
	if n != 1 {
		t.Fatalf("walk synced %d deletes, want 1", n)
	}
	// The marker has no scoped carrier: bare preserves #9752 semantics.
	if _, ok := ss.DeleteJournalGenerationV4ForTesting(key); !ok {
		t.Fatal("purge-marked close must stay bare (marker preserved)")
	}
	if _, _, ok := ss.ScopedDeleteJournalEntryForTesting(key); ok {
		t.Fatal("purge-marked close must not go scoped (marker would be lost)")
	}
}

func TestCloseRoutesScopedV6WhenCapable10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := transitOpenV6_9767()
	delta.Event = "close"
	delta.RTFlowSessionID = 0xC10512
	delta.RoutingDomain = 100007
	key, _, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: v6 close delta must convert")
	}
	n := d.walkUserspaceSessionDeltas(ss, zoneIDs,
		[]dpuserspace.SessionDeltaInfo{delta}, queueDeltaSink{ss})
	if n != 1 {
		t.Fatalf("walk synced %d deletes, want 1", n)
	}
	domain, id, ok := ss.ScopedDeleteJournalEntryV6ForTesting(key)
	if !ok || domain != 100007 || id != 0xC10512 {
		t.Fatalf("scoped v6 journal = (%d, %#x, %v), want (100007, 0xC10512, true)", domain, id, ok)
	}
	if _, ok := ss.DeleteJournalGenerationV6ForTesting(key); ok {
		t.Fatal("capable v6 close must not also journal a bare delete")
	}
}
