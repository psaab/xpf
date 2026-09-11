package cluster

import (
	"reflect"
	"sort"
	"testing"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9634: resetRecvGen, the path a peer bulk re-prime runs, reset three of the
// four full-set receive guards. persistentNatLeaseRecvSeq (#8121) had exactly
// two references in the tree: its declaration and its admit. A full-set guard
// admits only a strictly newer (incarnation, seq). A peer that OS-rebooted
// draws a LOWER incarnation (its monotonic clock restarted), so every lease set
// from it was dropped as stale until its epoch passed the dead process's, which
// on a long-running cluster is days.

// fullSetGuardFields9634 enumerates every fullSetSeqGuard field on ss by
// reflection, keyed by field name. The set is ENUMERATED, not listed: a guard
// added later is found here whether or not anyone remembered to reset it.
func fullSetGuardFields9634(ss *SessionSync) map[string]*fullSetSeqGuard {
	out := map[string]*fullSetSeqGuard{}
	v := reflect.ValueOf(ss).Elem()
	want := reflect.TypeOf(fullSetSeqGuard{})
	for i := 0; i < v.NumField(); i++ {
		if f := v.Type().Field(i); f.Type == want {
			out[f.Name] = (*fullSetSeqGuard)(unsafe.Pointer(v.Field(i).UnsafeAddr()))
		}
	}
	return out
}

func sortedNames9634(m map[string]*fullSetSeqGuard) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func TestEveryFullSetGuardIsResetOnRePrime_9634(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	guards := fullSetGuardFields9634(ss)
	names := sortedNames9634(guards)
	if _, ok := guards["persistentNatLeaseRecvSeq"]; !ok || len(guards) < 4 {
		t.Fatalf("attribution: the enumeration found %v; it must see at least the four declared guards, persistentNatLeaseRecvSeq among them", names)
	}

	// Prime every guard at a long-running peer's incarnation.
	ss.recvSeqMu.Lock()
	for _, n := range names {
		if !guards[n].admit(10000, 5) {
			t.Fatalf("setup: %s refused its first set", n)
		}
		if guards[n].admit(100, 1) {
			t.Fatalf("setup: %s admitted a lower incarnation before any re-prime", n)
		}
	}
	ss.recvSeqMu.Unlock()

	ss.resetRecvGen()

	ss.recvSeqMu.Lock()
	defer ss.recvSeqMu.Unlock()
	for _, n := range names {
		if !guards[n].admit(100, 1) {
			t.Errorf("#9634: after a peer re-prime (resetRecvGen), %s still refuses the rebooted peer's "+
				"lower-incarnation set; its stream stays frozen until the peer's epoch passes the old one", n)
		}
	}
}

// The reset must not loosen ordering WITHIN an incarnation: an out-of-order set
// on the redundant fabric is still refused, for every guard.
func TestFullSetGuardsStillRefuseAReorderWithinAnIncarnation_9634(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.resetRecvGen()
	guards := fullSetGuardFields9634(ss)
	ss.recvSeqMu.Lock()
	defer ss.recvSeqMu.Unlock()
	for _, n := range sortedNames9634(guards) {
		g := guards[n]
		first, reorder, next := g.admit(100, 2), g.admit(100, 1), g.admit(100, 3)
		if !first || reorder || !next {
			t.Errorf("%s: within one incarnation want seq 2 admitted, 1 refused, 3 admitted; got %v %v %v", n, first, reorder, next)
		}
	}
}

// End to end through the persistent-NAT lease handler: the drop the issue
// measured, and its end after the re-prime.
func TestPersistentNatLeaseSetFromARebootedPeerIsAdmittedAfterRePrime_9634(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var sets int
	ss.OnPersistentNatLeasesReceived = func([]userspace.IdleLeaseWire) { sets++ }
	frame := func(incarnation, seq uint64) []byte {
		return appendFullSetSeq(encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{sampleIdleLease()}), incarnation, seq)
	}

	ss.handleMessage(nil, syncMsgPersistentNatLease, frame(10000, 5))
	if sets != 1 {
		t.Fatalf("setup: the long-running peer's lease set was not delivered (sets=%d)", sets)
	}
	ss.handleMessage(nil, syncMsgPersistentNatLease, frame(100, 1))
	if sets != 1 {
		t.Fatalf("attribution: a lower incarnation was admitted before any re-prime (sets=%d), so this cell would not isolate the reset", sets)
	}

	ss.resetRecvGen()
	ss.handleMessage(nil, syncMsgPersistentNatLease, frame(100, 1))
	if sets != 2 {
		t.Fatalf("#9634: after the peer re-prime, the rebooted peer's persistent-NAT lease set was still dropped as stale (sets=%d)", sets)
	}
}
