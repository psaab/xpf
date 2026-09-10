package daemon

// #9412 ACCEPTANCE, daemon hops: a helper delta that states a close class must
// be converted with that class and, when it is a close-state UPDATE rather than
// an open, still be synced to the peer.
//
// Written BEFORE the fix, and shaped to COMPILE at base. The class moves
// through JSON, on both the delta and the converted value, so a struct without
// the field drops it silently and the assertion reads it back absent.

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// closeClassSink9412 keeps the VALUES the walk admits. The shared
// captureDeltaSink keeps keys only, and the class rides on the value.
type closeClassSink9412 struct {
	opensV4 []dataplane.SessionValue
	opensV6 []dataplane.SessionValueV6
	deletes int
}

func (s *closeClassSink9412) openV4(_ dataplane.SessionKey, v dataplane.SessionValue) {
	s.opensV4 = append(s.opensV4, v)
}

func (s *closeClassSink9412) openV6(_ dataplane.SessionKeyV6, v dataplane.SessionValueV6) {
	s.opensV6 = append(s.opensV6, v)
}

func (s *closeClassSink9412) deleteV4(dataplane.SessionKey, dataplane.SessionValue)     { s.deletes++ }
func (s *closeClassSink9412) deleteV6(dataplane.SessionKeyV6, dataplane.SessionValueV6) { s.deletes++ }

func jsonKey9412(t *testing.T, v any, key string) any {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m[key]
}

// closeClassDelta9412 is a v4 TCP delta for `event`, with tcp_close_class
// injected the way the helper's JSON leg writes it.
func closeClassDelta9412(t *testing.T, event string, class int) dpuserspace.SessionDeltaInfo {
	t.Helper()
	base := dpuserspace.SessionDeltaInfo{
		Event: event, AddrFamily: 2, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 12345, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12, OwnerRGID: 1,
	}
	js, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	m["tcp_close_class"] = class
	if js, err = json.Marshal(m); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	var d dpuserspace.SessionDeltaInfo
	if err := json.Unmarshal(js, &d); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	return d
}

func TestConvertCarriesTheCloseClass9412(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	_, val, ok := userspaceSessionFromDeltaV4(closeClassDelta9412(t, "open", 1), zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: delta did not convert")
	}
	if got := jsonKey9412(t, val, "TCPCloseClass"); got != float64(1) {
		t.Fatalf("#9412 ACCEPTANCE: the helper's delta said CLOSING and the synced value "+
			"carries TCPCloseClass=%v, so the cluster wire has nothing to send.", got)
	}
}

func primaryForRG1Daemon9412() (*Daemon, *cluster.SessionSync) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return true },
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 1})
	return &Daemon{sessionSync: ss}, ss
}

// CONTROL: the same delta as an OPEN is admitted by this fixture at base. Without
// it, a red on the UPDATE cell below could be the ownership or zone predicate
// refusing the fixture, not the missing event route.
func TestTheCloseClassFixtureIsAdmittedAsAnOpen9412(t *testing.T) {
	d, ss := primaryForRG1Daemon9412()
	sink := &closeClassSink9412{}
	n := d.walkUserspaceSessionDeltas(ss, map[string]uint16{"lan": 1, "wan": 2},
		[]dpuserspace.SessionDeltaInfo{closeClassDelta9412(t, "open", 0)}, sink)
	if n != 1 || len(sink.opensV4) != 1 {
		t.Fatalf("FIXTURE: an open delta was not admitted (n=%d opens=%d)", n, len(sink.opensV4))
	}
}

func TestAnUpdateDeltaIsSyncedWithItsCloseClass9412(t *testing.T) {
	d, ss := primaryForRG1Daemon9412()
	sink := &closeClassSink9412{}
	n := d.walkUserspaceSessionDeltas(ss, map[string]uint16{"lan": 1, "wan": 2},
		[]dpuserspace.SessionDeltaInfo{closeClassDelta9412(t, "update", 2)}, sink)
	if n != 1 || len(sink.opensV4) != 1 {
		t.Fatalf("#9412 ACCEPTANCE: the helper reported a close-state UPDATE for a session "+
			"this node owns, and the walk synced %d value(s) (n=%d, deletes=%d). The "+
			"update never reaches the peer.", len(sink.opensV4), n, sink.deletes)
	}
	if got := jsonKey9412(t, sink.opensV4[0], "TCPCloseClass"); got != float64(2) {
		t.Fatalf("#9412 ACCEPTANCE: the synced update carries TCPCloseClass=%v, want 2 (TIME_WAIT)", got)
	}
	if sink.deletes != 0 {
		t.Fatalf("an update must never be synced as a delete (deletes=%d)", sink.deletes)
	}
}
