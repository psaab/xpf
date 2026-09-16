package daemon

// #9752 ACCEPTANCE, daemon hops: a helper delta that states an
// installing-table identity must be converted with that identity and synced
// to the peer. Shaped like close_state_sync_9412_acceptance_test.go: values
// move through JSON so a struct without the fields drops them silently.

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type installTableSink9752 struct {
	opensV4 []dataplane.SessionValue
	opensV6 []dataplane.SessionValueV6
	deletes int
}

func (s *installTableSink9752) openV4(_ dataplane.SessionKey, v dataplane.SessionValue) {
	s.opensV4 = append(s.opensV4, v)
}

func (s *installTableSink9752) openV6(_ dataplane.SessionKeyV6, v dataplane.SessionValueV6) {
	s.opensV6 = append(s.opensV6, v)
}

func (s *installTableSink9752) deleteV4(dataplane.SessionKey, dataplane.SessionValue) {
	s.deletes++
}
func (s *installTableSink9752) deleteV6(dataplane.SessionKeyV6, dataplane.SessionValueV6) {
	s.deletes++
}

func jsonKey9752(t *testing.T, v any, key string) any {
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

// installTableDelta9752 is a v4 TCP delta for `event`, with the table
// identity injected the way the helper's JSON leg writes it.
func installTableDelta9752(t *testing.T, event string) dpuserspace.SessionDeltaInfo {
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
	m["install_table_domain"] = 525590
	m["install_table_check"] = 3318534811
	if js, err = json.Marshal(m); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	var d dpuserspace.SessionDeltaInfo
	if err := json.Unmarshal(js, &d); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	return d
}

func TestConvertCarriesTheInstallTable9752(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	_, val, ok := userspaceSessionFromDeltaV4(installTableDelta9752(t, "open"), zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: delta did not convert")
	}
	if got := jsonKey9752(t, val, "InstallTableDomain"); got != float64(525590) {
		t.Fatalf("#9752 ACCEPTANCE: the helper's delta said domain 525590 and the synced value "+
			"carries InstallTableDomain=%v, so the cluster wire has nothing to send.", got)
	}
	if got := jsonKey9752(t, val, "InstallTableCheck"); got != float64(3318534811) {
		t.Fatalf("#9752 ACCEPTANCE: the helper's delta said check 3318534811 and the synced value "+
			"carries InstallTableCheck=%v.", got)
	}
}

func primaryForRG1Daemon9752() (*Daemon, *cluster.SessionSync) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return true },
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 1})
	return &Daemon{sessionSync: ss}, ss
}

func TestAnOpenDeltaIsSyncedWithItsInstallTable9752(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	sink := &installTableSink9752{}
	n := d.walkUserspaceSessionDeltas(ss, map[string]uint16{"lan": 1, "wan": 2},
		[]dpuserspace.SessionDeltaInfo{installTableDelta9752(t, "open")}, sink)
	if n != 1 || len(sink.opensV4) != 1 {
		t.Fatalf("#9752 ACCEPTANCE: the helper reported an open for a session "+
			"this node owns, and the walk synced %d value(s) (n=%d, deletes=%d).", len(sink.opensV4), n, sink.deletes)
	}
	if got := jsonKey9752(t, sink.opensV4[0], "InstallTableDomain"); got != float64(525590) {
		t.Fatalf("#9752 ACCEPTANCE: the synced open carries InstallTableDomain=%v, want 525590", got)
	}
	if got := jsonKey9752(t, sink.opensV4[0], "InstallTableCheck"); got != float64(3318534811) {
		t.Fatalf("#9752 ACCEPTANCE: the synced open carries InstallTableCheck=%v, want 3318534811", got)
	}
	if sink.deletes != 0 {
		t.Fatalf("an open must never be synced as a delete (deletes=%d)", sink.deletes)
	}
}

// purgeRetirementSink9752 records the values the walk hands to the delete
// arms, so the marker bit's travel from delta to sink is observable without
// a cluster connection.
type purgeRetirementSink9752 struct {
	deletesV4 []dataplane.SessionValue
}

func (s *purgeRetirementSink9752) openV4(_ dataplane.SessionKey, _ dataplane.SessionValue) {
}
func (s *purgeRetirementSink9752) openV6(_ dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
}
func (s *purgeRetirementSink9752) deleteV4(_ dataplane.SessionKey, v dataplane.SessionValue) {
	s.deletesV4 = append(s.deletesV4, v)
}
func (s *purgeRetirementSink9752) deleteV6(_ dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
}

func TestCloseWalkCarriesThePurgeRetirementBit9752(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	sink := &purgeRetirementSink9752{}
	delta := installTableDelta9752(t, "close")
	delta.PurgeRetirement = true
	n := d.walkUserspaceSessionDeltas(ss, map[string]uint16{"lan": 1, "wan": 2},
		[]dpuserspace.SessionDeltaInfo{delta}, sink)
	if n != 1 || len(sink.deletesV4) != 1 {
		t.Fatalf("#9752: the close reached %d deletes (n=%d); the marker bit has nowhere to ride", len(sink.deletesV4), n)
	}
	if sink.deletesV4[0].LogFlags&dataplane.LogFlagPurgeRetirementOnly == 0 {
		t.Fatal("#9752: the delete sink received a value without the purge-retirement bit; " +
			"the cluster delete would go out unmarked and the peer would derive companions")
	}
}
