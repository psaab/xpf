package daemon

// #9752 round 4 item 4, chain link G1: the Rust producer's delta golden
// (pkg/dataplane/userspace/testdata/pbr_delta_9752.json, written by the
// helper's own session_delta_info) → REAL unmarshal → REAL daemon walk →
// synced SessionValue → shared val golden for the cluster link. No
// hand-shaped delta anywhere: the walk consumes producer bytes.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type chainSink9752 struct {
	keys []dataplane.SessionKey
	vals []dataplane.SessionValue
}

func (s *chainSink9752) openV4(k dataplane.SessionKey, v dataplane.SessionValue) {
	s.keys = append(s.keys, k)
	s.vals = append(s.vals, v)
}
func (s *chainSink9752) openV6(_ dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
}
func (s *chainSink9752) deleteV4(_ dataplane.SessionKey, _ dataplane.SessionValue) {
}
func (s *chainSink9752) deleteV6(_ dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
}

func TestProducerDeltaConvertsToSyncedValue9752(t *testing.T) {
	raw, err := os.ReadFile("../dataplane/userspace/testdata/pbr_delta_9752.json")
	if err != nil {
		t.Fatalf("read producer golden: %v", err)
	}
	var delta dpuserspace.SessionDeltaInfo
	if err := json.Unmarshal(raw, &delta); err != nil {
		t.Fatalf("unmarshal producer delta: %v", err)
	}
	if delta.Event != "open" || delta.SrcPort != 55068 || delta.DstPort != 443 {
		t.Fatalf("producer golden misread: event=%s ports=%d/%d", delta.Event, delta.SrcPort, delta.DstPort)
	}
	if delta.InstallTableDomain != 525590 || delta.InstallTableCheck != 3318534811 {
		t.Fatalf("producer golden lost the stamp: (%d,%d)",
			delta.InstallTableDomain, delta.InstallTableCheck)
	}
	if delta.RTFlowSessionID != 77 {
		t.Fatalf("producer golden lost the session id: %d", delta.RTFlowSessionID)
	}
	d, ss := primaryForRG1Daemon9752()
	sink := &chainSink9752{}
	n := d.walkUserspaceSessionDeltas(ss, map[string]uint16{"lan": 1, "wan": 2}, []dpuserspace.SessionDeltaInfo{delta}, sink)
	if n != 1 || len(sink.vals) != 1 {
		t.Fatalf("walk synced %d values, want 1", len(sink.vals))
	}
	key, val := sink.keys[0], sink.vals[0]
	// Production key shape: network-order ports.
	if key.Protocol != 6 || key.SrcPort != userspaceHostToNetwork16(55068) || key.DstPort != userspaceHostToNetwork16(443) {
		t.Fatalf("converted key misread: %+v", key)
	}
	if val.InstallTableDomain != 525590 || val.InstallTableCheck != 3318534811 {
		t.Fatalf("converted value lost the stamp: (%d,%d)", val.InstallTableDomain, val.InstallTableCheck)
	}
	if val.SessionID == 0 || val.RTFlowSessionID == 0 {
		t.Fatalf("converted value lost session identity: %+v", val)
	}
	// Hand off to the cluster link: the converted (key, value) pair as
	// JSON. The round-trip is asserted so the file is proven lossless —
	// production passes the structs in memory; the file is only the
	// cycle-free carrier.
	// Normalize clock readings for golden stability (the chain pins
	// identity + stamp, not instants).
	val.Created, val.LastSeen = 0, 0
	pair := struct {
		Key dataplane.SessionKey
		Val dataplane.SessionValue
	}{key, val}
	wire, err := json.Marshal(pair)
	if err != nil {
		t.Fatalf("marshal converted pair: %v", err)
	}
	var rt struct {
		Key dataplane.SessionKey
		Val dataplane.SessionValue
	}
	if err := json.Unmarshal(wire, &rt); err != nil || rt != pair {
		t.Fatalf("value golden would not round-trip: %v", err)
	}
	const path = "../dataplane/userspace/testdata/synced_val_9752.json"
	if os.Getenv("XPF_WRITE_SYNCED_VAL_9752") != "" {
		if err := os.WriteFile(path, append(wire, '\n'), 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shared val golden: %v", err)
	}
	if string(golden) != string(wire)+"\n" {
		t.Fatalf("converted value drifted vs the shared golden:\n got %s\nwant %s", wire, golden)
	}
}
