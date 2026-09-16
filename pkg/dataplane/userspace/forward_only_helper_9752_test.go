package userspace

// #9752 round 3 item 4: the forward-only mark reaches the helper request JSON,
// batch and single, and a forward-only single sends exactly one request (the
// reverse companion is the sender's decision, not the helper's derivation).
// Observed through the recording session socket: real request encode/decode.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestForwardOnlyBatchMarksEveryHelperRequest9752(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}
	keys := []dataplane.ScopedSessionKey{
		{Key: k, RoutingDomain: 100007},
		{Key: rev, RoutingDomain: 100007},
	}
	// Mirror error ignored (no BPF here): the helper requests are recorded
	// before the mirror step, and they are what this cell asserts.
	_, _, _ = m.BatchDeletePeerSyncedSessionsScoped(keys, true)
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("recorded %d helper requests, want 2", len(got))
	}
	for i, req := range got {
		if !req.PeerDelete || !req.ForwardOnly {
			t.Errorf("request %d: peer=%v forward_only=%v, want both true", i, req.PeerDelete, req.ForwardOnly)
		}
	}
}

func TestOrdinaryBatchLeavesTheMarkClear9752(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	_, _, _ = m.BatchDeletePeerSyncedSessionsScoped(scopedKeys9364(100007, 1234), false)
	for i, req := range rec.all() {
		if req.ForwardOnly {
			t.Errorf("request %d of an ordinary batch carries forward_only", i)
		}
	}
}

func TestForwardOnlySingleSendsExactlyOneMarkedRequest9752(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}
	val := dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}

	m.mu.Lock()
	m.syncDeleteV4LockedMarked(k, val, true, true, true)
	m.mu.Unlock()
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("forward-only single sent %d helper requests, want exactly the named key", len(got))
	}
	if !got[0].PeerDelete || !got[0].ForwardOnly {
		t.Errorf("peer=%v forward_only=%v, want both true", got[0].PeerDelete, got[0].ForwardOnly)
	}
}

// #9752 round 3 item 4: the forward-only mark is a new wire field, and Go and
// the helper must spell its key identically (#9714 pattern). If they do not,
// every forward-only delete reaches the helper unmarked and derives the
// reverse — the defect itself — while every other Go cell stays green.
func TestTheForwardOnlyWireKeyMatchesTheHelper9752(t *testing.T) {
	marked, err := json.Marshal(SessionSyncRequest{ForwardOnly: true})
	if err != nil {
		t.Fatalf("marshal a marked delete: %v", err)
	}
	if !strings.Contains(string(marked), `"forward_only":true`) {
		t.Errorf("a marked delete does not carry \"forward_only\":true on the wire: %s", marked)
	}
	unmarked, err := json.Marshal(SessionSyncRequest{})
	if err != nil {
		t.Fatalf("marshal an unmarked delete: %v", err)
	}
	if strings.Contains(string(unmarked), "forward_only") {
		t.Errorf("an unmarked delete carries the forward_only key: %s", unmarked)
	}

	src, err := os.ReadFile("../../../userspace-dp/src/protocol/control.rs")
	if err != nil {
		t.Fatalf("read the helper source that decodes the field: %v", err)
	}
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			stripped.WriteString("\n")
			continue
		}
		stripped.WriteString(line)
		stripped.WriteString("\n")
	}
	code := stripped.String()
	for _, want := range []string{`#[serde(rename = "forward_only", default)]`, "pub forward_only: bool,"} {
		if !strings.Contains(code, want) {
			t.Errorf("the helper's SessionSyncRequest no longer contains %q; a marked Go delete "+
				"would decode as unmarked and derive the reverse (#9752 round 3)", want)
		}
	}
}
