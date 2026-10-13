package daemon

import (
	"errors"
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/nfqueue"
)

type captureVerdictCall9506 struct {
	packet  *nfqueue.Packet
	verdict nfqueue.Verdict
}

// recordCaptureVerdicts9506 replaces the capture sink's terminal syscall for
// one test. result decides each call's error, in call order.
func recordCaptureVerdicts9506(t *testing.T, result func(call int) error) *[]captureVerdictCall9506 {
	t.Helper()
	var calls []captureVerdictCall9506
	previous := ipsecCapturePacketVerdict
	ipsecCapturePacketVerdict = func(packet *nfqueue.Packet, verdict nfqueue.Verdict) error {
		calls = append(calls, captureVerdictCall9506{packet: packet, verdict: verdict})
		if result == nil {
			return nil
		}
		return result(len(calls))
	}
	t.Cleanup(func() { ipsecCapturePacketVerdict = previous })
	return &calls
}

func newCaptureActor9506(t *testing.T, supervisor *ipsecSupervisor, phase nfqueue.PipelinePhase) *IpsecCapturePipeline {
	t.Helper()
	actor, err := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{
		Supervisor: supervisor,
		Registry:   new(nfqueue.OriginRegistry),
		Pipeline:   nfqueue.CapturePipelineConfig{Phase: phase, HandoffCap: 1, BatchCap: 1},
	})
	if err != nil {
		t.Fatalf("NewIpsecCapturePipeline: %v", err)
	}
	return actor
}

func allocateCaptureQueue9506(t *testing.T, supervisor *ipsecSupervisor) ipsecQueueHandle {
	t.Helper()
	handle, err := supervisor.allocateQueue(ipsecQueueKey{
		Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookForward,
		Owner: "w0", STN: "st0", Ifindex: 10,
	})
	if err != nil {
		t.Fatalf("allocateQueue: %v", err)
	}
	return handle
}

func assertOneCaptureDrop9506(t *testing.T, calls []captureVerdictCall9506, packet *nfqueue.Packet) {
	t.Helper()
	if len(calls) != 1 || calls[0].packet != packet || calls[0].verdict != nfqueue.VerdictDrop {
		t.Fatalf("capture terminal calls=%+v, want exactly one DROP for the captured packet", calls)
	}
}

// The capture sink is the security gate for decrypted traffic: whatever the
// pipeline requests, including a shadow-phase ACCEPT, the kernel receives one
// DROP through the supervisor committer.
func TestIpsecCaptureSinkDropsEveryRequestedVerdict9506(t *testing.T) {
	for _, requested := range []nfqueue.Verdict{nfqueue.VerdictAccept, nfqueue.VerdictDrop} {
		calls := recordCaptureVerdicts9506(t, nil)
		supervisor := newIpsecSupervisor()
		handle := allocateCaptureQueue9506(t, supervisor)
		actor := newCaptureActor9506(t, supervisor, nfqueue.PipelineShadow)
		packet := &nfqueue.Packet{}
		err := actor.VerdictFrame(nfqueue.CaptureFrame{
			Packet: packet, QueueNumber: handle.Number, QueueEpoch: handle.Epoch,
			SnapshotGeneration: 1,
		}, requested)
		if err != nil {
			t.Fatalf("requested %v: VerdictFrame error %v", requested, err)
		}
		assertOneCaptureDrop9506(t, *calls, packet)
		supervisor.terminalMu.Lock()
		retained := len(supervisor.terminal)
		supervisor.terminalMu.Unlock()
		if retained != 0 {
			t.Fatalf("requested %v: %d terminal records retained after a successful DROP", requested, retained)
		}
	}
}

// Every frame the actor's pipeline terminates reaches the supervisor-backed
// sink, even for an actor without receive queues.
func TestIpsecCaptureActorIsPipelineTerminalSink9506(t *testing.T) {
	calls := recordCaptureVerdicts9506(t, nil)
	actor := newCaptureActor9506(t, newIpsecSupervisor(), nfqueue.PipelineShadow)
	packet := &nfqueue.Packet{}
	// An unregistered queue fails provenance and is terminated by the
	// pipeline itself, not by the caller.
	if err := actor.Enqueue(nfqueue.CaptureFrame{Packet: packet}); err == nil {
		t.Fatal("unregistered capture queue was admitted")
	}
	assertOneCaptureDrop9506(t, *calls, packet)
}

// A kernel packet ID that comes back on the same queue epoch still receives a
// verdict: after a successful DROP the key is released, and while an earlier
// uncertain verdict still holds it the sink falls back to a direct DROP.
func TestIpsecCaptureSinkReusedPacketIDStillGetsVerdict9506(t *testing.T) {
	calls := recordCaptureVerdicts9506(t, func(call int) error {
		if call == 2 {
			return errors.New("verdict outcome unknown")
		}
		return nil
	})
	supervisor := newIpsecSupervisor()
	handle := allocateCaptureQueue9506(t, supervisor)
	actor := newCaptureActor9506(t, supervisor, nfqueue.PipelineEnforcing)
	frame := func(packet *nfqueue.Packet) nfqueue.CaptureFrame {
		return nfqueue.CaptureFrame{
			Packet: packet, QueueNumber: handle.Number, QueueEpoch: handle.Epoch,
			SnapshotGeneration: 1,
		}
	}
	// Zero-value packets all carry kernel packet ID 0 on this queue epoch.
	first, second, third := &nfqueue.Packet{}, &nfqueue.Packet{}, &nfqueue.Packet{}
	if err := actor.VerdictFrame(frame(first), nfqueue.VerdictDrop); err != nil {
		t.Fatalf("first verdict: %v", err)
	}
	if err := actor.VerdictFrame(frame(second), nfqueue.VerdictDrop); err == nil {
		t.Fatal("second verdict hid its uncertain sink error")
	}
	if err := actor.VerdictFrame(frame(third), nfqueue.VerdictDrop); err != nil {
		t.Fatalf("reused packet ID behind an uncertain record: %v", err)
	}
	want := []*nfqueue.Packet{first, second, third}
	if len(*calls) != len(want) {
		t.Fatalf("capture terminal calls=%+v, want one DROP per packet", *calls)
	}
	for i, call := range *calls {
		if call.packet != want[i] || call.verdict != nfqueue.VerdictDrop {
			t.Fatalf("call %d=%+v, want DROP for packet %d", i, call, i)
		}
	}
}

// Successful verdicts leave no per-packet record behind, and uncertain ones
// are capped, so the map and the supervisor tick stay bounded under load.
func TestIpsecTerminalRecordsStayBounded9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	handle := allocateCaptureQueue9506(t, supervisor)
	commit := func(id uint32, sink ipsecVerdictSink) error {
		_, _, err := supervisor.commitValidatedVerdict(
			ipsecLeaseToken{queueEpoch: handle.Epoch}, handle.Number, ipsecVerdictDrop, nil,
			ipsecPacketRef{GateID: handle.Number, QueueNumber: handle.Number,
				QueueEpoch: handle.Epoch, SnapshotGeneration: 1, PacketID: id},
			sink,
		)
		return err
	}
	ok := &recordingVerdictSink{}
	for id := range uint32(20_000) {
		if err := commit(id+1, ok); err != nil {
			t.Fatalf("commit %d: %v", id+1, err)
		}
	}
	supervisor.terminalMu.Lock()
	retained := len(supervisor.terminal)
	supervisor.terminalMu.Unlock()
	if ok.calls != 20_000 || retained != 0 {
		t.Fatalf("successful verdicts=%d retained=%d, want 20000 and 0", ok.calls, retained)
	}

	failing := ipsecVerdictSinkFunc(func(ipsecVerdict, uint32) error { return errors.New("uncertain") })
	for id := range uint32(ipsecTerminalUncertainCap + 100) {
		_ = commit(100_000+id, failing)
	}
	supervisor.terminalMu.Lock()
	retained = len(supervisor.terminal)
	_, newestKept := supervisor.terminal[ipsecTerminalKey{GateID: handle.Number,
		QueueNumber: handle.Number, QueueEpoch: handle.Epoch, PacketID: 100_000 + ipsecTerminalUncertainCap + 99}]
	_, oldestKept := supervisor.terminal[ipsecTerminalKey{GateID: handle.Number,
		QueueNumber: handle.Number, QueueEpoch: handle.Epoch, PacketID: 100_000}]
	supervisor.terminalMu.Unlock()
	if retained != ipsecTerminalUncertainCap || !newestKept || oldestKept {
		t.Fatalf("uncertain records=%d newest=%v oldest=%v, want cap %d keeping the newest",
			retained, newestKept, oldestKept, ipsecTerminalUncertainCap)
	}
}

type ipsecVerdictSinkFunc func(ipsecVerdict, uint32) error

func (f ipsecVerdictSinkFunc) Verdict(verdict ipsecVerdict, packetID uint32) error {
	return f(verdict, packetID)
}

func TestIpsecAllocateQueueRegistersEmissionGateEpoch9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	handle := allocateCaptureQueue9506(t, supervisor)
	gate := supervisor.gate(handle.Number)
	if gate == nil || gate.epoch.Load() != handle.Epoch || gate.currentState() != ipsecGateOpen {
		t.Fatalf("queue %d epoch %d gate=%+v, want an open gate at the queue epoch",
			handle.Number, handle.Epoch, gate)
	}
	if err := supervisor.retireQueue(handle, true, true); err != nil {
		t.Fatalf("retireQueue: %v", err)
	}
	if gate.currentState() != ipsecGateClosed {
		t.Fatalf("retired gate state=%v, want closed", gate.currentState())
	}
}

// Each accepted snapshot replaces the P-MECH half of the packet authority;
// a snapshot without inventory clears it rather than keeping an older one.
func TestPMechAcceptedAuthorityFollowsSnapshotInventory9506(t *testing.T) {
	snapshot := buildPMechZoneSnapshot(nil, wiringHandles9506(), 4, 4)
	runtime := &ipsecCaptureRuntime{zoneSnapshot: snapshot, handles: wiringHandles9506()}
	publish := func(config uint64, fib uint32, generation uint64, identity string) {
		var inventory *dpuserspace.IpsecPMechInventorySnapshot
		if generation != 0 {
			inventory = &dpuserspace.IpsecPMechInventorySnapshot{
				Generation: generation, FIBGeneration: fib, PolicyIdentity: identity,
			}
		}
		runtime.publishSnapshotAuthority(config, fib, &dpuserspace.ConfigSnapshot{PMechInventory: inventory})
	}
	check := func(step string, generation uint64, fib uint32, identity byte) {
		t.Helper()
		got := snapshot.PacketAuthority()
		var want [32]byte
		for i := range want {
			want[i] = identity
		}
		if got.PMechInventoryGeneration != generation || got.PMechInventoryFIBGeneration != fib ||
			got.PMechPolicyIdentity != want {
			t.Fatalf("%s: authority=%+v, want inventory (%d,%d) identity %#x",
				step, got, generation, fib, identity)
		}
	}
	publish(9, 7, 11, strings.Repeat("ab", 32))
	check("first inventory", 11, 7, 0xab)
	publish(10, 8, 12, strings.Repeat("cd", 32))
	check("replacement inventory", 12, 8, 0xcd)
	runtime.publishSnapshotAuthority(11, 9, nil)
	check("generation-only publish", 12, 8, 0xcd)
	publish(12, 10, 0, "")
	check("snapshot without inventory", 0, 0, 0)
}
