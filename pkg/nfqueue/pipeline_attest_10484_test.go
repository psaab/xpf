package nfqueue

import (
	"os"
	"testing"
	"time"
)

func TestD11ArmEnvironmentGateFrozenAtDaemonConstruction10484(t *testing.T) {
	const envName = "XPF_ATTEST_10484_ARM"
	old, hadOld := os.LookupEnv(envName)
	t.Cleanup(func() {
		if hadOld {
			_ = os.Setenv(envName, old)
		} else {
			_ = os.Unsetenv(envName)
		}
	})
	_ = os.Unsetenv(envName)
	armEnabledAtConstruction := os.Getenv(envName) == "1"
	armer := NewD11AttestationArmer("node-a", NewD11AttestationLedger(), func(string, uint64) error {
		return nil
	})
	armer.SetEnvironmentGate(func() bool { return armEnabledAtConstruction })
	_ = os.Setenv(envName, "1")
	if err := armer.Arm("attest-0123456789abcdef0123456789abcdef", 9, "00112233445566778899aabbccddeeff"); err != errD11ArmDisabled {
		t.Fatalf("Arm after environment mutation = %v, want cached disabled gate", err)
	}
}

func TestD11LedgerFinalizeIfTerminalRetainsRows10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-0123456789abcdef0123456789abcdef", 9)
	frame := CaptureFrame{
		Packet:    &Packet{queueID: 1000, payload: []byte{0x45, 0x01}, nfgenFamily: 2, hook: 2, indevIfindex: 7},
		origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-a", STN: "stn-a", OwnedIfindex: 7},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 11, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 1000}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if ledger.FinalizeIfTerminal() {
		t.Fatal("finalized admission-pending row")
	}
	if !ledger.UpdateAdmission(key, "ADMIT_OK", false) {
		t.Fatal("UpdateAdmission failed")
	}
	if ledger.FinalizeIfTerminal() {
		t.Fatal("finalized row before terminal completion")
	}
	if !ledger.RecordCompletion(key, ReinjectCompletion{RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch, QueueEpoch: lease.QueueEpoch, QueueNumber: lease.QueueNumber, Outcome: CompletionUncertain}, "Uncertain") {
		t.Fatal("RecordCompletion failed")
	}
	if !ledger.FinalizeIfTerminal() {
		t.Fatal("terminal row was not finalized")
	}
	snapshot := ledger.Snapshot()
	if !snapshot.Finalized || len(snapshot.Records) != 1 {
		t.Fatalf("snapshot = %+v, want finalized one-row evidence", snapshot)
	}
	if snapshot.Records[0].TerminalState != "Uncertain" {
		t.Fatalf("terminal state = %q, want Uncertain", snapshot.Records[0].TerminalState)
	}
}

func TestD11CancelDrainKeepsPendingUntilCompletion10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-0123456789abcdef0123456789abcdef", 9)
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 11),
		FlowKey: "d11-cancel",
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 11, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !ledger.UpdateAdmission(key, "ADMIT_OK", false) {
		t.Fatal("UpdateAdmission failed")
	}
	submitter := new(pipelineTestSubmitter)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: new(pipelineTestSink), Submitter: submitter,
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	pending := &pendingReinject{
		frame: frame, lease: lease, deadline: time.Now().Add(time.Second),
		ledger: ledger, ledgerKey: key,
	}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
	p.pending[lease.RequestID] = pending
	p.mu.Unlock()

	if err := p.CancelForD11Drain(lease.PermitEpoch); err != nil {
		t.Fatalf("CancelForD11Drain: %v", err)
	}
	p.mu.Lock()
	_, stillPending := p.pending[lease.RequestID]
	p.mu.Unlock()
	if !stillPending {
		t.Fatal("D11 cancellation deleted the pending row before Rust completion")
	}
	if len(submitter.cancelled) != 1 || submitter.cancelled[0] != lease.RequestID {
		t.Fatalf("cancelled request IDs = %v, want [%d]", submitter.cancelled, lease.RequestID)
	}
	submitter.drain = []ReinjectCompletion{{
		RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch,
		QueueNumber: lease.QueueNumber, QueueEpoch: lease.QueueEpoch,
		Family: 1, Hook: 1, OwnedIfindex: 7,
		Outcome: CompletionCancelled, Reason: "D11 rollback",
	}}
	if err := p.DrainD11(lease.PermitEpoch, time.Second); err != nil {
		t.Fatalf("DrainD11: %v", err)
	}
	if !ledger.FinalizeIfTerminal() {
		t.Fatal("ledger did not finalize after Rust cancellation completion")
	}
	snapshot := ledger.Snapshot()
	if len(snapshot.Records) != 1 {
		t.Fatalf("records = %d, want one retained row", len(snapshot.Records))
	}
	record := snapshot.Records[0]
	if record.ResolveCount != 1 || record.Completion != CompletionCancelled ||
		record.TerminalState != "FAIL" {
		t.Fatalf("record = %+v, want exactly one cancelled terminal completion", record)
	}
}
