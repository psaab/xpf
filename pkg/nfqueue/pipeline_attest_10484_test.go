package nfqueue

import (
	"fmt"
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
		record.TerminalState != string(CompletionCancelled) {
		t.Fatalf("record = %+v, want exactly one cancelled terminal completion", record)
	}
}

func TestD11DigestFrozenVector10484(t *testing.T) {
	got := d11GoFrameDigest(
		[]byte{0x00, 0x11, 0x22},
		ReinjectLease{RequestID: 1, PermitEpoch: 2, QueueEpoch: 3, QueueNumber: 4},
		CaptureOrigin{
			Family:       CaptureFamilyInet,
			Hook:         CaptureHookForward,
			OwnedIfindex: 5,
			Owner:        "rg1",
			STN:          "stn1",
		},
		"attest-00000000000000000000000000000000",
	)
	const want = "7972bbf33fb7f81d51ee31ab9b0588f3d104b33deb48e62de6bb9a7e24b05ab1"
	if gotHex := fmt.Sprintf("%x", got[:]); gotHex != want {
		t.Fatalf("digest = %s, want %s", gotHex, want)
	}
}

func TestD11ArmFailedNonceIsOneShotAndNewRunReplacesAfterDisarm10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	announceErr := true
	armer := NewD11AttestationArmer("node-a", ledger, func(string, uint64) error {
		if announceErr {
			return fmt.Errorf("announce unavailable")
		}
		return nil
	})
	armer.SetEnvironmentGate(func() bool { return true })
	runA := "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := armer.Arm(runA, 9, "00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("failed announcement unexpectedly armed")
	}
	if err := armer.Arm(runA, 9, "00112233445566778899aabbccddeeff"); err != errD11ArmActive {
		t.Fatalf("same attempted nonce error = %v, want %v", err, errD11ArmActive)
	}
	announceErr = false
	runB := "attest-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := armer.Arm(runB, 10, "00112233445566778899aabbccddee00"); err != nil {
		t.Fatalf("new nonce arm: %v", err)
	}
	if !armer.BeginDrain() || !armer.Disarm() {
		t.Fatal("new run did not reach DISARMED")
	}
	runC := "attest-cccccccccccccccccccccccccccccccc"
	if err := armer.Arm(runC, 11, "00112233445566778899aabbccddee11"); err != nil {
		t.Fatalf("post-disarm nonce arm: %v", err)
	}
}

func TestD11LedgerVoidReasonCapAndDeterministicRecords10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
	// Fill the combined record/failure budget. The next row must be truncated
	// rather than allowing failures to grow around the manifest cap.
	for i := range D11ManifestCap {
		requestID := uint64(D11ManifestCap - i)
		frame := CaptureFrame{
			Packet:    pipelineTestPacket(uint16(1000+i), 2, 2, uint32(10+i), uint32(requestID)),
			origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner", STN: "stn", OwnedIfindex: uint32(10 + i)},
			originSet: true,
		}
		if i%2 == 0 {
			if _, err := ledger.Reserve(frame, ReinjectLease{
				RequestID: requestID, PermitEpoch: 9, QueueEpoch: requestID, QueueNumber: uint16(1000 + i),
			}); err != nil {
				t.Fatalf("Reserve[%d]: %v", i, err)
			}
		} else {
			ledger.RecordFailure(frame, "selection failed")
		}
	}
	extra := CaptureFrame{
		Packet:    pipelineTestPacket(2000, 2, 2, 99, 99),
		origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner", STN: "stn", OwnedIfindex: 99},
		originSet: true,
	}
	ledger.RecordFailure(extra, "over cap")
	snapshot := ledger.Snapshot()
	if !snapshot.Truncated || len(snapshot.Records)+len(snapshot.Failures) != D11ManifestCap {
		t.Fatalf("cap snapshot = truncated=%v records=%d failures=%d", snapshot.Truncated, len(snapshot.Records), len(snapshot.Failures))
	}
	ledger.MarkVoid("authority publication failed")
	snapshot = ledger.Snapshot()
	if snapshot.VoidReason != "authority publication failed" || !snapshot.Finalized {
		t.Fatalf("void snapshot = %+v", snapshot)
	}
	for i := range snapshot.Records[1:] {
		if snapshot.Records[i].Key.RequestID > snapshot.Records[i+1].Key.RequestID {
			t.Fatalf("records are not deterministic: %v then %v", snapshot.Records[i].Key, snapshot.Records[i+1].Key)
		}
	}
}

func TestD11WouldPermitRecordsFailTerminalAndReason52Counters10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 11),
		FlowKey: "would-permit",
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 1, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	ledger.UpdateAdmission(key, "ADMIT_OK", false)
	var denyCount int
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: new(pipelineTestSink),
		DenyEvents: DenyEventSinkFunc(func(event IpsecInnerDeny) bool {
			if event.Reason == ReasonEvaluatorUnavailable {
				denyCount++
				return true
			}
			return false
		}),
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: &pendingReinject{
		frame: frame, lease: lease, ledger: ledger, ledgerKey: key,
	}}
	p.pending[lease.RequestID] = p.flows[frame.FlowKey].pending
	p.mu.Unlock()
	if !p.resolveCompletion(ReinjectCompletion{
		RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch,
		QueueNumber: lease.QueueNumber, QueueEpoch: lease.QueueEpoch,
		Family: 1, Hook: 1, OwnedIfindex: 7, Outcome: CompletionWouldPermit,
	}) {
		t.Fatal("WouldPermit completion was not resolved")
	}
	snapshot := ledger.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].TerminalState != "FAIL" ||
		snapshot.Records[0].Completion != CompletionWouldPermit {
		t.Fatalf("WouldPermit ledger row = %+v", snapshot.Records)
	}
	if got := p.Stats(); got.D11Suppressed != 1 || got.D11Deny52 != 1 || denyCount != 1 {
		t.Fatalf("WouldPermit counters = %+v deny=%d", got, denyCount)
	}
}

func TestD11AckTimeoutRecordsUncertainAndFinalizes10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 11),
		FlowKey: "timeout",
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 7, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	ledger.UpdateAdmission(key, "ADMIT_OK", false)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: new(pipelineTestSink),
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	pending := &pendingReinject{
		frame: frame, lease: lease, deadline: time.Unix(1, 0),
		ledger: ledger, ledgerKey: key,
	}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
	p.pending[lease.RequestID] = pending
	p.mu.Unlock()
	if got := p.Poll(time.Unix(2, 0)); got != 1 {
		t.Fatalf("Poll resolved %d requests, want one timeout", got)
	}
	if !ledger.FinalizeIfTerminal() {
		t.Fatal("timeout left the D11 ledger non-terminal")
	}
	record := ledger.Snapshot().Records[0]
	if record.Completion != CompletionUncertain ||
		record.TerminalState != "Uncertain" || record.ResolveCount != 1 {
		t.Fatalf("timeout record = %+v", record)
	}
}
