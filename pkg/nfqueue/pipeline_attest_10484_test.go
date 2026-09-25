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

func TestD11MarkerMatchesRejectsMalformedAndWrongSelectors10484(t *testing.T) {
	var selector [16]byte
	for i := range selector {
		selector[i] = byte(i + 1)
	}
	valid := make([]byte, 20+8+32)
	valid[0] = 0x45
	valid[9] = 1
	valid[20] = 8
	copy(valid[20+8+16:], selector[:])
	other := append([]byte(nil), valid...)
	other[20+8+16] ^= 0xff
	echoReply := append([]byte(nil), valid...)
	echoReply[20] = 0
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"valid-echo-request", valid, true},
		{"valid-echo-reply", echoReply, false},
		{"short-ipv4", valid[:19], false},
		{"wrong-version", func() []byte { p := append([]byte(nil), valid...); p[0] = 0x65; return p }(), false},
		{"short-ihl", func() []byte { p := append([]byte(nil), valid...); p[0] = 0x44; return p }(), false},
		{"non-icmp", func() []byte { p := append([]byte(nil), valid...); p[9] = 6; return p }(), false},
		{"bad-icmp-type", func() []byte { p := append([]byte(nil), valid...); p[20] = 3; return p }(), false},
		{"bad-icmp-code", func() []byte { p := append([]byte(nil), valid...); p[21] = 1; return p }(), false},
		{"wrong-selector", other, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := d11MarkerMatches(test.pkt, selector); got != test.want {
				t.Fatalf("d11MarkerMatches = %v, want %v", got, test.want)
			}
		})
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
	if !ledger.FinalizeIfTerminal() {
		t.Fatal("empty run did not finalize before archive")
	}
	announceErr = true
	runC := "attest-cccccccccccccccccccccccccccccccc"
	if err := armer.Arm(runC, 11, "00112233445566778899aabbccddee11"); err == nil {
		t.Fatal("failed post-disarm announcement unexpectedly armed")
	}
	if archived, ok := armer.ArchivedSnapshot(runB); !ok || !archived.Finalized {
		t.Fatalf("failed arm dropped prior archive: ok=%v snapshot=%+v", ok, archived)
	}
	announceErr = false
	runD := "attest-dddddddddddddddddddddddddddddddd"
	if err := armer.Arm(runD, 12, "00112233445566778899aabbccddee22"); err != nil {
		t.Fatalf("post-disarm nonce arm: %v", err)
	}
	if archived, ok := armer.ArchivedSnapshot(runB); !ok || !archived.Finalized {
		t.Fatalf("prior run was not archived before Begin: ok=%v snapshot=%+v", ok, archived)
	}
	if !armer.BeginDrain() || !armer.Disarm() {
		t.Fatal("third run did not reach DISARMED")
	}
	if !ledger.FinalizeIfTerminal() {
		t.Fatal("third run did not finalize")
	}
	if err := armer.Arm(runA, 12, "00112233445566778899aabbccddeeff"); err != errD11ArmActive {
		t.Fatalf("A->B->C(fail)->D->A reuse error = %v, want %v", err, errD11ArmActive)
	}
}

func TestD11CancelTreatsCancelResponseAsSendOnlyAndRecordsUncertain10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-0123456789abcdef0123456789abcdef", 9)
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 13),
		FlowKey: "d11-cancel-send-only",
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 13, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
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
	pending := &pendingReinject{frame: frame, lease: lease, ledger: ledger, ledgerKey: key}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
	p.pending[lease.RequestID] = pending
	p.mu.Unlock()
	if err := p.Cancel(lease.PermitEpoch, lease.QueueNumber, lease.QueueEpoch); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if len(submitter.cancelled) != 1 || submitter.cancelled[0] != lease.RequestID {
		t.Fatalf("cancelled IDs = %v, want [%d]", submitter.cancelled, lease.RequestID)
	}
	snapshot := ledger.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].Completion != CompletionUncertain ||
		snapshot.Records[0].TerminalState != "Uncertain" || snapshot.Records[0].ResolveCount != 1 {
		t.Fatalf("cancel ledger row = %+v, want one uncertain terminal", snapshot.Records)
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
	if got := p.Stats(); got.D11Suppressed != 1 || got.V1PermitSuppressed != 0 ||
		got.D11Deny52 != 1 || denyCount != 1 {
		t.Fatalf("WouldPermit counters = %+v deny=%d", got, denyCount)
	}
}

func TestD11CompletionOriginMismatchIsUncertainWhileV1Accepts10484(t *testing.T) {
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 11),
		FlowKey: "d11-origin-mismatch",
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 1, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", lease.PermitEpoch)
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !ledger.UpdateAdmission(key, "ADMIT_OK", false) {
		t.Fatal("UpdateAdmission failed")
	}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: new(pipelineTestSink),
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	pending := &pendingReinject{frame: frame, lease: lease, ledger: ledger, ledgerKey: key}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
	p.pending[lease.RequestID] = pending
	p.mu.Unlock()
	if !p.resolveCompletion(ReinjectCompletion{
		RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch,
		QueueEpoch: lease.QueueEpoch, QueueNumber: lease.QueueNumber,
		Family: 2, Hook: 1, OwnedIfindex: 7, Outcome: CompletionWritten,
		BytesWritten: uint32(len(frame.Packet.Payload())),
	}) {
		t.Fatal("D11 mismatched completion was not resolved")
	}
	record := ledger.Snapshot().Records[0]
	if record.TerminalState != "Uncertain" || record.Completion != CompletionWritten {
		t.Fatalf("D11 mismatch record = %+v, want Uncertain/Written", record)
	}
	if got := p.Stats(); got.Uncertain != 1 || got.Written != 0 || got.Reinjected != 0 {
		t.Fatalf("D11 mismatch stats = %+v, want uncertain only", got)
	}

	v1, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: new(pipelineTestSink),
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline V1: %v", err)
	}
	v1Pending := &pendingReinject{frame: frame, lease: lease}
	v1.mu.Lock()
	v1.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: v1Pending}
	v1.pending[lease.RequestID] = v1Pending
	v1.mu.Unlock()
	if !v1.resolveCompletion(ReinjectCompletion{
		RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch,
		QueueEpoch: lease.QueueEpoch, QueueNumber: lease.QueueNumber,
		Family: 2, Hook: 1, OwnedIfindex: 7, Outcome: CompletionWritten,
		BytesWritten: uint32(len(frame.Packet.Payload())),
	}) {
		t.Fatal("V1 mismatched completion was not resolved")
	}
	if got := v1.Stats(); got.Written != 1 || got.Reinjected != 1 || got.Uncertain != 0 {
		t.Fatalf("V1 mismatch stats = %+v, want written/reinjected only", got)
	}
}

func TestD11AdmissionContractFailureUnwindsPending10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 12),
		FlowKey: "admission-contract",
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 12, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !ledger.UpdateAdmission(key, "ADMIT_OK", false) {
		t.Fatal("UpdateAdmission failed")
	}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: new(pipelineTestSink),
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	item := &pendingReinject{frame: frame, lease: lease, ledger: ledger, ledgerKey: key}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: item}
	p.pending[lease.RequestID] = item
	p.mu.Unlock()
	failed := p.applyAdmission(item, ReinjectAdmission{
		RequestID: lease.RequestID + 1, PermitEpoch: lease.PermitEpoch,
		QueueNumber: lease.QueueNumber, QueueEpoch: lease.QueueEpoch,
		Family: 1, Hook: 1, OwnedIfindex: 7, Admitted: true,
	})
	if failed != item {
		t.Fatalf("contract failure item = %p, want %p", failed, item)
	}
	p.mu.Lock()
	_, pending := p.pending[lease.RequestID]
	flow := p.flows[frame.FlowKey]
	p.mu.Unlock()
	if pending || (flow != nil && flow.pending != nil) {
		t.Fatalf("contract failure left pending state: map=%v flow=%p", pending, flow)
	}
	record := ledger.Snapshot().Records[0]
	if record.AdmissionCode != "CONTRACT" || !record.ContractRefusal ||
		record.TerminalState != "FAIL" {
		t.Fatalf("contract failure ledger row = %+v", record)
	}
}

func TestD11LedgerEarlyDuplicateAndLatePins10484(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
	if ledger.MarkLate(999) {
		t.Fatal("unknown late completion unexpectedly matched a D11 row")
	}
	if failures := ledger.Snapshot().Failures; len(failures) != 1 ||
		failures[0].Reason != "unmatched late completion request_id=999" {
		t.Fatalf("unknown late marker = %+v", failures)
	}
	frame := CaptureFrame{
		Packet:    pipelineTestPacket(77, 2, 2, 7, 12),
		origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner", STN: "st0", OwnedIfindex: 7},
		originSet: true,
	}
	lease := ReinjectLease{RequestID: 12, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !ledger.UpdateAdmission(key, "ADMIT_OK", false) {
		t.Fatal("UpdateAdmission failed")
	}
	completion := ReinjectCompletion{
		RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch,
		QueueEpoch: lease.QueueEpoch, QueueNumber: lease.QueueNumber,
		Outcome: CompletionUncertain,
	}
	if !ledger.RecordEarlyCompletion(key, completion) ||
		!ledger.RecordEarlyCompletion(key, ReinjectCompletion{RequestID: 99, Outcome: CompletionWritten}) {
		t.Fatal("early completion was not retained")
	}
	if !ledger.MarkDuplicate(key) || !ledger.MarkLate(lease.RequestID) {
		t.Fatal("duplicate/late markers were not recorded")
	}
	if !ledger.RecordCompletion(key, completion, "Uncertain") {
		t.Fatal("terminal completion was not recorded")
	}
	record := ledger.Snapshot().Records[0]
	if !record.Duplicate || record.LateAttempts != 1 || record.ResolveCount != 1 ||
		record.TerminalState != "FAIL" || record.EarlyCompletion == nil ||
		record.EarlyCompletion.RequestID != lease.RequestID {
		t.Fatalf("duplicate/late record = %+v", record)
	}
	if ledger.FinalizeIfTerminal() {
		t.Fatal("duplicate/late terminal row finalized")
	}
	if !ledger.AllTerminal() {
		t.Fatal("duplicate/late row was not terminal for close teardown")
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

func TestD11AdmissionReasonAndTerminalMapping10484(t *testing.T) {
	tests := []struct {
		code     uint8
		name     string
		contract bool
	}{
		{reinjectAdmitOK, "ADMIT_OK", false},
		{reinjectAdmitStale, "ADMIT_STALE", false},
		{reinjectAdmitFull, "ADMIT_FULL", false},
		{reinjectAdmitShutdown, "ADMIT_SHUTDOWN", false},
		{reinjectAdmitBadLease, "ADMIT_BAD_LEASE", true},
		{reinjectAdmitBridge, "ADMIT_BRIDGE", true},
		{reinjectAdmitInputHook, "ADMIT_INPUT_HOOK", true},
		{reinjectAdmitNonDryRun, "ADMIT_NON_DRY_RUN", true},
		{reinjectAdmitNoGeneration, "ADMIT_NO_GENERATION", true},
		{reinjectAdmitTunnelRowMissing, "ADMIT_TUNNEL_ROW_MISSING", true},
		{255, "ADMIT_UNKNOWN_255", true},
	}
	for index, test := range tests {
		name, contract := d11AdmissionReason(test.code)
		if name != test.name || contract != test.contract {
			t.Fatalf("code %d maps to (%q,%v), want (%q,%v)",
				test.code, name, contract, test.name, test.contract)
		}
		if test.code == reinjectAdmitOK {
			continue
		}
		ledger := NewD11AttestationLedger()
		ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
		frame := CaptureFrame{
			Packet:    pipelineTestPacket(77, 2, 2, 7, uint32(index+1)),
			origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner", STN: "st0", OwnedIfindex: 7},
			originSet: true,
		}
		key, err := ledger.Reserve(frame, ReinjectLease{
			RequestID: uint64(index + 1), PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77,
		})
		if err != nil {
			t.Fatalf("Reserve code %d: %v", test.code, err)
		}
		if !ledger.UpdateAdmission(key, name, contract) {
			t.Fatalf("UpdateAdmission code %d failed", test.code)
		}
		record := ledger.Snapshot().Records[0]
		wantTerminal := "VOID"
		if contract {
			wantTerminal = "FAIL"
		}
		if record.TerminalState != wantTerminal || record.ContractRefusal != contract {
			t.Fatalf("code %d record = %+v, want terminal=%s contract=%v",
				test.code, record, wantTerminal, contract)
		}
		if !ledger.FinalizeIfTerminal() {
			t.Fatalf("code %d refusal did not finalize", test.code)
		}
	}
}

func TestD11OriginValidRejectsWrongOwner10484(t *testing.T) {
	p := &CapturePipeline{attestation: &D11AttestationConfig{
		OriginValid: func(origin CaptureOrigin) bool { return origin.Owner == "owner-a" },
	}}
	frame := CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 1),
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-b", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
	if _, err := p.validateD11Frame(frame); err == nil || err.Error() != "origin owner mismatch" {
		t.Fatalf("wrong owner validation error = %v, want origin owner mismatch", err)
	}
	frame.origin.Owner = "owner-a"
	if _, err := p.validateD11Frame(frame); err == nil || err.Error() != "zone evaluator unavailable" {
		t.Fatalf("accepted owner validation error = %v, want zone evaluator unavailable", err)
	}
}

type d11AttestLeaseMinter11016 struct {
	calls int
}

func (m *d11AttestLeaseMinter11016) MintLease(frame CaptureFrame) (ReinjectLease, error) {
	return m.MintLeaseForAttest(frame, "", 1)
}

func (m *d11AttestLeaseMinter11016) MintLeaseForAttest(frame CaptureFrame, _ string, permitEpoch uint64) (ReinjectLease, error) {
	m.calls++
	return ReinjectLease{
		RequestID: uint64(m.calls), PermitEpoch: permitEpoch,
		QueueNumber: frame.Packet.QueueID(), QueueEpoch: frame.QueueEpoch,
	}, nil
}

func d11IngressFrame11016(hook CaptureHook, flow string, id uint32) CaptureFrame {
	return CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, id), FlowKey: flow,
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: hook,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true,
	}
}

func TestD11RejectsInputHookBeforeLeaseOrReserve11016(t *testing.T) {
	ledger := NewD11AttestationLedger()
	armer := NewD11AttestationArmer("node-a", ledger, func(string, uint64) error { return nil })
	armer.SetEnvironmentGate(func() bool { return true })
	if err := armer.Arm("attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9,
		"00112233445566778899aabbccddeeff"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	minter := new(d11AttestLeaseMinter11016)
	submitter := new(pipelineTestSubmitter)
	var denies []IpsecInnerDeny
	p := &CapturePipeline{
		leaseMinter: minter, submitter: submitter,
		attestation: &D11AttestationConfig{
			Armer: armer, Ledger: ledger,
			OriginValid:      func(CaptureOrigin) bool { return true },
			AuthorityCurrent: func() bool { return true },
		},
		zoneEvaluator: passZoneEvaluator9506{}, zoneSnapshot: passZoneSnapshot9506{},
		denyEvents: DenyEventSinkFunc(func(event IpsecInnerDeny) bool {
			denies = append(denies, event)
			return true
		}),
		sink: new(pipelineTestSink), flows: make(map[string]*flowState),
		pending: make(map[uint64]*pendingReinject),
	}
	input := d11IngressFrame11016(CaptureHookInput, "input", 11)
	if _, err := p.validateD11Frame(input); err == nil || err.Error() != "unsupported family or hook" {
		t.Fatalf("inet/input dry-run validation error=%v, want explicit unsupported-hook error", err)
	}
	p.attestSubmit([]CaptureFrame{input})
	if minter.calls != 0 || len(submitter.submitted) != 0 {
		t.Fatalf("inet/input consumed lease/submission resources: minted=%d submitted=%d",
			minter.calls, len(submitter.submitted))
	}
	if got := ledger.Snapshot(); len(got.Records) != 0 || len(got.Failures) != 1 ||
		got.Failures[0].Reason != "unsupported family or hook" {
		t.Fatalf("inet/input ledger=%+v, want one explicit failure and no lease record", got)
	}
	if len(denies) != 1 || denies[0].Reason != ReasonUnsupportedHook ||
		p.Stats().Adjudicated != 0 {
		t.Fatalf("inet/input denies=%+v stats=%+v", denies, p.Stats())
	}

	output := d11IngressFrame11016(CaptureHookForward, "output", 12)
	if _, err := p.validateD11Frame(output); err != nil {
		t.Fatalf("inet/output dry-run validation: %v", err)
	}
	p.flows[output.FlowKey] = &flowState{frames: []CaptureFrame{output}}
	p.attestSubmit([]CaptureFrame{output})
	if minter.calls != 1 || len(submitter.submitted) != 1 ||
		submitter.submitted[0].Origin.Hook != CaptureHookForward ||
		p.Stats().Adjudicated != 1 {
		t.Fatalf("inet/output did not retain D11 path: minted=%d submitted=%+v stats=%+v",
			minter.calls, submitter.submitted, p.Stats())
	}
}

type d11FixedZoneEvaluator11017 struct{ evaluation ZoneEvaluation }

func (e d11FixedZoneEvaluator11017) Evaluate(CaptureOrigin, ZoneSnapshotRef) ZoneEvaluation {
	return e.evaluation
}

type d11CurrentZoneSnapshot11017 struct{ current bool }

func (d11CurrentZoneSnapshot11017) ResolveSTN(string) ZoneResolution {
	return ZoneResolution{ZoneID: 1, IfID: 7, Reason: ZoneReasonZoned}
}
func (d11CurrentZoneSnapshot11017) Generations() (uint64, uint32) { return 1, 1 }
func (s d11CurrentZoneSnapshot11017) Current() bool               { return s.current }

func TestD11ValidationDenialsCountOnlyDeliveredReason52Events11017(t *testing.T) {
	tests := []struct {
		name      string
		hook      CaptureHook
		evaluator ZoneEvaluator
		snapshot  ZoneSnapshotRef
		reason    IpsecInnerReason
	}{
		{
			name: "zone unzoned", hook: CaptureHookForward,
			evaluator: d11FixedZoneEvaluator11017{evaluation: ZoneEvaluation{
				Decision: ZoneDrop, Reason: ZoneReasonUnzoned,
			}},
			snapshot: d11CurrentZoneSnapshot11017{current: true}, reason: ReasonZoneUnzoned,
		},
		{
			name: "stale generation", hook: CaptureHookForward,
			evaluator: passZoneEvaluator9506{},
			snapshot:  d11CurrentZoneSnapshot11017{current: false}, reason: ReasonStaleGeneration,
		},
		{
			name: "evaluator unavailable", hook: CaptureHookForward,
			snapshot: d11CurrentZoneSnapshot11017{current: true}, reason: ReasonEvaluatorUnavailable,
		},
		{
			name: "unsupported hook", hook: CaptureHookInput,
			evaluator: passZoneEvaluator9506{},
			snapshot:  d11CurrentZoneSnapshot11017{current: true}, reason: ReasonUnsupportedHook,
		},
	}
	for _, tc := range tests {
		for _, delivered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/delivered-%v", tc.name, delivered), func(t *testing.T) {
				ledger := NewD11AttestationLedger()
				ledger.Begin("node-a", "attest-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 9)
				var attempted, events []IpsecInnerDeny
				p := &CapturePipeline{
					submitter: new(pipelineTestSubmitter),
					attestation: &D11AttestationConfig{
						Ledger: ledger,
						OriginValid: func(CaptureOrigin) bool { return true },
						AuthorityCurrent: func() bool { return true },
					},
					zoneEvaluator: tc.evaluator, zoneSnapshot: tc.snapshot,
					denyEvents: DenyEventSinkFunc(func(event IpsecInnerDeny) bool {
						attempted = append(attempted, event)
						if delivered {
							events = append(events, event)
						}
						return delivered
					}),
					sink: new(pipelineTestSink), flows: make(map[string]*flowState),
					pending: make(map[uint64]*pendingReinject),
				}
				p.attestSubmit([]CaptureFrame{d11IngressFrame11016(tc.hook, "deny", 21)})
				if len(attempted) != 1 || attempted[0].Reason != tc.reason ||
					len(events) != boolInt11017(delivered) {
					t.Fatalf("deny attempts=%+v delivered events=%+v, want reason=%s delivered=%v",
						attempted, events, tc.reason, delivered)
				}
				wantMetric := uint64(0)
				if delivered && tc.reason == ReasonEvaluatorUnavailable {
					wantMetric = 1
				}
				if got := p.Stats().D11Deny52; got != wantMetric {
					t.Fatalf("D11Deny52=%d, want %d for delivered=%v reason=%s",
						got, wantMetric, delivered, tc.reason)
				}
			})
		}
	}
}

func boolInt11017(value bool) int {
	if value {
		return 1
	}
	return 0
}
