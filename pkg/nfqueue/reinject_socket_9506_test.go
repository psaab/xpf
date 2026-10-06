package nfqueue

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type shortWriteConn struct {
	bytes.Buffer
}

func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (c *shortWriteConn) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return c.Buffer.Write(data[:1])
}

type dummyAddr string

func (a dummyAddr) Network() string { return "test" }
func (a dummyAddr) String() string  { return string(a) }

func TestReinjectSocketWriteHandlesShortWrites9506(t *testing.T) {
	conn := new(shortWriteConn)
	if err := writeReinjectMessage(conn, reinjectMsgCancel, []byte{1, 2, 3}, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := conn.Bytes(); len(got) != 8 || binary.BigEndian.Uint32(got[:4]) != 4 || got[4] != reinjectMsgCancel || !bytes.Equal(got[5:], []byte{1, 2, 3}) {
		t.Fatalf("wire bytes=%v, want framed cancel payload", got)
	}
}

func TestReinjectSocketDecodesExtendedCompletionOutcomes9506(t *testing.T) {
	want := map[byte]CompletionOutcome{
		6:  CompletionFenced,
		7:  CompletionDenied,
		8:  CompletionAccepted,
		9:  CompletionWouldReinject,
		10: CompletionWouldPermit,
	}
	for code, expected := range want {
		payload := make([]byte, 2+37)
		binary.BigEndian.PutUint16(payload[:2], 1)
		payload[2+32] = code
		completions, err := decodeCompletions(payload)
		if err != nil {
			t.Fatalf("code %d: decode completions: %v", code, err)
		}
		if len(completions) != 1 || completions[0].Outcome != expected {
			t.Fatalf("code %d: completions=%+v, want %s", code, completions, expected)
		}
	}
}

func TestReinjectSocketDecodesWrittenAndExtendedBatch9506(t *testing.T) {
	codes := []byte{1, 6, 7, 8, 9, 10}
	payload := make([]byte, 2+len(codes)*37)
	binary.BigEndian.PutUint16(payload[:2], uint16(len(codes)))
	for i, code := range codes {
		off := 2 + i*37
		binary.BigEndian.PutUint64(payload[off:off+8], uint64(i+1))
		binary.BigEndian.PutUint16(payload[off+24:off+26], uint16(100+i))
		payload[off+32] = code
		binary.BigEndian.PutUint32(payload[off+33:off+37], uint32(i+10))
	}
	completions, err := decodeCompletions(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(completions) != len(codes) {
		t.Fatalf("completions=%d, want %d", len(completions), len(codes))
	}
	want := []CompletionOutcome{
		CompletionWritten,
		CompletionFenced,
		CompletionDenied,
		CompletionAccepted,
		CompletionWouldReinject,
		CompletionWouldPermit,
	}
	for i, completion := range completions {
		if completion.Outcome != want[i] || completion.BytesWritten != uint32(i+10) {
			t.Fatalf("completion[%d]=%+v, want outcome=%s bytes=%d", i, completion, want[i], i+10)
		}
	}
}

func TestReinjectSocketAdmissionReasonConsistencyFailsClosed9506(t *testing.T) {
	for _, code := range []byte{reinjectAdmitNoGeneration, reinjectAdmitTunnelRowMissing, 99} {
		t.Run(fmt.Sprintf("reason-%d", code), func(t *testing.T) {
			payload := make([]byte, 2+34)
			binary.BigEndian.PutUint16(payload[:2], 1)
			payload[2+32] = 1
			payload[2+33] = code
			admissions, err := decodeAdmissions(payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(admissions) != 1 {
				t.Fatalf("admissions=%d, want one row", len(admissions))
			}
			if admissions[0].Admitted || admissions[0].ReasonCode != code {
				t.Fatalf("admission=%+v, want refusal for non-OK reason", admissions[0])
			}
		})
	}
}

func TestEncodeSubmitBatchPMechTailTwoFrames9506(t *testing.T) {
	origin := CaptureOrigin{
		Family: CaptureFamilyInet, Hook: CaptureHookForward,
		Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
	}
	frames := []AdjudicatedFrame{
		{
			Frame: CaptureFrame{
				Packet:                        pipelineTestPacket(77, 2, 2, 7, 1),
				FlowKey:                       "flow-a",
				SnapshotGeneration:            11,
				ConfigGeneration:              12,
				FIBGeneration:                 13,
				PMechInventoryGeneration:      14,
				PMechInventoryFIBGeneration:  15,
				PMechPolicyIdentity:           [32]byte{0: 0x41, 31: 0x4a},
			},
			Origin: origin,
			Lease:  ReinjectLease{RequestID: 1, PermitEpoch: 2, QueueNumber: 77, QueueEpoch: 3},
			ZoneID: 4,
			IfID:   7,
			DeadlineMonoNS:  0x0102030405060708,
			DeadlineClockID: reinjectDeadlineClockMonotonic,
		},
		{
			Frame: CaptureFrame{
				Packet:                        pipelineTestPacket(77, 2, 2, 7, 2),
				FlowKey:                       "flow-b",
				SnapshotGeneration:            21,
				ConfigGeneration:              22,
				FIBGeneration:                 23,
				PMechInventoryGeneration:      24,
				PMechInventoryFIBGeneration:  25,
				PMechPolicyIdentity:           [32]byte{0: 0x51, 31: 0x5a},
			},
			Origin: origin,
			Lease:  ReinjectLease{RequestID: 2, PermitEpoch: 3, QueueNumber: 77, QueueEpoch: 4},
			ZoneID: 5,
			IfID:   8,
			DeadlineMonoNS:  0x1112131415161718,
			DeadlineClockID: reinjectDeadlineClockMonotonic,
		},
	}
	payload, err := encodeSubmitBatch(frames)
	if err != nil {
		t.Fatal(err)
	}
	const fixedRowLen = 8 + 8 + 8 + 2 + 8 + 3 + 4
	rowLen := fixedRowLen + 1 + len(origin.Owner) + 1 + len(origin.STN) +
		4 + len(frames[0].Frame.Packet.Payload()) + reinjectSubmitPMechTailLen
	if want := 2 + 2*rowLen; len(payload) != want {
		t.Fatalf("payload length=%d, want %d", len(payload), want)
	}
	tail := 2 + rowLen - reinjectSubmitPMechTailLen
	if got := binary.BigEndian.Uint64(payload[tail : tail+8]); got != 11 {
		t.Fatalf("first snapshot generation=%d, want 11", got)
	}
	if got := binary.BigEndian.Uint64(payload[tail+8 : tail+16]); got != 12 {
		t.Fatalf("first config generation=%d, want 12", got)
	}
	if got := binary.BigEndian.Uint32(payload[tail+16 : tail+20]); got != 13 {
		t.Fatalf("first FIB generation=%d, want 13", got)
	}
	if got := binary.BigEndian.Uint16(payload[tail+20 : tail+22]); got != 4 {
		t.Fatalf("first zone ID=%d, want 4", got)
	}
	if got := binary.BigEndian.Uint32(payload[tail+22 : tail+26]); got != 7 {
		t.Fatalf("first if ID=%d, want 7", got)
	}
	if got := binary.BigEndian.Uint64(payload[tail+26 : tail+34]); got != 14 {
		t.Fatalf("first P-MECH inventory generation=%d, want 14", got)
	}
	if got := binary.BigEndian.Uint32(payload[tail+34 : tail+38]); got != 15 {
		t.Fatalf("first P-MECH inventory FIB generation=%d, want 15", got)
	}
	if got := payload[tail+38 : tail+70]; !bytes.Equal(got, frames[0].Frame.PMechPolicyIdentity[:]) {
		t.Fatalf("first P-MECH policy identity=%x, want %x", got, frames[0].Frame.PMechPolicyIdentity)
	}
	if got := binary.BigEndian.Uint64(payload[tail+70 : tail+78]); got != frames[0].DeadlineMonoNS {
		t.Fatalf("first monotonic deadline=%x, want %x", got, frames[0].DeadlineMonoNS)
	}
	if got := payload[tail+78]; got != reinjectDeadlineClockMonotonic {
		t.Fatalf("first deadline clock id=%d, want %d", got, reinjectDeadlineClockMonotonic)
	}
	second := 2 + rowLen
	if got := binary.BigEndian.Uint64(payload[second : second+8]); got != 2 {
		t.Fatalf("second request ID=%d, want 2 (tail boundary=%d)", got, tail)
	}
}

func TestReinjectSubmitGoRustPinnedLayout9506(t *testing.T) {
	frame := AdjudicatedFrame{
		Frame: CaptureFrame{
			Packet: pipelineTestPacket(9, 2, 2, 42, 0), FlowKey: "flow-a",
			SnapshotGeneration: 13, ConfigGeneration: 17, FIBGeneration: 19,
			PMechInventoryGeneration: 31, PMechInventoryFIBGeneration: 32,
		},
		Origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner", STN: "stn", OwnedIfindex: 42,
		},
		Lease: ReinjectLease{RequestID: 1, PermitEpoch: 7, QueueNumber: 9, QueueEpoch: 11},
		ZoneID: 23, IfID: 29,
		DeadlineMonoNS:  0x0102030405060708,
		DeadlineClockID: reinjectDeadlineClockMonotonic,
	}
	for i := range frame.Frame.PMechPolicyIdentity {
		frame.Frame.PMechPolicyIdentity[i] = 0x41
	}
	payload, err := encodeSubmitBatch([]AdjudicatedFrame{frame})
	if err != nil {
		t.Fatal(err)
	}
	const pinnedGoRustVector = "000100000000000000010000000000000007000000000000000b0009641d379cc20483cb0001010000002a056f776e65720373746e000000024500000000000000000d00000000000000110000001300170000001d000000000000001f000000204141414141414141414141414141414141414141414141414141414141414141010203040506070801"
	want, err := hex.DecodeString(pinnedGoRustVector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("submit vector=%x, want pinned Go/Rust bytes %x", payload, want)
	}
	const explicitTailStart = 59
	if len(payload) != 138 || reinjectSubmitPMechTailLen != 79 {
		t.Fatalf("pinned frame length=%d, tail const=%d, want 138/79", len(payload), reinjectSubmitPMechTailLen)
	}
	if got := binary.BigEndian.Uint64(payload[explicitTailStart+70 : explicitTailStart+78]); got != 0x0102030405060708 {
		t.Fatalf("pinned deadline at 70..77=%x", got)
	}
	if got := payload[explicitTailStart+78]; got != 1 {
		t.Fatalf("pinned clock id at 78=%d, want 1", got)
	}
}

func TestStampReinjectDeadlineFailsClosed9506(t *testing.T) {
	clockCalls := 0
	clock := func(clockID int32, ts *unix.Timespec) error {
		clockCalls++
		if clockID != unix.CLOCK_MONOTONIC {
			t.Fatalf("clock id=%d, want CLOCK_MONOTONIC", clockID)
		}
		ts.Sec = 12
		ts.Nsec = 345
		return nil
	}
	got, err := stampReinjectDeadlineWithClock(5*time.Millisecond, clock)
	if err != nil || got != 12_005_000_345 || clockCalls != 1 {
		t.Fatalf("stamp=(%d,%v) calls=%d, want 12005000345, nil, 1", got, err, clockCalls)
	}
	got, err = stampReinjectDeadlineWithClock(reinjectMaxAckDeadline, func(_ int32, ts *unix.Timespec) error {
		ts.Sec = 12
		ts.Nsec = 345
		return nil
	})
	if err != nil || got != 13_000_000_345 {
		t.Fatalf("1s stamp=(%d,%v), want 13000000345, nil", got, err)
	}
	for _, deadline := range []time.Duration{0, -1, reinjectMaxAckDeadline + 1} {
		callsBefore := clockCalls
		if _, err := stampReinjectDeadlineWithClock(deadline, clock); err == nil {
			t.Fatalf("AckDeadline=%s accepted", deadline)
		}
		if clockCalls != callsBefore {
			t.Fatalf("invalid AckDeadline=%s sampled the clock", deadline)
		}
	}
	if _, err := stampReinjectDeadlineWithClock(time.Millisecond, func(_ int32, ts *unix.Timespec) error {
		*ts = unix.Timespec{}
		return nil
	}); err == nil {
		t.Fatal("zero monotonic sample accepted")
	}
	clockErr := errors.New("clock failure")
	if _, err := stampReinjectDeadlineWithClock(time.Millisecond, func(int32, *unix.Timespec) error {
		return clockErr
	}); !errors.Is(err, clockErr) {
		t.Fatalf("clock failure=%v, want %v", err, clockErr)
	}
}

func TestReinjectSocketRoundTripAndCompletion9506(t *testing.T) {
	dir := t.TempDir()
	submitPath := filepath.Join(dir, "submit.sock")
	completePath := filepath.Join(dir, "complete.sock")
	submitListener, err := net.Listen("unix", submitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer submitListener.Close()
	completeListener, err := net.Listen("unix", completePath)
	if err != nil {
		t.Fatal(err)
	}
	defer completeListener.Close()

	submitServer := make(chan error, 1)
	go func() {
		conn, err := submitListener.Accept()
		if err != nil {
			submitServer <- err
			return
		}
		defer conn.Close()
		typ, payload, err := readReinjectMessage(conn)
		if err != nil {
			submitServer <- err
			return
		}
		if typ != reinjectMsgSubmitBatch || len(payload) < 2 || binary.BigEndian.Uint16(payload[:2]) != 1 {
			submitServer <- errors.New("unexpected submit batch")
			return
		}
		admit := make([]byte, 2+34)
		binary.BigEndian.PutUint16(admit[:2], 1)
		binary.BigEndian.PutUint64(admit[2+0:2+8], 41)
		binary.BigEndian.PutUint64(admit[2+8:2+16], 5)
		binary.BigEndian.PutUint64(admit[2+16:2+24], 9)
		binary.BigEndian.PutUint16(admit[2+24:2+26], 77)
		admit[2+26] = reinjectOriginInet
		admit[2+27] = reinjectOriginForward
		binary.BigEndian.PutUint32(admit[2+28:2+32], 7)
		admit[2+32] = 1
		if err := writeReinjectMessage(conn, reinjectMsgAdmit, admit, time.Second); err != nil {
			submitServer <- err
			return
		}
		typ, payload, err = readReinjectMessage(conn)
		if err != nil {
			submitServer <- err
			return
		}
		if typ != reinjectMsgCancel || len(payload) < 1 || payload[0]&0x01 == 0 {
			submitServer <- errors.New("unexpected cancel message")
			return
		}
		submitServer <- nil
	}()

	completeServer := make(chan error, 1)
	go func() {
		conn, err := completeListener.Accept()
		if err != nil {
			completeServer <- err
			return
		}
		defer conn.Close()
		completion := make([]byte, 2+37)
		binary.BigEndian.PutUint16(completion[:2], 1)
		binary.BigEndian.PutUint64(completion[2+0:2+8], 41)
		binary.BigEndian.PutUint64(completion[2+8:2+16], 5)
		binary.BigEndian.PutUint64(completion[2+16:2+24], 9)
		binary.BigEndian.PutUint16(completion[2+24:2+26], 77)
		completion[2+26] = reinjectOriginInet
		completion[2+27] = reinjectOriginForward
		binary.BigEndian.PutUint32(completion[2+28:2+32], 7)
		completion[2+32] = 1
		binary.BigEndian.PutUint32(completion[2+33:2+37], 2)
		completeServer <- writeReinjectMessage(conn, reinjectMsgComplete, completion, time.Second)
	}()

	client := &SocketReinjectSubmitter{
		submitPath: submitPath, completePath: completePath, timeout: time.Second,
	}
	frame := AdjudicatedFrame{
		Frame: CaptureFrame{
			Packet:  pipelineTestPacket(77, 2, 2, 7, 41),
			FlowKey: "flow-41",
		},
		Origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		Lease: ReinjectLease{RequestID: 41, PermitEpoch: 5, QueueNumber: 77, QueueEpoch: 9},
		DeadlineMonoNS:  0x0102030405060708,
		DeadlineClockID: reinjectDeadlineClockMonotonic,
	}
	admissions, err := client.SubmitAdjudicated([]AdjudicatedFrame{frame})
	if err != nil {
		t.Fatal(err)
	}
	if len(admissions) != 1 || !admissions[0].Admitted || admissions[0].OwnedIfindex != 7 {
		t.Fatalf("admissions=%+v, want one admitted origin", admissions)
	}
	completions, err := client.DrainReinjectCompletions(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(completions) != 1 || completions[0].Outcome != CompletionWritten || completions[0].BytesWritten != 2 {
		t.Fatalf("completions=%+v, want one written completion", completions)
	}
	if _, err := client.CancelReinject([]uint64{41}, 5, []ReinjectQueueScope{{QueueNumber: 77, QueueEpoch: 9}}); err != nil {
		t.Fatal(err)
	}
	if err := <-submitServer; err != nil {
		t.Fatal(err)
	}
	if err := <-completeServer; err != nil {
		t.Fatal(err)
	}
}

func TestReinjectSocketAdmissionDeadline9506(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverRead := make(chan error, 1)
	go func() {
		_, _, err := readReinjectMessage(server)
		serverRead <- err
	}()
	stub := &SocketReinjectSubmitter{timeout: 5 * time.Millisecond}
	_, err := stub.roundTripLocked(client, reinjectMsgSubmitBatch, []byte{0, 0})
	if err == nil || !isTimeout(err) {
		t.Fatalf("roundTrip error=%v, want timeout", err)
	}
	if err := <-serverRead; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("server read=%v", err)
	}
}

func TestReinjectSocketCompletionTimeoutResetsPartialFrame9506(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "complete.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte{0, 0})
		time.Sleep(20 * time.Millisecond)
	}()

	client := &SocketReinjectSubmitter{
		completePath: path,
		timeout:      5 * time.Millisecond,
	}
	if completions, err := client.DrainReinjectCompletions(1); err != nil || completions != nil {
		t.Fatalf("partial completion read=(%v, %v), want timeout-as-empty", completions, err)
	}
	client.completeMu.Lock()
	reset := client.complete == nil
	client.completeMu.Unlock()
	if !reset {
		t.Fatal("partial completion timeout retained a desynchronized stream")
	}
	<-serverDone
}
