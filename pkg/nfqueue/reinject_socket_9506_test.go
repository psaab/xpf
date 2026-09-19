package nfqueue

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
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
		6: CompletionFenced,
		7: CompletionDenied,
		8: CompletionAccepted,
		9: CompletionWouldReinject,
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
