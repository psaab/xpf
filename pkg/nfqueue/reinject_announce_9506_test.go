package nfqueue

import (
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestAnnounceReinjectPublishesPersistentAuthorityFrames9506(t *testing.T) {
	dir := t.TempDir()
	submitPath := filepath.Join(dir, "reinject-submit.sock")
	listener, err := net.Listen("unix", submitPath)
	if err != nil {
		t.Fatalf("listen submit socket: %v", err)
	}
	defer listener.Close()
	frames := make(chan []byte, 2)
	errs := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errs <- acceptErr
			return
		}
		defer conn.Close()
		for i := 0; i < 2; i++ {
			typ, payload, readErr := readReinjectMessage(conn)
			if readErr != nil {
				errs <- readErr
				return
			}
			if typ != reinjectMsgAnnounce {
				errs <- errors.New("unexpected announce message type")
				return
			}
			frames <- payload
		}
	}()

	client, err := NewSocketReinjectSubmitter(submitPath, filepath.Join(dir, "unused-complete.sock"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.AnnounceReinject(7, true, []ReinjectQueueEpoch{{Queue: 12, Epoch: 31}}); err != nil {
		t.Fatalf("open announce: %v", err)
	}
	if err := client.AnnounceReinject(7, false, []ReinjectQueueEpoch{{Queue: 12, Epoch: 31}}); err != nil {
		t.Fatalf("close announce: %v", err)
	}
	defer client.Close()

	for i, wantOpen := range []byte{1, 0} {
		select {
		case err := <-errs:
			t.Fatalf("server frame %d: %v", i, err)
		case payload := <-frames:
			if len(payload) != 21 {
				t.Fatalf("frame %d payload length=%d, want 21", i, len(payload))
			}
			if got := binary.BigEndian.Uint64(payload[:8]); got != 7 {
				t.Fatalf("frame %d permit=%d, want 7", i, got)
			}
			if payload[8] != wantOpen {
				t.Fatalf("frame %d open=%d, want %d", i, payload[8], wantOpen)
			}
			if got := binary.BigEndian.Uint16(payload[9:11]); got != 1 {
				t.Fatalf("frame %d queue count=%d, want 1", i, got)
			}
			if got := binary.BigEndian.Uint16(payload[11:13]); got != 12 {
				t.Fatalf("frame %d queue=%d, want 12", i, got)
			}
			if got := binary.BigEndian.Uint64(payload[13:21]); got != 31 {
				t.Fatalf("frame %d epoch=%d, want 31", i, got)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for frame %d", i)
		}
	}
}

func TestAnnounceReinjectReplaysLatestAuthorityBeforeSubmitAfterReconnect9506(t *testing.T) {
	dir := t.TempDir()
	submitPath := filepath.Join(dir, "reinject-submit.sock")
	listener, err := net.Listen("unix", submitPath)
	if err != nil {
		t.Fatalf("listen submit socket: %v", err)
	}
	defer listener.Close()
	events := make(chan string, 2)
	errs := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				errs <- acceptErr
				return
			}
			typ, _, readErr := readReinjectMessage(conn)
			if readErr != nil {
				_ = conn.Close()
				errs <- readErr
				return
			}
			if typ != reinjectMsgAnnounce {
				_ = conn.Close()
				errs <- errors.New("fresh submit connection did not receive authority replay first")
				return
			}
			if i == 0 {
				events <- "first-announce"
				_ = conn.Close()
				continue
			}
			events <- "replayed-announce"
			submitType, _, submitErr := readReinjectMessage(conn)
			if submitErr != nil {
				_ = conn.Close()
				errs <- submitErr
				return
			}
			if submitType != reinjectMsgSubmitBatch {
				_ = conn.Close()
				errs <- errors.New("submit did not follow replayed authority")
				return
			}
			admit := make([]byte, 2+34)
			binary.BigEndian.PutUint16(admit[:2], 1)
			binary.BigEndian.PutUint64(admit[2:10], 41)
			binary.BigEndian.PutUint64(admit[10:18], 7)
			binary.BigEndian.PutUint64(admit[18:26], 31)
			binary.BigEndian.PutUint16(admit[26:28], 12)
			admit[28] = reinjectOriginInet
			admit[29] = reinjectOriginForward
			binary.BigEndian.PutUint32(admit[30:34], 7)
			admit[34] = 1
			admit[35] = 0
			if writeErr := writeReinjectMessage(conn, reinjectMsgAdmit, admit, time.Second); writeErr != nil {
				errs <- writeErr
			}
			_ = conn.Close()
		}
	}()

	client, err := NewSocketReinjectSubmitter(submitPath, filepath.Join(dir, "unused-complete.sock"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	rows := []ReinjectQueueEpoch{{Queue: 12, Epoch: 31}}
	if err := client.AnnounceReinject(7, true, rows); err != nil {
		t.Fatalf("first announce: %v", err)
	}
	select {
	case err := <-errs:
		t.Fatalf("first connection: %v", err)
	case event := <-events:
		if event != "first-announce" {
			t.Fatalf("first event=%q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first authority frame")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}
	frame := AdjudicatedFrame{
		Frame: CaptureFrame{
			Packet:  pipelineTestPacket(12, 2, 2, 7, 41),
			FlowKey: "flow-41",
		},
		Origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		Lease: ReinjectLease{RequestID: 41, PermitEpoch: 7, QueueNumber: 12, QueueEpoch: 31},
	}
	admissions, err := client.SubmitAdjudicated([]AdjudicatedFrame{frame})
	if err != nil {
		t.Fatalf("submit after reconnect: %v", err)
	}
	if len(admissions) != 1 || !admissions[0].Admitted {
		t.Fatalf("admissions=%+v, want one admitted frame", admissions)
	}
	select {
	case err := <-errs:
		t.Fatalf("reconnect server: %v", err)
	case event := <-events:
		if event != "replayed-announce" {
			t.Fatalf("reconnect event=%q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for replayed authority before submit")
	}
}

func TestEncodeAnnounceRejectsDuplicateQueue9506(t *testing.T) {
	if _, err := encodeAnnounce(3, true, []ReinjectQueueEpoch{{Queue: 1, Epoch: 2}, {Queue: 1, Epoch: 3}}); err == nil {
		t.Fatal("duplicate queue authority must be rejected before socket write")
	}
}
