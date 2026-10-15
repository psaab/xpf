package nfqueue

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestDrainReinjectCompletionsRetainsOverflow13234 is the regression for
// #13234 (D5-03): a single reinjectMsgComplete frame carrying more than
// max entries must not lose the surplus. Earlier drains returning only
// completions[:max] discarded the rest after consuming the whole frame.
func TestDrainReinjectCompletionsRetainsOverflow13234(t *testing.T) {
	dir := t.TempDir()
	completePath := filepath.Join(dir, "complete.sock")
	listener, err := net.Listen("unix", completePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	const total = 5
	releaseServer := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		payload := make([]byte, 2+total*37)
		binary.BigEndian.PutUint16(payload[:2], total)
		for i := range total {
			off := 2 + i*37
			binary.BigEndian.PutUint64(payload[off:off+8], uint64(101+i))
			binary.BigEndian.PutUint64(payload[off+8:off+16], 9)
			binary.BigEndian.PutUint64(payload[off+16:off+24], 1)
			binary.BigEndian.PutUint16(payload[off+24:off+26], 77)
			payload[off+26] = reinjectOriginInet
			payload[off+27] = reinjectOriginForward
			binary.BigEndian.PutUint32(payload[off+28:off+32], 7)
			payload[off+32] = 1 // written
			binary.BigEndian.PutUint32(payload[off+33:off+37], 64)
		}
		serverDone <- writeReinjectMessage(conn, reinjectMsgComplete, payload, time.Second)
		<-releaseServer
	}()

	client := &SocketReinjectSubmitter{completePath: completePath, timeout: time.Second}
	defer client.Close()

	// First drain asks for fewer than the frame carries.
	first, err := client.DrainReinjectCompletions(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].RequestID != 101 || first[1].RequestID != 102 {
		t.Fatalf("first drain=%+v, want request IDs 101,102", first)
	}
	// Buffered remainder must be served before/without another socket read;
	// the server sent only one frame, so a re-read would time out empty.
	second, err := client.DrainReinjectCompletions(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 2 || second[0].RequestID != 103 || second[1].RequestID != 104 {
		t.Fatalf("second drain=%+v, want retained request IDs 103,104 (overflow lost if empty)", second)
	}
	third, err := client.DrainReinjectCompletions(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 1 || third[0].RequestID != 105 {
		t.Fatalf("third drain=%+v, want retained request ID 105", third)
	}
	// Buffer exhausted: next drain is a normal timeout-as-empty, no error.
	fourth, err := client.DrainReinjectCompletions(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(fourth) != 0 {
		t.Fatalf("fourth drain=%+v, want empty after buffer exhausted", fourth)
	}
	close(releaseServer)
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
