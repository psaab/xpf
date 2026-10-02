package userspace

import (
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

func TestStalledSyslogDoesNotParkEventReader11697(t *testing.T) {
	const records = 200

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	// Keep the advertised TCP receive window small before the handshake; the
	// collector deliberately never reads and the tiny window fills with the
	// 200 close records.
	rawConn, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	defer listener.Close()
	clientConn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientConn.SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}
	collectorConn, err := listener.AcceptTCP()
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	if err := collectorConn.SetReadBuffer(1024); err != nil {
		collectorConn.Close()
		clientConn.Close()
		t.Fatal(err)
	}
	defer collectorConn.Close() // Deliberately never read from the collector.

	client := logging.NewSyslogClientWithConn(clientConn, "tcp")
	client.Format = "structured"
	client.MinSeverity = logging.SyslogInfo
	client.Categories = logging.CategoryAll
	defer client.Close()
	reader := logging.NewEventReader(nil, logging.NewEventBuffer(records*2+8))
	reader.SetSyslogClients([]*logging.SyslogClient{client})
	reader.SetPolicyNames(map[uint32]string{77: strings.Repeat("p", 8192)})

	dir := t.TempDir()
	es := NewEventStream(filepath.Join(dir, "stalled-syslog.sock"))
	var latencyMu sync.Mutex
	sentAt := make(map[uint64]time.Time, records)
	latencies := make(chan time.Duration, records)
	var applied int
	es.SetOnEvent(func(_ uint8, seq uint64, _ SessionDeltaInfo) bool {
		latencyMu.Lock()
		start := sentAt[seq]
		applied++
		latencyMu.Unlock()
		if !start.IsZero() {
			latencies <- time.Since(start)
		}
		return true
	})
	appliedCount := func() int {
		latencyMu.Lock()
		defer latencyMu.Unlock()
		return applied
	}
	es.SetOnRawDataplaneEvent(func(_ uint64, payload []byte) {
		reader.ProcessRawEvent(payload)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer connectCancel()
	var conn net.Conn
	for conn == nil {
		conn, err = net.Dial("unix", es.socketPath)
		if err == nil {
			break
		}
		select {
		case <-connectCtx.Done():
			t.Fatalf("dial event stream: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer conn.Close()
	for !es.IsConnected() {
		select {
		case <-connectCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(time.Millisecond):
		}
	}

	closePayload := buildTypedDataplaneEventV4Payload(
		dataplane.EventTypeSessionClose, 0, 6, 12345, 443,
		[4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2},
		[4]byte{}, 0, 1, 2, 77, 0, 0, 0, 0, 0,
	)
	// SESSION_CLOSE's policy ID and syslog gate are additive fields outside the
	// dataplane.Event prefix used by the shared event formatter.
	binary.LittleEndian.PutUint32(closePayload[136:140], 77)
	closePayload[135] = 1
	deltaPayload := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2},
		[4]byte{}, [4]byte{}, 0, 0,
		1, 2, 3, 4, 5, 6, 0, 1, 2,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	for i := range records {
		closeSeq := uint64(i*2 + 1)
		deltaSeq := closeSeq + 1
		if err := writeFrame(conn, EventFrameTypeSessionClose, closeSeq, closePayload); err != nil {
			t.Fatalf("write close %d: %v", i, err)
		}
		latencyMu.Lock()
		sentAt[deltaSeq] = time.Now()
		latencyMu.Unlock()
		if err := writeFrame(conn, EventTypeSessionOpen, deltaSeq, deltaPayload); err != nil {
			t.Fatalf("write interleaved delta %d: %v", i, err)
		}
	}

	lastSeq := uint64(records * 2)
	deadline := time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() < lastSeq {
		if time.Now().After(deadline) {
			t.Fatalf("reader stalled at seq %d of %d; applied %d interleaved deltas",
				es.lastAppliedSeq.Load(), lastSeq, appliedCount())
		}
		time.Sleep(time.Millisecond)
	}
	if !es.IsConnected() {
		t.Fatal("stalled syslog collector closed the event stream")
	}
	if got := client.DroppedWrites(); got == 0 {
		t.Fatal("200 stalled-collector close records did not fill the bounded queue; DroppedWrites stayed zero")
	}

	got := make([]time.Duration, 0, records)
	for len(got) < records {
		select {
		case d := <-latencies:
			got = append(got, d)
		case <-time.After(time.Second):
			t.Fatalf("only %d/%d interleaved session deltas were applied", len(got), records)
		}
	}
	if got := appliedCount(); got != records {
		t.Fatalf("applied %d session deltas, want %d", got, records)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	p99 := got[(len(got)*99+99)/100-1]
	if p99 >= 50*time.Millisecond {
		t.Fatalf("interleaved session-delta p99 = %s, want <50ms", p99)
	}
}
