package grpcapi

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockPacketDropStream is a minimal grpc.ServerStreamingServer used to drive
// MonitorPacketDrop's validation. It carries a context so a request that
// passes validation exits the stream loop via ctx.Done() instead of blocking.
type mockPacketDropStream struct {
	ctx  context.Context
	sent []string
}

func (m *mockPacketDropStream) Send(r *pb.MonitorPacketDropResponse) error {
	m.sent = append(m.sent, r.Line)
	return nil
}
func (m *mockPacketDropStream) Context() context.Context     { return m.ctx }
func (m *mockPacketDropStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockPacketDropStream) SendHeader(metadata.MD) error { return nil }
func (m *mockPacketDropStream) SetTrailer(metadata.MD)       {}
func (m *mockPacketDropStream) SendMsg(any) error            { return nil }
func (m *mockPacketDropStream) RecvMsg(any) error            { return nil }

func packetDropTestStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.1.1/24; }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces ge-0/0/0.0; }
        security-zone untrust;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMonitorPacketDropRejectsInvalidInputs guards #3382: MonitorPacketDrop is
// a local-only stream that must reject impossible/unknown filters with
// InvalidArgument rather than opening a stream that can never match (a silent
// empty stream during incident response).
//
// FAIL-ON-REVERT: removing the validation block lets each of these requests
// subscribe and (for the cancelled context) return context.Canceled instead of
// InvalidArgument.
func TestMonitorPacketDropRejectsInvalidInputs(t *testing.T) {
	s := &Server{store: packetDropTestStore(t), eventBuf: logging.NewEventBuffer(16)}

	cases := []struct {
		name string
		req  *pb.MonitorPacketDropRequest
	}{
		{"non-local node", &pb.MonitorPacketDropRequest{Node: "1"}},
		{"node all", &pb.MonitorPacketDropRequest{Node: "all"}},
		{"negative count", &pb.MonitorPacketDropRequest{Count: -1}},
		{"count over cap", &pb.MonitorPacketDropRequest{Count: 9000}},
		{"source-port over 65535", &pb.MonitorPacketDropRequest{SourcePort: 70000}},
		{"destination-port over 65535", &pb.MonitorPacketDropRequest{DestinationPort: 99999}},
		{"unknown protocol", &pb.MonitorPacketDropRequest{Protocol: "tpc"}},
		{"unknown from-zone", &pb.MonitorPacketDropRequest{FromZone: "trsut"}},
		{"unknown interface", &pb.MonitorPacketDropRequest{Interface: "ge-0/0/99"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A bounded context so a fail-on-revert (validation removed)
			// surfaces as a fast DeadlineExceeded instead of a hang: with
			// validation present the call returns InvalidArgument before it
			// ever subscribes, so the timeout is never reached.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream := &mockPacketDropStream{ctx: ctx}
			err := s.MonitorPacketDrop(tc.req, stream)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("MonitorPacketDrop(%+v) code = %v, want InvalidArgument (err=%v)", tc.req, status.Code(err), err)
			}
		})
	}
}

// TestMonitorPacketDropAcceptsValidInputs proves the validation does not reject
// legitimate filters: a valid request passes validation, subscribes, and exits
// via the cancelled context (context.Canceled), never InvalidArgument.
func TestMonitorPacketDropAcceptsValidInputs(t *testing.T) {
	s := &Server{store: packetDropTestStore(t), eventBuf: logging.NewEventBuffer(16)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the stream loop returns immediately

	req := &pb.MonitorPacketDropRequest{
		Node:            "local",
		Count:           100,
		SourcePort:      443,
		DestinationPort: 80,
		Protocol:        "TCP",
		FromZone:        "trust",
		Interface:       "ge-0/0/0",
	}
	stream := &mockPacketDropStream{ctx: ctx}
	err := s.MonitorPacketDrop(req, stream)
	if status.Code(err) == codes.InvalidArgument {
		t.Fatalf("MonitorPacketDrop(valid) = InvalidArgument (%v), want it to pass validation", err)
	}
	if err != context.Canceled {
		t.Fatalf("MonitorPacketDrop(valid) err = %v, want context.Canceled (validation passed, loop exited)", err)
	}
}

// runPacketDropUntilMatch runs MonitorPacketDrop with count=1 in a goroutine,
// adds the supplied record once the subscription is live, and returns the
// matcher result: (matched, line). It bounds the wait so a fail-on-revert
// (validated-but-never-matches) surfaces as matched==false within the timeout
// instead of hanging. The cross-goroutine read of stream.sent is safe because
// the result channel send/receive establishes happens-before.
func runPacketDropUntilMatch(t *testing.T, s *Server, eb *logging.EventBuffer, req *pb.MonitorPacketDropRequest, rec logging.EventRecord) (bool, string) {
	t.Helper()
	req.Count = 1
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := &mockPacketDropStream{ctx: ctx}
	errc := make(chan error, 1)
	go func() { errc <- s.MonitorPacketDrop(req, stream) }()

	// Let the RPC subscribe (it Subscribes then sends "Starting packet
	// drop:") before publishing the record, so the fan-out reaches it.
	time.Sleep(100 * time.Millisecond)
	eb.Add(rec)

	err := <-errc
	if err != nil {
		// count=1 returns nil on a match; a non-nil error (e.g. the 3s
		// DeadlineExceeded) means the record never matched.
		return false, ""
	}
	// stream.sent[0] is the "Starting packet drop:" banner; the matched
	// record is the next line.
	for _, line := range stream.sent {
		if line != "Starting packet drop:" {
			return true, line
		}
	}
	return false, ""
}

// TestMonitorPacketDropProtocolMatches guards the #3382 matcher fix (Codex
// MAJOR 1 + 3rd-round follow-up): the protocol filter must match against the
// numeric protocol the RECORD carries, not a re-parse of the rendered name.
//
//   - "6"/"tcp"/"TCP" all match a TCP drop (rec.Protocol="TCP", num 6).
//   - "41" matches an IPv6-encap drop (rec.Protocol="IPV6", num 41). This is
//     the case the re-parse approach got WRONG: protoName(41)="IPV6" but
//     appid.ProtocolNumber("ipv6") is deliberately one-way, so re-parsing
//     rec.Protocol dropped every proto-41 record.
//
// FAIL-ON-REVERT: comparing by re-parsed rec.Protocol makes the proto-41 case
// never match (RED), and the old strings.EqualFold compare makes the numeric
// "6" case never match "TCP".
func TestMonitorPacketDropProtocolMatches(t *testing.T) {
	cases := []struct {
		name     string
		reqProto string
		recName  string
		recNum   uint8
	}{
		{"numeric tcp", "6", "TCP", 6},
		{"lower tcp", "tcp", "TCP", 6},
		{"upper tcp", "TCP", "TCP", 6},
		{"numeric ipv6-encap", "41", "IPV6", 41}, // protoName non-reversible
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eb := logging.NewEventBuffer(16)
			s := &Server{store: packetDropTestStore(t), eventBuf: eb}
			rec := logging.EventRecord{
				Type: "POLICY_DENY", Protocol: tc.recName, ProtocolNum: tc.recNum,
				SrcAddr: "1.2.3.4:1000", DstAddr: "5.6.7.8:80",
			}
			matched, _ := runPacketDropUntilMatch(t, s, eb, &pb.MonitorPacketDropRequest{Protocol: tc.reqProto}, rec)
			if !matched {
				t.Fatalf("protocol filter %q did not match a %s drop (num %d); matcher is accepted-but-never-matches",
					tc.reqProto, tc.recName, tc.recNum)
			}
		})
	}
}

// TestMonitorPacketDropInterfaceAliasMatches guards the #3382 matcher fix
// (Codex MAJOR 2): the config-key interface form ("ge-0/0/0") must match a
// record whose IngressIface is the Linux form ("ge-0-0-0").
//
// FAIL-ON-REVERT: the old exact rec.IngressIface != req.Interface compare makes
// the config-key form never match the Linux-form record, so matched is false.
func TestMonitorPacketDropInterfaceAliasMatches(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	s := &Server{store: packetDropTestStore(t), eventBuf: eb}
	rec := logging.EventRecord{
		Type: "POLICY_DENY", Protocol: "TCP",
		SrcAddr: "1.2.3.4:1000", DstAddr: "5.6.7.8:80",
		IngressIface: "ge-0-0-0", // Linux form, as resolveIfName stores it
	}
	matched, _ := runPacketDropUntilMatch(t, s, eb, &pb.MonitorPacketDropRequest{Interface: "ge-0/0/0"}, rec)
	if !matched {
		t.Fatal("config-key interface ge-0/0/0 did not match a record with IngressIface ge-0-0-0; matcher is accepted-but-never-matches")
	}
}

type blockingOverrunPacketDropStream struct {
	ctx     context.Context
	mu      sync.Mutex
	sent    []string
	blocked bool
	parked  chan struct{}
	release chan struct{}
}

func (m *blockingOverrunPacketDropStream) Send(r *pb.MonitorPacketDropResponse) error {
	m.mu.Lock()
	m.sent = append(m.sent, r.Line)
	block := r.Line != "Starting packet drop:" && !m.blocked
	if block {
		m.blocked = true
	}
	m.mu.Unlock()
	if block {
		close(m.parked)
		<-m.release
	}
	return nil
}
func (m *blockingOverrunPacketDropStream) Context() context.Context     { return m.ctx }
func (m *blockingOverrunPacketDropStream) SetHeader(metadata.MD) error  { return nil }
func (m *blockingOverrunPacketDropStream) SendHeader(metadata.MD) error { return nil }
func (m *blockingOverrunPacketDropStream) SetTrailer(metadata.MD)       {}
func (m *blockingOverrunPacketDropStream) SendMsg(any) error            { return nil }
func (m *blockingOverrunPacketDropStream) RecvMsg(any) error            { return nil }
func (m *blockingOverrunPacketDropStream) hasLine(line string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sent := range m.sent {
		if sent == line {
			return true
		}
	}
	return false
}
func (m *blockingOverrunPacketDropStream) lines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.sent...)
}

func TestMonitorPacketDropReportsSubscriberOverrun_10834(t *testing.T) {
	eb := logging.NewEventBuffer(512)
	s := &Server{store: packetDropTestStore(t), eventBuf: eb}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &blockingOverrunPacketDropStream{
		ctx: ctx, parked: make(chan struct{}), release: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		done <- s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{Node: "local", Count: 2}, stream)
	}()

	startDeadline := time.Now().Add(2 * time.Second)
	for !stream.hasLine("Starting packet drop:") && time.Now().Before(startDeadline) {
		time.Sleep(time.Millisecond)
	}
	if !stream.hasLine("Starting packet drop:") {
		t.Fatal("packet-drop stream did not start")
	}

	eb.Add(logging.EventRecord{
		Time: time.Now(), Type: "POLICY_DENY", SrcAddr: "10.0.1.1:1000",
		DstAddr: "10.0.2.1:80", Protocol: "TCP", Action: "deny",
	})
	select {
	case <-stream.parked:
	case <-time.After(2 * time.Second):
		t.Fatal("packet-drop stream did not park on its first event")
	}
	const storm = 300
	for range storm {
		eb.Add(logging.EventRecord{
			Time: time.Now(), Type: "POLICY_DENY", SrcAddr: "10.0.1.1:1000",
			DstAddr: "10.0.2.1:80", Protocol: "TCP", Action: "deny",
		})
	}
	dropped := eb.DroppedTotal()
	if dropped == 0 {
		t.Fatal("bounded event storm did not overrun the blocked packet-drop subscriber")
	}
	close(stream.release)

	marker := logging.OverrunLine(dropped)
	deadline := time.Now().Add(2 * time.Second)
	for !stream.hasLine(marker) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("packet-drop stream did not finish after reporting the gap")
	}

	lines := stream.lines()
	if !stream.hasLine(marker) {
		t.Fatalf("packet-drop stream omitted gap marker %q: %v", marker, lines)
	}
	if final := fmt.Sprintf("dropped=%d", dropped); !stream.hasLine(final) {
		t.Errorf("packet-drop stream omitted final drop count %q: %v", final, lines)
	}
	if got := uint64(storm+1) - dropped; got != 257 {
		t.Errorf("published accounting: expected 257 delivered and %d dropped, got 301 published", dropped)
	}
}
