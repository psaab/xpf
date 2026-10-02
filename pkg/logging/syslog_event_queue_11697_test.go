package logging

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

type stalledSyslogEventConn11697 struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newStalledSyslogEventConn11697() *stalledSyslogEventConn11697 {
	return &stalledSyslogEventConn11697{entered: make(chan struct{}), release: make(chan struct{})}
}

func (c *stalledSyslogEventConn11697) Write(b []byte) (int, error) {
	c.enteredOnce.Do(func() { close(c.entered) })
	<-c.release
	return len(b), nil
}
func (c *stalledSyslogEventConn11697) Read([]byte) (int, error) { return 0, nil }
func (c *stalledSyslogEventConn11697) Close() error {
	c.releaseOnce.Do(func() { close(c.release) })
	return nil
}
func (c *stalledSyslogEventConn11697) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stalledSyslogEventConn11697) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stalledSyslogEventConn11697) SetDeadline(time.Time) error      { return nil }
func (c *stalledSyslogEventConn11697) SetReadDeadline(time.Time) error  { return nil }
func (c *stalledSyslogEventConn11697) SetWriteDeadline(time.Time) error { return nil }

func TestEventReaderSyslogQueueNeverBlocksAndCountsDrops11697(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	t.Cleanup(func() { _ = client.Close() })

	if !client.SendFromEventReader(SyslogInfo, "stalled collector") {
		t.Fatal("first event was not accepted")
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter the stalled connection")
	}

	start := time.Now()
	for range syslogEventQueueDepth * 2 {
		client.SendFromEventReader(SyslogInfo, "queued event")
	}
	if elapsed := time.Since(start); elapsed >= 50*time.Millisecond {
		t.Fatalf("reader-side enqueue batch took %s with a stalled writer, want <50ms", elapsed)
	}
	if got := client.DroppedWrites(); got == 0 {
		t.Fatal("bounded queue overflow was not counted in DroppedWrites")
	}
}

func TestEventReaderSyslogQueueRetirementCountsPending11697(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	if !client.SendFromEventReader(SyslogInfo, "in flight") {
		t.Fatal("first event was not accepted")
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter the stalled connection")
	}
	for range syslogEventQueueDepth {
		client.SendFromEventReader(SyslogInfo, "pending")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if got := client.DroppedWrites(); got != syslogEventQueueDepth {
		t.Fatalf("DroppedWrites after retirement = %d, want %d queued records", got, syslogEventQueueDepth)
	}
}

func TestEventReaderSlogSyslogDoesNotBlock11697(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	withSlogDefault(t, handler)
	t.Cleanup(handler.Close)

	reader := NewEventReader(nil, nil)
	raw := make([]byte, rawEventWireSize)
	raw[52] = eventTypePolicyDeny
	raw[53] = 6
	raw[55] = addrFamilyInet

	done := make(chan bool, 1)
	go func() { done <- reader.ProcessRawEvent(raw) }()
	select {
	case accepted := <-done:
		if !accepted {
			t.Fatal("event reader rejected the raw event")
		}
	case <-time.After(50 * time.Millisecond):
		_ = client.Close()
		<-done
		t.Fatal("EventReader blocked in SyslogSlogHandler.Handle")
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("event-reader syslog writer did not reach the stalled connection")
	}
}

type captureSyslogEventConn11697 struct {
	writes chan []byte
}

func (c *captureSyslogEventConn11697) Write(b []byte) (int, error) {
	c.writes <- append([]byte(nil), b...)
	return len(b), nil
}
func (c *captureSyslogEventConn11697) Read([]byte) (int, error)         { return 0, nil }
func (c *captureSyslogEventConn11697) Close() error                     { return nil }
func (c *captureSyslogEventConn11697) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureSyslogEventConn11697) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureSyslogEventConn11697) SetDeadline(time.Time) error      { return nil }
func (c *captureSyslogEventConn11697) SetReadDeadline(time.Time) error  { return nil }
func (c *captureSyslogEventConn11697) SetWriteDeadline(time.Time) error { return nil }

func TestEventReaderBinarySyslogQueueOwnsPayload11697(t *testing.T) {
	conn := &captureSyslogEventConn11697{writes: make(chan []byte, 1)}
	client := NewSyslogClientWithConn(conn, "tcp")
	t.Cleanup(func() { _ = client.Close() })

	payload := []byte{0, 1, 2, 3}
	if !client.SendBinaryFromEventReader(payload) {
		t.Fatal("binary event was not accepted")
	}
	payload[0] = 9
	select {
	case got := <-conn.writes:
		if !bytes.Equal(got, []byte{0, 1, 2, 3}) {
			t.Fatalf("queued binary payload changed after enqueue: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("binary writer did not send the queued event")
	}
}

var _ net.Conn = (*stalledSyslogEventConn11697)(nil)
var _ net.Conn = (*captureSyslogEventConn11697)(nil)
