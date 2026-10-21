package daemon

// #16083 fold (Opus2 Finding 2): since every slog record queues on the
// async per-client writer, daemon exit must drain that writer — otherwise
// records Handle already accepted vanish at process exit, neither
// delivered nor counted. runShutdownSequence now ends with
// shutdownSlogHandler, which drains bounded by slogShutdownDrainTimeout.
//
// RED on revert: delete the drain call and the healthy-collector record
// below is never written before runShutdownSequence returns.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/logging"
)

// gatedSyslogConn16083 delivers writes only after its gate opens, so a
// record is provably still queued when shutdown begins.
type gatedSyslogConn16083 struct {
	gate   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	writes [][]byte
}

func (c *gatedSyslogConn16083) Write(b []byte) (int, error) {
	<-c.gate
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	c.mu.Unlock()
	return len(b), nil
}
func (c *gatedSyslogConn16083) Read([]byte) (int, error)         { return 0, nil }
func (c *gatedSyslogConn16083) Close() error                     { c.release(); return nil }
func (c *gatedSyslogConn16083) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *gatedSyslogConn16083) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *gatedSyslogConn16083) SetDeadline(time.Time) error      { return nil }
func (c *gatedSyslogConn16083) SetReadDeadline(time.Time) error  { return nil }
func (c *gatedSyslogConn16083) SetWriteDeadline(time.Time) error { return nil }
func (c *gatedSyslogConn16083) release()                         { c.once.Do(func() { close(c.gate) }) }
func (c *gatedSyslogConn16083) written() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.writes))
	for i, w := range c.writes {
		out[i] = string(w)
	}
	return out
}

var _ net.Conn = (*gatedSyslogConn16083)(nil)

func TestRunShutdownSequenceDrainsSlogHandler16083(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}

	conn := &gatedSyslogConn16083{gate: make(chan struct{})}
	client := logging.NewSyslogClientWithConn(conn, "tcp")
	handler := logging.NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*logging.SyslogClient{client})

	d := &Daemon{
		store:       store,
		applySem:    semaphore.NewWeighted(1),
		slogHandler: handler,
	}
	// Install as default so runShutdownSequence's own teardown records
	// (incl. "shutdown complete") also queue through this client.
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Queue a record while the collector gate is shut: accepted, not written.
	slog.Info("pre-shutdown daemon record 16083")
	if got := conn.written(); len(got) != 0 {
		t.Fatalf("precondition: record written before gate opened: %v", got)
	}

	var wg sync.WaitGroup
	_, stopRun := context.WithCancel(context.Background())
	sentinel := errors.New("run-error-passthrough")
	done := make(chan error, 1)
	go func() { done <- d.runShutdownSequence(&wg, stopRun, sentinel) }()

	// The sequence reaches its end only after the drain budget starts;
	// open the gate shortly after so the writer can deliver during drain.
	time.Sleep(50 * time.Millisecond)
	conn.release()

	select {
	case runErr := <-done:
		if runErr != sentinel {
			t.Fatalf("runShutdownSequence must pass runErr through: got %v", runErr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runShutdownSequence did not return within 15s")
	}

	// On return, the queued record (and the shutdown-complete record
	// behind it) must already be on the wire — delivering them was the
	// drain's job, not a later goroutine's.
	found := false
	foundComplete := false
	for _, frame := range conn.written() {
		if strings.Contains(frame, "pre-shutdown daemon record 16083") {
			found = true
		}
		if strings.Contains(frame, "shutdown complete") {
			foundComplete = true
		}
	}
	if !found {
		t.Fatalf("queued slog record was not delivered by shutdown drain; writes=%q dropped=%d",
			conn.written(), client.DroppedWrites())
	}
	if !foundComplete {
		t.Fatalf("shutdown-complete record was not delivered by shutdown drain; writes=%q dropped=%d",
			conn.written(), client.DroppedWrites())
	}
	if !client.ShutdownDrained() {
		t.Fatal("syslog writer goroutine still running after shutdown drain")
	}
}
