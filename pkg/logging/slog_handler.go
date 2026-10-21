package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type eventReaderSlogContextKey struct{}

var eventReaderSlogContext = context.WithValue(context.Background(), eventReaderSlogContextKey{}, true)

// eventReaderSlogInfo marks firewall event logs from the EventReader; their
// remote syslog copies use the same bounded per-client writer as every other
// slog record (#16083).
func eventReaderSlogInfo(message string, args ...any) {
	slog.Default().Log(eventReaderSlogContext, slog.LevelInfo, message, args...)
}

type suppressSystemSyslogContextKey struct{}

var suppressSystemSyslogContext = context.WithValue(eventReaderSlogContext, suppressSystemSyslogContextKey{}, true)

// eventReaderSlogInfoSuppressSystemSyslog is eventReaderSlogInfo for a
// record whose copy must NOT be forwarded to the `system syslog host`
// clients (#14612). The record still reaches the wrapped base handler
// (stderr / local log) unconditionally; only SyslogSlogHandler's remote
// forwarding is withheld. Used for a FILTER_LOG event whose term carried
// `then log` without `then syslog` — the #6859 gate covered the
// EventReader's stream clients but not this slog sink.
func eventReaderSlogInfoSuppressSystemSyslog(message string, args ...any) {
	slog.Default().Log(suppressSystemSyslogContext, slog.LevelInfo, message, args...)
}

func isSuppressSystemSyslogContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	suppress, _ := ctx.Value(suppressSystemSyslogContextKey{}).(bool)
	return suppress
}

// SyslogSlogHandler is an slog.Handler that forwards log records to remote
// syslog servers in addition to a wrapped base handler (typically stderr).
//
// The client set is SHARED by pointer across WithAttrs/WithGroup derivatives
// (#9916 F-056): SetClients/Close on any member of the lineage affects all of
// them, so a reconfigure is observed by previously derived slog.With(...) loggers
// instead of stranding them on closed clients. The daemon calls SetClients only
// on the root; sharing is the correct semantic for one logical handler.
type SyslogSlogHandler struct {
	base slog.Handler
	// mu guards the shared pointer's lazy publication (zero-value safe), not
	// the client slice itself. The slice lives in shared under its own lock.
	mu     sync.RWMutex
	shared *syslogClientSet
	attrs  []slog.Attr
	groups []string
}

// syslogClientSet is the shared, mutex-guarded client slice behind every member
// of a SyslogSlogHandler lineage (#9916 F-056). Derivatives share the pointer
// (like forwarding); attrs/groups are still copied per derivative.
type syslogClientSet struct {
	mu      sync.RWMutex
	clients []*SyslogClient
}

// NewSyslogSlogHandler wraps a base slog.Handler with syslog forwarding.
func NewSyslogSlogHandler(base slog.Handler) *SyslogSlogHandler {
	return &SyslogSlogHandler{base: base, shared: &syslogClientSet{}}
}

// loadShared returns the lineage's client set, or nil for a zero-value handler
// that has never been given one. Lock-free for callers after New (pointer never
// changes); the RLock covers only the lazy-publication race.
func (h *SyslogSlogHandler) loadShared() *syslogClientSet {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.shared
}

// loadOrAllocShared returns the lineage's client set, allocating it on first use
// so zero-value lineages still share (WithAttrs/WithGroup and SetClients route
// through here). Safe for concurrent use.
func (h *SyslogSlogHandler) loadOrAllocShared() *syslogClientSet {
	h.mu.RLock()
	s := h.shared
	h.mu.RUnlock()
	if s != nil {
		return s
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shared == nil {
		h.shared = &syslogClientSet{}
	}
	return h.shared
}

// SetClients replaces the set of syslog clients. Old clients are closed.
// Shared across the lineage (#9916 F-056): derived handlers observe the swap.
// The slice is COPIED: the caller retains no alias into the handler, so a
// caller-side mutation of the passed backing array can never race the
// lineage-wide readers (Handle snapshots the header and iterates it lock-free).
func (h *SyslogSlogHandler) SetClients(clients []*SyslogClient) {
	s := h.loadOrAllocShared()
	s.mu.Lock()
	old := s.clients
	s.clients = append([]*SyslogClient(nil), clients...)
	s.mu.Unlock()

	for _, c := range old {
		c.Close()
	}
}

// Clients returns the currently installed syslog clients.
//
// #6829 A5: exported so a caller's wiring can be asserted on the VALUE that
// reaches the client, not just on a log line. applySystemSyslog computes the
// facility and assigns it in two separate steps either side of the dial, which
// is the refactor shape that silently drops a value; without this, deleting
// either step left the whole suite green.
func (h *SyslogSlogHandler) Clients() []*SyslogClient {
	s := h.loadShared()
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*SyslogClient(nil), s.clients...)
}

// Close closes all syslog clients. Queued writer records are discarded
// and counted (the reconfigure path: a client swap must not wait on the
// old collector).
func (h *SyslogSlogHandler) Close() {
	s := h.loadShared()
	if s == nil {
		return
	}
	s.mu.Lock()
	clients := s.clients
	s.clients = nil
	s.mu.Unlock()

	for _, c := range clients {
		c.Close()
	}
}

// The ShutdownTimeout deadline is a TOTAL bound across all clients, so
// one stalled collector cannot multiply it per client; each client still
// gets at least a minimal slice so a healthy one is not starved to zero.
const slogShutdownClientMinSlice = 10 * time.Millisecond

// ShutdownTimeout orderly-closes the handler for process exit (#16083
// fold): each client's queued backlog is delivered bounded by the TOTAL
// timeout (shared deadline, drained concurrently so one hung collector
// cannot starve healthy ones), then the clients are closed. Whatever a
// client cannot deliver in its share is discarded and counted by the
// writer's drop accounting — never silently lost, never unbounded.
// ShutdownTimeout is the daemon-exit path; Close remains the reconfigure
// path. Nil-safe and idempotent (a second call finds no clients).
func (h *SyslogSlogHandler) ShutdownTimeout(timeout time.Duration) {
	s := h.loadShared()
	if s == nil {
		return
	}
	s.mu.Lock()
	clients := s.clients
	s.clients = nil
	s.mu.Unlock()

	if timeout <= 0 {
		for _, c := range clients {
			c.Close()
		}
		return
	}
	deadline := time.Now().Add(timeout)
	var wg sync.WaitGroup
	for _, c := range clients {
		remaining := time.Until(deadline)
		if remaining < slogShutdownClientMinSlice {
			remaining = slogShutdownClientMinSlice
		}
		wg.Add(1)
		go func(c *SyslogClient, budget time.Duration) {
			defer wg.Done()
			c.CloseTimeout(budget)
		}(c, remaining)
	}
	wg.Wait()
}

// Enabled implements slog.Handler.
func (h *SyslogSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *SyslogSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always forward to the base handler (stderr) — unconditionally, even on a
	// re-entrant call, so the record is never lost from local logs.
	err := h.base.Handle(ctx, r)

	// #14612: a record marked suppress-system-syslog (a `then log`-only
	// FILTER_LOG hit) has already reached the local log via the base
	// handler above; it must not be copied to the `system syslog host`
	// clients.
	if isSuppressSystemSyslogContext(ctx) {
		return err
	}

	// Snapshot the client set. With no syslog clients configured (the
	// default until syslog config applies) there is nothing to forward.
	// The set is shared across the lineage (#9916 F-056); the snapshot is
	// taken under the shared lock and the sends run outside it, as before.
	var clients []*SyslogClient
	if s := h.loadShared(); s != nil {
		s.mu.RLock()
		clients = s.clients
		s.mu.RUnlock()
	}

	if len(clients) == 0 {
		return err
	}

	// Forward to syslog clients through the bounded per-client writer
	// (#16083). Non-event slog callers previously did a synchronous Send, so
	// a blackholed TCP/TLS collector could park arbitrary daemon goroutines
	// (commit/apply, reconcile, API handlers) behind the client mutex for
	// the write/dial timeout. A record the writer goroutine fails to
	// deliver — or one enqueued from inside that writer's own send path
	// (e.g. a drop warning) — is dropped and counted rather than
	// synchronously re-delivered, so Handle never blocks on the collector
	// and a nested record can never wedge the writer.
	severity := slogLevelToSyslog(r.Level)
	msg := formatRecord(r, h.attrs, h.groups)
	for _, c := range clients {
		if !c.ShouldSend(severity) {
			continue
		}
		if c.fromSyslogWriter() {
			c.noteSlogHandlerDrop()
			continue
		}
		_ = c.sendFromSlog(r.Time, severity, msg)
	}

	return err
}

// WithAttrs implements slog.Handler.
func (h *SyslogSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SyslogSlogHandler{
		base:   h.base.WithAttrs(attrs),
		shared: h.loadOrAllocShared(), // share the client set (#9916 F-056)
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: h.groups,
	}
}

// WithGroup implements slog.Handler.
func (h *SyslogSlogHandler) WithGroup(name string) slog.Handler {
	return &SyslogSlogHandler{
		base:   h.base.WithGroup(name),
		shared: h.loadOrAllocShared(), // share the client set (#9916 F-056)
		attrs:  h.attrs,
		groups: append(append([]string{}, h.groups...), name),
	}
}

// slogLevelToSyslog maps slog levels to syslog severity values.
func slogLevelToSyslog(level slog.Level) int {
	switch {
	case level >= slog.LevelError:
		return SyslogError
	case level >= slog.LevelWarn:
		return SyslogWarning
	case level < slog.LevelInfo:
		return SyslogDebug
	default:
		return SyslogInfo
	}
}

// formatRecord produces a compact text representation of a log record.
func formatRecord(r slog.Record, preAttrs []slog.Attr, groups []string) string {
	var b strings.Builder
	b.WriteString(r.Message)

	for _, a := range preAttrs {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value.String())
	}

	r.Attrs(func(a slog.Attr) bool {
		key := a.Key
		if len(groups) > 0 {
			key = strings.Join(groups, ".") + "." + key
		}
		fmt.Fprintf(&b, " %s=%s", key, a.Value.String())
		return true
	})

	return b.String()
}
