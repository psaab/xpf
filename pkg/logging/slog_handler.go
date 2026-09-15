package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

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
	// forwarding is the set of goroutine IDs currently inside the
	// syslog-forwarding section of Handle. It is the re-entrancy guard
	// (#2287): if a client's Send emits an slog record (e.g. a drop warning),
	// slog routes it back through this handler on the SAME goroutine; the
	// guard skips re-forwarding it to syslog so no under-lock or transitive
	// slog call can wedge the daemon. Forwarding to the base handler (stderr)
	// stays unconditional. Shared by pointer across WithAttrs/WithGroup
	// derivatives so a nested Handle through a derived handler is also caught.
	forwarding *sync.Map // map[uint64]struct{}
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
	return &SyslogSlogHandler{base: base, shared: &syslogClientSet{}, forwarding: &sync.Map{}}
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
func (h *SyslogSlogHandler) SetClients(clients []*SyslogClient) {
	s := h.loadOrAllocShared()
	s.mu.Lock()
	old := s.clients
	s.clients = clients
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

// Close closes all syslog clients.
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

// Enabled implements slog.Handler.
func (h *SyslogSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// goIDFn resolves the current goroutine ID. It is a package var so tests can
// install a counting seam to assert the no-client fast path never pays the
// runtime.Stack cost (#2295). Production always uses goID.
var goIDFn = goID

// Handle implements slog.Handler.
func (h *SyslogSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always forward to the base handler (stderr) — unconditionally, even on a
	// re-entrant call, so the record is never lost from local logs.
	err := h.base.Handle(ctx, r)

	// Snapshot the client set first. With no syslog clients configured (the
	// default until syslog config applies) there is nothing to forward, so
	// return before paying for the re-entrancy guard's goID() — runtime.Stack +
	// ParseUint per record is wasted work on the common no-client path (#2295).
	// The set is shared across the lineage (#9916 F-056); the snapshot is taken
	// under the shared lock and the sends run outside it, as before.
	var clients []*SyslogClient
	if s := h.loadShared(); s != nil {
		s.mu.RLock()
		clients = s.clients
		s.mu.RUnlock()
	}

	if len(clients) == 0 {
		return err
	}

	// Re-entrancy guard (#2287): if this goroutine is already inside the
	// syslog-forwarding section (a client Send emitted an slog record that
	// routed back here), skip re-forwarding to syslog. Defense-in-depth so no
	// under-lock or transitive slog call from the send path can wedge the
	// daemon by recursing into a client's Send. Only reached when clients are
	// present, so goID() runs only when there is something to forward (#2295).
	if h.forwarding != nil {
		gid := goIDFn()
		if _, busy := h.forwarding.Load(gid); busy {
			return err
		}
		h.forwarding.Store(gid, struct{}{})
		defer h.forwarding.Delete(gid)
	}

	// Forward to syslog clients.
	severity := slogLevelToSyslog(r.Level)
	msg := formatRecord(r, h.attrs, h.groups)
	for _, c := range clients {
		if c.ShouldSend(severity) {
			c.Send(severity, msg)
		}
	}

	return err
}

// WithAttrs implements slog.Handler.
func (h *SyslogSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SyslogSlogHandler{
		base:       h.base.WithAttrs(attrs),
		shared:     h.loadOrAllocShared(), // share the client set (#9916 F-056)
		attrs:      append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups:     h.groups,
		forwarding: h.forwarding, // share the re-entrancy guard (#2287)
	}
}

// WithGroup implements slog.Handler.
func (h *SyslogSlogHandler) WithGroup(name string) slog.Handler {
	return &SyslogSlogHandler{
		base:       h.base.WithGroup(name),
		shared:     h.loadOrAllocShared(), // share the client set (#9916 F-056)
		attrs:      h.attrs,
		groups:     append(append([]string{}, h.groups...), name),
		forwarding: h.forwarding, // share the re-entrancy guard (#2287)
	}
}

// slogLevelToSyslog maps slog levels to syslog severity values.
func slogLevelToSyslog(level slog.Level) int {
	switch {
	case level >= slog.LevelError:
		return SyslogError
	case level >= slog.LevelWarn:
		return SyslogWarning
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
