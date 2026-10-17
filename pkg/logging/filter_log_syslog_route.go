package logging

import "sync"

// filter_log_syslog_route.go — #6859: which firewall-filter terms may reach the
// syslog clients.
//
// Junos routes the two filter-log actions to different sinks: `then log` writes
// the filter-log buffer, `then syslog` sends to the system log. xpf categorised
// every filter-log event as CategoryFirewall and gated the fan-out only per
// CLIENT, never per term — so both spellings reached every subscribed syslog
// client, and a term an operator wrote as `then log` specifically to keep hits
// ON the box was shipped to whatever remote collector was configured.
//
// THE DECISION CANNOT BE MADE IN THE DATAPLANE. The `syslog` bit reaches the
// Rust FirewallTermSnapshot (#6853) but parse_term never consumes it, so the
// event carries no indication of which spelling produced it. What it DOES carry
// is RuleID/TermID, and the Rust side assigns both as positional indices into
// the snapshot the Go control plane itself rendered — so the control plane can
// answer authoritatively from the same snapshot it sent.
// userspace.FilterTermSyslogMap is a projection of that snapshot rather than a
// second walk of the config, because a divergence between the two orderings
// would route one term's hits under another term's spelling with nothing
// failing.
//
// PLACEMENT is what makes suppression safe: the gate is consulted at the syslog
// fan-out in ringbuf.go, AFTER the event-buffer callbacks and BEFORE the local
// writers. xpf has no `show firewall log`; `show security log` reads that buffer
// and still shows a suppressed hit.
//
// #14612: there are TWO remote sinks, not one. The gate above covers the
// EventReader's stream clients; the daemon "firewall event" slog line is a
// second sink, forwarded by SyslogSlogHandler to the `system syslog host`
// clients. logEvent therefore computes the same allows() decision BEFORE
// emitting that line and marks a gated FILTER_LOG record
// suppress-system-syslog, so the handler withholds its remote copy while
// the local (base-handler) copy and the buffer entry are unchanged.

// filterSyslogRoute holds the (filter_id, term_id) -> `then syslog` map the
// filter-log fan-out gate consults.
//
// The zero value is the pre-#6859 behaviour: a nil map means "no apply has
// wired this yet" and every filter-log event forwards, so a path that never
// wires it cannot silently suppress `then syslog` as well. An empty NON-nil map
// is the opposite instruction — "wired; this config has no `then syslog`
// terms" — and is what a config with all filters removed installs, so the
// reader cannot resume forwarding under deleted terms' ids.
type filterSyslogRoute struct {
	mu sync.RWMutex
	m  map[uint64]bool
}

// allows reports whether a FILTER_LOG event from (filterID, termID) may be
// forwarded to the syslog clients.
func (r *filterSyslogRoute) allows(filterID, termID uint32) bool {
	r.mu.RLock()
	m := r.m
	r.mu.RUnlock()
	if m == nil {
		return true
	}
	return m[FilterTermSyslogKey(filterID, termID)]
}

// FilterTermSyslogKey packs a filter-log event's (filter_id, term_id) identity
// into the key used by the #6859 syslog-routing map.
//
// It is the SINGLE definition of that packing. The producer
// (userspace.FilterTermSyslogMap) and this consumer must agree exactly — a
// divergence would route filter-log events to the wrong sink with nothing
// failing — so the producer calls this function rather than repeating the
// shift.
func FilterTermSyslogKey(filterID, termID uint32) uint64 {
	return uint64(filterID)<<32 | uint64(termID)
}

// SetFilterTermSyslog installs the #6859 (filter_id, term_id) -> `then syslog`
// map (goroutine-safe). Called on every config apply with the map projected
// from the same filter snapshot that was pushed to the dataplane.
//
// Passing a nil map restores the pre-#6859 behaviour of forwarding every
// filter-log event to every syslog client. Callers wiring a real config should
// pass the projection even when it is empty (a config with no filter terms
// yields an empty NON-nil map), so the gate stays active.
func (er *EventReader) SetFilterTermSyslog(m map[uint64]bool) {
	er.filterSyslogRoute.mu.Lock()
	er.filterSyslogRoute.m = m
	er.filterSyslogRoute.mu.Unlock()
}

// FilterTermSyslog returns a copy of the installed #6859 routing map
// (goroutine-safe), preserving the nil/non-nil distinction the gate depends on.
//
// A COUNT would be the wrong instrument here and is deliberately not what this
// exposes: nil ("never wired", legacy fan-out) and an empty non-nil map
// ("wired, no syslog terms") both have length zero while instructing the gate
// to do OPPOSITE things, and a caller checking a count could not tell a wiring
// regression from a config with no `then syslog` terms. Returning the map makes
// both observable — the same reason SyslogClients exists alongside
// SyslogClientCount (#6829 F2).
func (er *EventReader) FilterTermSyslog() map[uint64]bool {
	er.filterSyslogRoute.mu.RLock()
	defer er.filterSyslogRoute.mu.RUnlock()
	if er.filterSyslogRoute.m == nil {
		return nil
	}
	out := make(map[uint64]bool, len(er.filterSyslogRoute.m))
	for k, v := range er.filterSyslogRoute.m {
		out[k] = v
	}
	return out
}
