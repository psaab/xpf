// Package sysservices holds the shared, EFFECTIVE management-listener state
// rendered by `show system services`. It is a LEAF package (imports only the
// standard library) so the daemon (which owns the listener lifecycle), the
// local interactive CLI (pkg/cli), and the remote gRPC renderer (pkg/grpcapi)
// can all depend on it without an import cycle.
//
// The point of this package (#6385/#6401): both `show system services`
// renderers — the local CLI (pkg/cli/cli_show_system.go) AND the remote gRPC
// renderer (pkg/grpcapi/server_show_system.go, the path the remote `cli` binary
// reaches) — read ONE daemon-owned snapshot of what each listener is ACTUALLY
// doing, not the requested/config-declared values. Before #6385 both renderers
// hardcoded `127.0.0.1:50051 (always on)` / `127.0.0.1:8080 (always on)`, so a
// relocated, loopback-clamped (#5035/#5127), or disabled listener was reported
// wrong, and a dropped local-only patch (the #6384 A10-b2-F5 attempt) left the
// local and remote surfaces disagreeing. Sourcing both from Lines() guarantees
// they can never diverge again.
//
// #6401 fold: each listener carries a STATE (not just an address) so a
// CONFIGURED-but-FAILED bind is reported as such rather than misread as either
// serving (the old requested-addr fallback) or off ("disabled").
package sysservices

import "fmt"

// State is the operational state of a management listener.
type State int

const (
	// StateDisabled: the listener is not configured / off (e.g. an empty
	// --api-addr, where the daemon never started the HTTP REST listener). Zero
	// value so a zero Listener renders "disabled".
	StateDisabled State = iota
	// StateListening: the listener is bound and serving at Addr.
	StateListening
	// StateFailed: the listener is CONFIGURED but not currently serving — its
	// bind failed (net.Listen error) or its serve loop exited. Addr is the
	// address it tried to bind (may be empty when unknown). Distinct from
	// StateDisabled so an operator can tell a genuinely-off listener from one
	// that failed to come up.
	StateFailed
	// StateStale: the listener IS serving a socket, but not at the address
	// the configuration currently resolves to (#14582) — it sits on the
	// loopback fallback because the configured interface had no usable
	// address at resolution time, or on an interface address that has since
	// been replaced/vanished. Off-box callers to the configured address get
	// RST while the socket lives elsewhere, so this must never render as
	// Listening. Addr is the address ACTUALLY bound (the fallback or the
	// vanished address), so the operator sees where it really is.
	StateStale
)

// Listener is the effective state of one management listener.
type Listener struct {
	// Addr is the bind address. For StateListening it is the ACTUAL bound
	// address (post-clamp, post-bind — an ephemeral :0 request resolves to its
	// concrete port); for StateFailed it is the address that failed to bind (or
	// "" when unknown); for StateStale it is the address actually bound (the
	// loopback fallback or the vanished interface address, #14582); for
	// StateDisabled it is ignored.
	Addr string
	// State is the listener's operational state.
	State State
}

// render formats one listener cell: the address when serving, an
// address-tagged "(bind failed)" (or bare "bind failed") when failed,
// "(stale bind)" when serving at a superseded/fallback address,
// "disabled" when off.
func (l Listener) render() string {
	switch l.State {
	case StateListening:
		return l.Addr
	case StateFailed:
		if l.Addr != "" {
			return l.Addr + " (bind failed)"
		}
		return "bind failed"
	case StateStale:
		if l.Addr != "" {
			return l.Addr + " (stale bind)"
		}
		return "stale bind"
	default: // StateDisabled
		return "disabled"
	}
}

// Listeners is the EFFECTIVE state of each management listener `show system
// services` reports. The daemon builds it after the listeners bind
// (Daemon.effectiveListeners); a nil snapshot source in a renderer means the
// CLI was spawned outside a running daemon (offline recovery / unit test), where
// there is no live listener to read.
type Listeners struct {
	// GRPC is the primary (loopback, unauthenticated) gRPC control listener. It
	// is always configured, so it is never StateDisabled — StateListening while
	// serving, StateFailed if net.Listen failed or the serve loop exited.
	GRPC Listener
	// HTTP is the HTTP REST listener (first bind). StateDisabled when --api-addr
	// is empty (the daemon never started it), StateFailed on a boot bind failure,
	// else StateListening.
	HTTP Listener
	// HTTPS is the HTTPS REST listener (first bind, #8597 K86).
	HTTPS Listener
	// HTTPs / HTTPSs carry one row per bind address when the plane binds more
	// than one address (#14583: dual-stack web-management). Empty means the
	// single HTTP/HTTPS row is the whole plane; renderers and metrics prefer
	// these when present.
	HTTPs  []Listener
	HTTPSs []Listener
}

// Lines renders the gRPC / HTTP REST listener rows for `show system services`,
// in render order, driven by the effective state. It is the SINGLE formatter
// both the local CLI and remote gRPC renderers call, so the two surfaces are
// byte-identical by construction.
func (l Listeners) Lines() []string {
	lines := []string{fmt.Sprintf("  gRPC:           %s", l.GRPC.render())}
	for _, row := range l.httpRows() {
		lines = append(lines, fmt.Sprintf("  HTTP REST:      %s", row.render()))
	}
	for _, row := range l.httpsRows() {
		lines = append(lines, fmt.Sprintf("  HTTPS REST:     %s", row.render()))
	}
	return lines
}

// HTTPRows / HTTPSRows return the per-address rows for a plane, falling back
// to the single legacy row when no plural rows were recorded.
func (l Listeners) HTTPRows() []Listener { return l.httpRows() }

func (l Listeners) HTTPSRows() []Listener { return l.httpsRows() }

func (l Listeners) httpRows() []Listener {
	if len(l.HTTPs) > 0 {
		return l.HTTPs
	}
	return []Listener{l.HTTP}
}

func (l Listeners) httpsRows() []Listener {
	if len(l.HTTPSs) > 0 {
		return l.HTTPSs
	}
	return []Listener{l.HTTPS}
}

// SurfaceRows returns the (surface, listener) rows the management-listener
// metric emits (#14583): grpc always; http/https one per bind address when
// plural rows exist, else the single legacy row — but only when that row
// names a configured plane (non-empty Addr or non-Disabled state), so a
// legacy snapshot with no HTTPS row emits no https series.
func (l Listeners) SurfaceRows() []struct {
	Surface string
	L       Listener
} {
	type row = struct {
		Surface string
		L       Listener
	}
	rows := []row{{"grpc", l.GRPC}}
	appendPlane := func(surface string, single Listener, plural []Listener, always bool) {
		if len(plural) > 0 {
			for _, r := range plural {
				rows = append(rows, row{surface, r})
			}
			return
		}
		if always || single.Addr != "" || single.State != StateDisabled {
			rows = append(rows, row{surface, single})
		}
	}
	appendPlane("http", l.HTTP, l.HTTPs, true)
	appendPlane("https", l.HTTPS, l.HTTPSs, false)
	return rows
}
