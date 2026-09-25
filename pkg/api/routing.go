package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/frr"
)

// maxBGPRoutes bounds how many BGP routes the REST
// /api/routing/bgp?type=routes endpoint renders into a single JSON response.
// The FRR package owns the shared REST/gRPC route-count ceiling. Keep this
// variable so tests can exercise truncation without a million-route fixture.
var maxBGPRoutes = frr.MaxBGPRoutes

// --- #6809: bounding a SLOW READER, not a large table ------------------------
//
// The route cap above bounds bytes and CPU *after progress*. It bounds nothing
// while the handler is BLOCKED. An authenticated client that opens
// /api/routing/bgp?type=routes and then reads slowly — or stops reading without
// disconnecting — fills the socket buffers, and the periodic `bw.Flush()` in
// the stream callback blocks in the kernel. That pins four things at once, none
// of which any existing bound covers:
//
//   - the handler goroutine, parked in Flush;
//   - the vtysh child, which blocks as soon as ITS stdout pipe fills;
//   - that pipe and the client connection;
//   - and, before this, an unbounded number of each, because there was no
//     admission limit on the endpoint.
//
// r.Context() cancels on DISCONNECT, which the #5232 check already handles. A
// still-connected non-reader produces neither a disconnect nor a write error,
// so nothing fires. http.Server's WriteTimeout is deliberately 0 process-wide
// (SSE event/log streams must be able to stay open indefinitely — see the const
// block in server.go), so there is no global backstop either.
//
// THE TWO BUDGETS ARE NOT REDUNDANT, and this is the part that is easy to get
// wrong. Cancelling a context does NOT interrupt a write already blocked in the
// kernel: a finite context kills vtysh and frees the child + pipe, but the
// handler goroutine stays parked in Flush forever. Only a socket write deadline
// unblocks it. Conversely a write deadline alone does not bound a client that
// dribbles just enough bytes to reset it every window. So:
//
//   - bgpStreamWriteDeadline is the PROGRESS budget — it bounds one flush, and
//     is what actually unpins the goroutine;
//   - bgpStreamTotalBudget is the ELAPSED backstop — it bounds the whole
//     request, and catches the dribbling client that resets the write window
//     forever.
//
// Be precise about what the backstop can and cannot do on a ResponseWriter
// that does NOT support write deadlines: it still kills and reaps the vtysh
// child, freeing the process, its pipe and the RIB dump, but it CANNOT unpin
// this goroutine, because nothing short of a socket deadline interrupts a
// write already blocked in the kernel. That configuration is therefore a
// partial bound, not a full one, and the write deadline is the load-bearing
// half. In production the writer is a real *http.response over a TCP conn,
// which supports deadlines.
//
// A per-flush deadline is preferred over a pure elapsed cap as the primary
// mechanism because it does not punish a LEGITIMATELY large table on a slow
// but progressing link: each flush gets a fresh window, so a 1M-route dump to
// a genuine slow consumer completes, while a non-reader fails on the first
// window.

// bgpStreamWriteDeadline bounds a SINGLE downstream flush. A client that
// cannot accept one 1024-route chunk within this window is not reading. Vars,
// not consts, so a test can compress them without a real slow reader.
var bgpStreamWriteDeadline = 30 * time.Second

// bgpStreamTotalBudget bounds the whole route stream end to end. Generous by
// design: a full internet table capped at maxBGPRoutes streams out in seconds
// on any real link, so this only trips on a client engineered to make minimal
// progress, or where write deadlines are unavailable.
var bgpStreamTotalBudget = 10 * time.Minute

// maxConcurrentRIBStreams bounds how many full-RIB stream requests may be in
// flight. Each holds a vtysh child dumping the routing table, which contends
// with the control plane, so this is deliberately tighter than the diagnostic
// limiters (#5057's 4). The endpoint is a diagnostic, not a hot path.
const maxConcurrentRIBStreams = 2

// ribStreamLimiter admits at most maxConcurrentRIBStreams concurrent full-RIB
// streams, so a handful of slow readers cannot accumulate vtysh children
// without bound. It reuses the diagcmd fixed-capacity counting semaphore — the
// same fail-fast idiom the diagnostic and session-walk handlers use: Acquire is
// non-blocking, so an over-cap request gets an immediate 429 instead of joining
// an unbounded backlog (which would just move the pin).
//
// Unlike sessionWalkLimiter this instance is LOCAL to the REST surface rather
// than a shared diagcmd process-wide one, and that is deliberate: the gRPC and
// CLI `show route protocol bgp` paths call the BUFFERED GetBGPRoutes, which
// runs vtysh to completion before any client sees a byte and therefore cannot
// be pinned by a slow reader. There is no second surface to share a budget
// with, so a shared instance would imply a cross-surface bound that does not
// exist. A package var so a test can swap in a capacity-1 limiter.
var ribStreamLimiter = diagcmd.NewLimiter(maxConcurrentRIBStreams)

// deadlineArmingWriter arms a fresh write deadline immediately before each
// underlying write, so no write to the socket can block longer than the
// progress budget (#6809).
//
// It sits BETWEEN bufio and the ResponseWriter deliberately. Arming at the
// handler's explicit flush points leaves bufio's own capacity-triggered
// flushes — the majority of the real socket writes — uncovered, and those are
// the ones that block first. Placing it here makes the property structural
// rather than a matter of remembering every flush site, including the closing
// one a sub-1024-route table reaches without ever entering the periodic branch.
//
// A writer that cannot carry a deadline (http.ErrNotSupported) is recorded
// once and not retried per write; the elapsed backstop then bounds the vtysh
// child, though not this goroutine — see the note above.
type deadlineArmingWriter struct {
	w           io.Writer
	rc          *http.ResponseController
	d           time.Duration
	unsupported bool
}

func (a *deadlineArmingWriter) Write(p []byte) (int, error) {
	if !a.unsupported {
		if err := a.rc.SetWriteDeadline(time.Now().Add(a.d)); err != nil {
			a.unsupported = true
		}
	}
	return a.w.Write(p)
}

func (s *Server) routesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []RouteInfo{})
		return
	}

	// Iterate the SAME static-route sources the CLI/gRPC `show route` text
	// walks (#5439): the global inet.0 + inet6.0 tables AND every
	// routing-instance's per-VRF inet.0 + inet6.0 tables. Before #5439 this
	// handler rendered only cfg.RoutingOptions.StaticRoutes (inet.0), so it
	// silently omitted every IPv6 static route and every per-VRF static
	// route — not even their destination — making the REST view inconsistent
	// with the CLI/gRPC. Each route is tagged with its family and Junos RIB
	// name so a consumer can tell inet from inet6 and the default table from
	// a VRF. The inet.0 rows still come first, in their original order, so a
	// legacy consumer's positional reads are unchanged.
	var result []RouteInfo
	result = appendStaticRoutes(result, cfg.RoutingOptions.StaticRoutes, "inet", "inet.0")
	result = appendStaticRoutes(result, cfg.RoutingOptions.Inet6StaticRoutes, "inet6", "inet6.0")
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		result = appendStaticRoutes(result, ri.StaticRoutes, "inet", ri.Name+".inet.0")
		result = appendStaticRoutes(result, ri.Inet6StaticRoutes, "inet6", ri.Name+".inet6.0")
	}
	if result == nil {
		result = []RouteInfo{}
	}
	writeOK(w, result)
}

// appendStaticRoutes renders each static route in routes into one or more
// RouteInfo rows tagged with the given family ("inet"/"inet6") and Junos RIB
// table name, appending them to result. It applies the same disposition
// labeling the CLI/gRPC `show route` text uses (#5298/#5410): a route with no
// forwarding next-hop carries a "reject" (RTN_UNREACHABLE), "discard"
// (RTN_BLACKHOLE), or "connected" (directly-connected) label, while a
// next-table route carries next_table and a normal route emits one row per
// next-hop. Reject and Discard are mutually exclusive and are checked before
// the no-next-hop fallthrough since a reject/discard route also carries no
// NextHops. Shared by the global inet.0/inet6.0 tables and every per-VRF
// table so all four sources render identically.
func appendStaticRoutes(result []RouteInfo, routes []*config.StaticRoute, family, table string) []RouteInfo {
	for _, r := range routes {
		if r == nil {
			continue
		}
		base := RouteInfo{
			Destination: r.Destination,
			Preference:  r.Preference,
			Family:      family,
			Table:       table,
		}
		if r.NextTable != "" {
			ri := base
			ri.NextTable = r.NextTable
			result = append(result, ri)
			continue
		}
		if r.Reject {
			ri := base
			ri.Disposition = "reject"
			result = append(result, ri)
			continue
		}
		if r.Discard {
			ri := base
			ri.Disposition = "discard"
			result = append(result, ri)
			continue
		}
		if len(r.NextHops) == 0 {
			ri := base
			ri.Disposition = "connected"
			result = append(result, ri)
			continue
		}
		for _, nh := range r.NextHops {
			ri := base
			ri.NextHop = nh.Address
			ri.Interface = nh.Interface
			result = append(result, ri)
		}
	}
	return result
}

// writeFRRError renders an FRR shell-out failure with the right status class
// (#9143). frr.ErrVtyshBusy is the process-wide vtysh admission bound refusing
// the request: the FRR daemons are healthy and we declined to ask, so it is a
// 429 with Retry-After — the same shape #6809's ribStreamLimiter branch already
// uses on this endpoint's sibling, and the same distinction #9142 drew for the
// delegated session clear. Everything else stays 500.
func writeFRRError(w http.ResponseWriter, err error) {
	if errors.Is(err, frr.ErrVtyshBusy) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests,
			"FRR status concurrency limit reached; retry shortly")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func (s *Server) ospfHandler(w http.ResponseWriter, r *http.Request) {
	if s.frr == nil {
		writeOK(w, TextResponse{Output: "FRR not available"})
		return
	}
	typ := r.URL.Query().Get("type")
	switch typ {
	case "database":
		output, err := s.frr.GetOSPFDatabase(r.Context())
		if err != nil {
			writeFRRError(w, err)
			return
		}
		writeOK(w, TextResponse{Output: output})
	default:
		neighbors, err := s.frr.GetOSPFNeighbors(r.Context())
		if err != nil {
			writeFRRError(w, err)
			return
		}
		var b strings.Builder
		for _, n := range neighbors {
			fmt.Fprintf(&b, "%-18s %-10s %-16s %-18s %s\n",
				n.NeighborID, n.Priority, n.State, n.Address, n.Interface)
		}
		writeOK(w, TextResponse{Output: b.String()})
	}
}

func (s *Server) bgpHandler(w http.ResponseWriter, r *http.Request) {
	if s.frr == nil {
		writeOK(w, TextResponse{Output: "FRR not available"})
		return
	}
	typ := r.URL.Query().Get("type")
	switch typ {
	case "routes":
		// The upstream RIB is streamed, not buffered: StreamBGPRoutes scans
		// vtysh stdout one route at a time and hands each to the callback
		// below, so a full internet table (~1M routes) is never rendered into
		// one multi-hundred-MB string on either the FRR side or in this
		// handler (#5056, extending the downstream-only streaming of #4708).
		// Each route line is formatted and JSON-escaped through a fixed-size
		// bufio buffer, so peak memory is bounded regardless of table size.
		// JSON string escaping is per-byte independent, so escaping each line
		// and concatenating yields exactly the same bytes as escaping the
		// joined string. The output is capped at maxBGPRoutes with a trailing
		// truncation notice so the response body stays bounded even for a
		// pathologically large table.
		// #6809 admission: one slot per in-flight full-RIB stream. Non-blocking
		// — an over-cap request is refused immediately rather than queued,
		// because a queued request holds the same connection it would have held
		// while streaming.
		release, err := ribStreamLimiter.Acquire()
		if err != nil {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests,
				"BGP route-stream concurrency limit reached; retry shortly")
			return
		}
		defer release()

		// #6809 elapsed backstop. Derived from r.Context() so a real disconnect
		// still cancels immediately (the #5232 path), and handed to
		// StreamBGPRoutes so its exec.CommandContext kills and reaps vtysh when
		// the budget expires. This bounds the CHILD; the write deadline below is
		// what bounds this goroutine.
		streamCtx, cancelStream := context.WithTimeout(r.Context(), bgpStreamTotalBudget)
		defer cancelStream()

		// #6809 progress budget, armed at the WRITE, not at the flush points.
		//
		// The obvious placement — arm it next to the periodic bw.Flush() — does
		// not work, and the slow-reader cell catches it. bufio auto-flushes
		// whenever its 4 KiB buffer fills, and 1024 routes is ~70 KiB, so the
		// stream performs roughly seventeen real socket writes between two
		// consecutive explicit flushes. Those are the writes that block first,
		// and an arm that only runs at the explicit boundary never covers them.
		//
		// Wrapping the ResponseWriter instead makes the coverage structural:
		// every byte that reaches the socket passes through one place that has
		// just armed a deadline, whoever decided to flush. It costs one
		// SetWriteDeadline per underlying write (~per 4 KiB), not per route.
		bw := bufio.NewWriter(&deadlineArmingWriter{
			w:  w,
			rc: http.NewResponseController(w),
			d:  bgpStreamWriteDeadline,
		})
		emitted := 0
		started := false
		// emitPrefix lazily writes the 200 status + envelope prefix on the
		// first route (or on an empty/complete table). Deferring it lets an
		// upstream vtysh START failure — detected before any route is
		// delivered — surface as a clean 500 instead of a truncated 200.
		emitPrefix := func() {
			if started {
				return
			}
			started = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Response{Success:true, Data: TextResponse{Output}} with Error
			// empty (omitempty) — matches encoding/json field order.
			io.WriteString(bw, `{"success":true,"data":{"output":"`)
		}
		truncated, err := s.frr.StreamBGPRoutes(streamCtx, maxBGPRoutes, func(route frr.BGPRoute) error {
			emitPrefix()
			writeJSONStringFragment(bw, fmt.Sprintf("%-24s %-20s %s\n",
				route.Network, route.NextHop, route.Path))
			emitted++
			// Periodically push bytes onto the wire so a very large table
			// streams out instead of parking in buffers.
			if emitted%1024 == 0 {
				// Abort if the client has disconnected: continuing to format
				// and JSON-escape every remaining route and write to a dead
				// connection is pure CPU/GC waste (#5232). Returning an error
				// stops the scan and cancels vtysh upstream. The un-flushed
				// bufio tail and closing envelope are intentionally dropped:
				// the connection is gone.
				// #6809: check the BUDGETED context, not r.Context(). It is
				// derived from it, so a disconnect still lands here; the
				// elapsed backstop now does too.
				if cerr := streamCtx.Err(); cerr != nil {
					return cerr
				}
				// A downstream write failure is also terminal: propagate it so
				// the scan stops and vtysh is cancelled instead of dumping the
				// rest of the table into a broken pipe. Since #6809 that
				// includes a write-deadline expiry, which is what converts a
				// blocked handler into an ordinary terminal write error.
				if ferr := bw.Flush(); ferr != nil {
					return ferr
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			return nil
		})
		if err != nil {
			if !started {
				// vtysh failed to start before any bytes were written — we can
				// still send a proper error status.
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			// Client disconnect or write failure mid-stream: headers + a
			// partial body are already on the wire, so we cannot switch to an
			// error status. The scan is aborted and vtysh cancelled; stop.
			return
		}
		// Empty or fully-drained table: emit the (possibly empty) envelope.
		emitPrefix()
		if truncated {
			// Bounded-response notice, inside the JSON string so the envelope
			// shape is unchanged; only present when the cap actually tripped.
			writeJSONStringFragment(bw, fmt.Sprintf(
				"... table truncated at %d routes; use the CLI 'show route protocol bgp' for the full table\n",
				maxBGPRoutes))
		}
		// json.Encoder appends a trailing newline; preserve it for
		// byte-equivalence with the previous buffered response.
		io.WriteString(bw, "\"}}\n")
		bw.Flush()
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	default:
		var b strings.Builder
		peers, err := s.frr.GetBGPSummary(r.Context())
		if err != nil {
			writeFRRError(w, err)
			return
		}
		fmt.Fprintf(&b, "%-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
			"Neighbor", "AF", "AS", "MsgRcvd", "MsgSent", "Up/Down", "State", "PfxRcd")
		for _, p := range peers {
			fmt.Fprintf(&b, "%-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
				p.Neighbor, p.AddressFamily, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State, p.PfxRcd)
		}
		writeOK(w, TextResponse{Output: b.String()})
	}
}

// writeJSONStringFragment writes s to w with exactly the escaping
// encoding/json applies inside a JSON string literal (HTML-safe by default:
// the "<", ">" and "&" bytes are emitted as their \uXXXX escapes, the same as
// the default json.Encoder used by writeJSON), but without the surrounding
// quotes.
// Because encoding/json escapes strings byte-by-byte with no cross-byte state,
// concatenating the fragments is byte-for-byte identical to escaping the
// concatenated string. Used to stream a large response without materializing
// the whole escaped payload in memory. json.Marshal never fails for a string.
func writeJSONStringFragment(w io.Writer, s string) {
	esc, err := json.Marshal(s)
	if err != nil {
		return
	}
	// esc is `"...escaped..."`; drop the surrounding quotes.
	w.Write(esc[1 : len(esc)-1])
}
