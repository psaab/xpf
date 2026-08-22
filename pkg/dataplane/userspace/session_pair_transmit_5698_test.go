// #5698 (bounded half): the forward+reverse session pair built by
// mirrorSessionPairV4 / mirrorSessionPairV6 must reach the Rust helper's
// session socket with NOTHING in between.
//
// Before the fix the pair was transmitted by syncSessionRequestsLocked, which
// drops m.mu ONCE and then LOOPS calling requestSessionSync per request — and
// requestSessionSync acquires and releases m.sessionMu around EACH round trip.
// So m.sessionMu was FREE between the forward's reply and the reverse's dial,
// and any other session-socket mutation (an operator clear, a policy
// invalidation, a GC delete, a stale-session reconciliation) could land BETWEEN
// the halves. A generation-0 forward delete landing there removes both halves
// in the helper, and the pair's already-built explicit reverse then re-creates
// a standalone reverse-only permit.
//
// The fix routes ONLY the pair mirrors through syncSessionPairLocked, which
// takes m.sessionMu ONCE for the whole (bounded) group.
//
// WHY THIS TEST IS DETERMINISTIC IN BOTH DIRECTIONS — the competitor loop and
// the per-reply hold are BOTH load-bearing; do not "simplify" either away:
//
//   - GREEN direction is deterministic BY CONSTRUCTION. With the fix,
//     sessionMu is never released between the two halves, so no competing
//     session-socket request can be interleaved no matter how the scheduler
//     runs. Zero violations is not a probability, it is an impossibility.
//
//   - RED direction is forced by Go's sync.Mutex STARVATION MODE. A plain
//     one-shot race would NOT fail reliably: on the first Unlock the runtime
//     merely wakes the waiter, and the unlocking goroutine (the pair loop) then
//     BARGES and re-acquires for the reverse before the woken competitor is
//     ever scheduled — that is exactly how the first draft of this test passed
//     against the unfixed code. Starvation mode is what removes barging: once a
//     waiter has been blocked for more than 1ms and re-queued, the mutex sets
//     its starving bit, after which Lock's fast path is disabled and a new
//     locker MUST queue behind the existing waiter, and Unlock hands the mutex
//     DIRECTLY to the head waiter. sessionPairReplyHold (well above the 1ms
//     starvation threshold) applied to every reply, plus a competitor that
//     re-contends in a tight loop, keeps sessionMu in starvation mode for the
//     whole run — so with the bug the competitor deterministically wins the gap
//     the pair opens between its halves, on every pair after the first.
//
// FAIL-ON-REVERT: point mirrorSessionPairV4 (or ...V6) back at
// syncSessionRequestsLocked and this test fails with
// "session-sync request ... interleaved BETWEEN the pair's forward and its
// reverse".
package userspace

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

const (
	// sessionPairReplyHold is how long the fake helper holds EVERY reply before
	// answering. It must comfortably exceed Go's 1ms mutex starvation
	// threshold: any goroutine that blocks on sessionMu while a round trip is
	// in flight then waits >1ms, which is what puts (and keeps) the mutex in
	// starvation mode and removes the barging that would otherwise let the
	// unfixed pair loop re-acquire sessionMu ahead of a parked competitor.
	sessionPairReplyHold = 2 * time.Millisecond
	// sessionPairInstalls is how many pairs the test mirrors. More than a
	// couple is only belt-and-braces: with the bug the very first pair after
	// the mutex enters starvation mode is already interleaved.
	sessionPairInstalls = 12
	// sessionPairCompetitors is how many goroutines hammer the session socket
	// alongside the pair. It MUST be >1. Go clears the mutex's starving bit on
	// a direct hand-off when the woken waiter is the LAST one
	// (`old>>mutexWaiterShift == 1`), so a single competitor lets the mutex
	// fall back to barge-friendly normal mode on every hand-off and the unfixed
	// pair loop then re-acquires ahead of it every time — a false green. With
	// two or more waiters queued the starving bit SURVIVES the hand-off, which
	// is what keeps barging disabled across the gap the unfixed pair opens.
	sessionPairCompetitors = 3
)

// sessionPairRecorder is a fake session socket that records the arrival ORDER
// of sync_session requests and flags any request that lands between a pair's
// forward and its reverse.
//
// Ordering is exact, not sampled: every sender (the pair mirror AND the
// competitor) holds sessionMu across its whole round trip, and this recorder
// appends BEFORE it replies — so append(i) happens-before reply(i)
// happens-before that sender's unlock happens-before the next sender's dial.
// At most one request is ever in flight.
type sessionPairRecorder struct {
	mu         sync.Mutex
	order      []string
	violations []string
	// firstViolationAt is the arrival index of the first interleaved request,
	// used to print a readable window instead of the whole (long) order.
	firstViolationAt int
	pairs            int
	// pendingForward is true once a forward has been recorded and its reverse
	// has not yet arrived.
	pendingForward bool
}

// classifySessionSyncReq labels a received request. The pair's two halves are
// "upsert" (forward / reverse); the competitor issues the only "delete".
func classifySessionSyncReq(req *SessionSyncRequest) string {
	switch {
	case req == nil:
		return "malformed"
	case req.Operation == "delete":
		return "competitor-delete"
	case req.IsReverse:
		return "reverse"
	default:
		return "forward"
	}
}

func (r *sessionPairRecorder) record(label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, label)
	if r.pendingForward && label != "reverse" {
		if len(r.violations) == 0 {
			r.firstViolationAt = len(r.order) - 1
		}
		r.violations = append(r.violations, fmt.Sprintf(
			"%q at position %d", label, len(r.order)-1))
	}
	switch label {
	case "forward":
		r.pendingForward = true
	case "reverse":
		if r.pendingForward {
			r.pairs++
		}
		r.pendingForward = false
	}
}

// orderWindow renders a readable slice of the arrival order centred on idx, so
// a failure names the offending neighbourhood instead of dumping every request.
func orderWindow(order []string, idx int) []string {
	const radius = 4
	lo := idx - radius
	if lo < 0 {
		lo = 0
	}
	hi := idx + radius + 1
	if hi > len(order) {
		hi = len(order)
	}
	return order[lo:hi]
}

func (r *sessionPairRecorder) serve(ln net.Listener) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				r.record(classifySessionSyncReq(req.SessionSync))
				// Hold the reply so any goroutine blocked on sessionMu crosses
				// the 1ms starvation threshold. See the file header.
				time.Sleep(sessionPairReplyHold)
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}(conn)
		}
	}()
}

// newSessionPairManager wires a Manager to a fake session socket in a SHORT
// temp dir. t.TempDir() embeds the (long) test name, and sessionSocketPath()
// appends the fixed "userspace-dp-sessions.sock" basename, which together can
// blow the 108-byte sun_path limit ("bind: invalid argument").
func newSessionPairManager(t *testing.T, r *sessionPairRecorder) *Manager {
	t.Helper()
	dir, err := os.MkdirTemp("", "x5698")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	ln, err := net.Listen("unix", filepath.Join(dir, "userspace-dp-sessions.sock"))
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	r.serve(ln)

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	m.lastSnapshot = &ConfigSnapshot{}
	return m
}

// startSessionMuCompetitor runs the goroutine that races the pair. It issues
// delete-shaped requests through the PRODUCTION entry point
// (Manager.requestSessionSync) in a tight loop, so it contends for sessionMu
// exactly the way an operator clear / GC delete / stale-session reconciliation
// does. The returned func stops it and waits.
func startSessionMuCompetitors(m *Manager) func() {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(sessionPairCompetitors)
	for i := 0; i < sessionPairCompetitors; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = m.requestSessionSync(ControlRequest{
					Type:           "sync_session",
					SuppressStatus: true,
					SessionSync: &SessionSyncRequest{
						Operation:  "delete",
						AddrFamily: dataplane.AFInet,
						Protocol:   6,
						SrcIP:      "10.0.61.55",
						DstIP:      "172.16.80.201",
						SrcPort:    40000,
						DstPort:    5201,
					},
				})
			}
		}()
	}
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		wg.Wait()
	}
}

// assertPairsContiguous is the shared verdict for the v4 and v6 cases.
func (r *sessionPairRecorder) assertPairsContiguous(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	violations := append([]string(nil), r.violations...)
	order := append([]string(nil), r.order...)
	pairs := r.pairs
	firstViolationAt := r.firstViolationAt
	r.mu.Unlock()

	// Guard against a vacuous green: the loop must actually have mirrored
	// every pair, and the competitor must actually have been on the socket.
	if pairs != sessionPairInstalls {
		t.Fatalf("recorder saw %d complete forward+reverse pairs, want %d; order=%v",
			pairs, sessionPairInstalls, orderWindow(order, len(order)/2))
	}
	competitors := 0
	for _, l := range order {
		if l == "competitor-delete" {
			competitors++
		}
	}
	if competitors == 0 {
		t.Fatalf("the competing session-socket requests never reached the helper, "+
			"so nothing raced the pair — the test proves nothing; order=%v",
			orderWindow(order, len(order)/2))
	}
	if len(violations) != 0 {
		t.Fatalf("%d session-sync request(s) interleaved BETWEEN the pair's forward "+
			"and its reverse (first: %v). sessionMu was released between the two halves, "+
			"so an unrelated session mutation landed INSIDE the pair (#5698). The pair "+
			"mirrors must transmit through syncSessionPairLocked, which holds sessionMu "+
			"for the whole pair. Arrival order around the first violation: %v",
			len(violations), violations[0], orderWindow(order, firstViolationAt))
	}
}

func TestSessionPairTransmitIsContiguous_5698(t *testing.T) {
	r := &sessionPairRecorder{}
	m := newSessionPairManager(t, r)
	stop := startSessionMuCompetitors(m)
	defer stop()

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey: dataplane.SessionKey{
			SrcIP:    [4]byte{172, 16, 80, 200},
			DstIP:    [4]byte{10, 0, 61, 102},
			SrcPort:  hostToNetwork16(5201),
			DstPort:  hostToNetwork16(50952),
			Protocol: 6,
		},
	}
	for i := 0; i < sessionPairInstalls; i++ {
		m.mirrorSessionPairV4(key, val)
	}
	stop()
	r.assertPairsContiguous(t)
}

// The IPv6 pair is a SEPARATE call site (mirrorSessionPairV6) with its own
// transmit line, so it needs its own binding: pointing only V4 at
// syncSessionPairLocked would leave the v6 pair interleavable, and this test is
// what catches that.
func TestSessionPairTransmitIsContiguousV6_5698(t *testing.T) {
	r := &sessionPairRecorder{}
	m := newSessionPairManager(t, r)
	stop := startSessionMuCompetitors(m)
	defer stop()

	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xbf, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x02},
		DstIP:    [16]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey: dataplane.SessionKeyV6{
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  hostToNetwork16(5201),
			DstPort:  hostToNetwork16(50952),
			Protocol: 6,
		},
	}
	for i := 0; i < sessionPairInstalls; i++ {
		m.mirrorSessionPairV6(key, val)
	}
	stop()
	r.assertPairsContiguous(t)
}

// TestSessionPairOversizedGroupFallsBack_5698 pins the guard on the contiguous
// path: a group larger than sessionPairMaxRequests must NOT be transmitted
// under one sessionMu hold (that would starve live session installs — the
// #5380 harm), and must NOT be silently dropped either. It falls back to
// syncSessionRequestsLocked's per-request locking, so every request still
// reaches the helper.
//
// FAIL-ON-REVERT: make the oversized branch `return errors.New(...)` (or drop
// the requests) and this test fails on the received count.
func TestSessionPairOversizedGroupFallsBack_5698(t *testing.T) {
	r := &sessionPairRecorder{}
	m := newSessionPairManager(t, r)

	reqs := make([]SessionSyncRequest, sessionPairMaxRequests+1)
	for i := range reqs {
		reqs[i] = SessionSyncRequest{Operation: "upsert", AddrFamily: dataplane.AFInet}
	}
	m.mu.Lock()
	err := m.syncSessionPairLocked(reqs...)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("oversized group returned %v; the fallback must still transmit", err)
	}

	r.mu.Lock()
	got := len(r.order)
	r.mu.Unlock()
	if got != len(reqs) {
		t.Fatalf("helper received %d of %d requests from an oversized group; the "+
			"over-cap branch must fall back to per-request locking, not drop or "+
			"refuse the group (#5698)", got, len(reqs))
	}
}
