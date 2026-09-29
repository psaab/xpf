package cluster

// Peer boot incarnation on the config-sync wire (#5084, plan #5480).
//
// THE DEFECT. `configApplyItem` carried only {gen, text}. When a peer reboots
// and re-primes, `resetRecvGen` zeroes the last-applied high-water but does not
// drain items already queued from the PRIOR boot. An old-boot item can apply
// after the reset and record a high high-water, after which the rebooted peer's
// lower-generation CURRENT config is refused as stale — persistent HA
// policy/routing divergence, healed only by another commit or reconnect.
//
// WHY THE OBVIOUS FIX IS WRONG, AND WAS TRIED. PR #6900 fenced on
// `configNamespaceConnID`, a floor over the per-connection `syncConnID`
// counter, and failed across seven review rounds. The post-mortem in one line:
//
//	`syncConnID` is a total ORDER over connections. The predicate the guard
//	needs is an EQUIVALENCE — were these two payloads produced by the same peer
//	boot? — because config generations are comparable only within one sender
//	incarnation. A ranking cannot express an equivalence, and the floor has no
//	correct setting: never descending locks out a live same-incarnation sibling
//	that merely connected earlier, while descending re-admits departed
//	older-incarnation connections and makes the floor a mutable target an
//	in-flight resetRecvGen can reclaim.
//
// Do not re-derive that. The converged design is
// `docs/peer-boot-incarnation-plan.md`.
//
// THE GRANULARITY IS FORCED, NOT CHOSEN. `initGenState` seeds
// `configGenCounter` from `MonotonicNanos()` so generations survive a daemon
// restart WITHIN a boot; they become incomparable exactly when CLOCK_MONOTONIC
// restarts, i.e. on OS boot. So the incarnation must change exactly on OS boot —
// not per process, not per connection. `/proc/sys/kernel/random/boot_id` is a
// 128-bit UUID the kernel regenerates per boot, stable for that boot, readable
// unprivileged, unchanged by a daemon restart. It matches exactly.
//
// COMPARE FOR EQUALITY ONLY. The value is opaque. Never order two boot ids —
// ordering is precisely the property established as unable to carry this
// meaning. "Which incarnation is current" is answered by WHICH ONE PRIMED.
//
// WHERE IT GOES. The `syncMsgBulkStart` payload grows 8 -> 24 bytes: the
// existing little-endian epoch, then 16 raw boot-id bytes. BulkStart is where
// the value is CONSUMED — the prime is the claim event — so there is no window
// in which a connection is installed but its incarnation is unknown. The auth
// HELLO was rejected as a carrier: `performSyncHandshake` returns immediately
// when `len(key) == 0`, so on an UNKEYED cluster a HELLO-carried incarnation
// would not exist at all and the guard would be silently absent — a
// configuration-dependent security property.
//
// FAIL OPEN on an absent incarnation, and that is a decision, not a default.
// A payload with no incarnation gets exactly today's generation-only ordering.
// The fallback is `origin/master`'s behaviour, not a weakened version of it; it
// is the convention every legacy sentinel in this package already uses
// (`gen == 0`, `epoch == 0`, `incarnation == 0 || seq == 0`); and failing closed
// would refuse ALL config from a not-yet-upgraded peer for the whole
// rolling-upgrade window, stranding the standby — strictly worse than the bug.
//
// It is also NOT a security decision. The incarnation is not an authorisation
// token and grants nothing; a peer that omits it gets what an old build gets.
// The authentication boundary is the PSK handshake and the frame HMAC, both
// untouched.
//
// THE KNOWN RESIDUAL, SHIPPED BOUNDED RATHER THAN CLOSED (plan §7). A
// pre-reboot socket that is half-open and has not yet errored can still hold a
// buffered BulkStart from the DEAD incarnation. If that frame lands after the
// new incarnation has primed, rule 1 switches the namespace BACK, and config
// from the live incarnation is then dropped until the next prime re-switches
// it. The window is bounded by the receive loop, not by chance: `receiveLoop`
// arms a 10s read deadline and gives up at `missedHeartbeats >= 2`, so such a
// socket self-evicts within ~20s of silence — and an OS reboot, which is the
// only thing that changes an incarnation, outlasts that window, so the frame is
// hard to produce at all. It is also SELF-HEALING: the peer re-pushes its
// current config on the reconnect that follows, and the drop is counted in
// ConfigsDeadIncarnationDropped and rendered in cluster status.
//
// Closing it rather than bounding it means a receiver-local strictly-increasing
// "namespace claim ordinal" bumped on each switch, with a switch refused from a
// connection whose slot is no longer installed. That is deliberately NOT done
// here: it is the same add-an-ordering instinct that produced #6900, and it
// should be added against a demonstrated failure, not pre-emptively. Operator
// documentation: docs/sync-protocol.md, "Peer boot incarnation".
//
// THE CONTINGENCY, recorded per the plan so a later reviewer knows what they
// would be signing up for: if a future requirement demands that an
// un-incarnated peer be REFUSED, that forces either a flag day or making the
// keyed handshake mandatory, because an upgraded receiver cannot distinguish
// "old peer that cannot send the field" from "peer suppressing the field"
// without a negotiated capability — and a negotiated capability has nowhere to
// live on the unkeyed path. Both are decisions well outside #5084.

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
)

// bootIncarnationLen is the raw byte length of a boot id (a 128-bit UUID).
const bootIncarnationLen = 16

// bootIncarnation is a peer boot identity. The zero value means
// "un-incarnated" — either a peer that predates this, or a local read failure.
type bootIncarnation [bootIncarnationLen]byte

// known reports whether this is a real incarnation rather than the
// un-incarnated sentinel.
func (b bootIncarnation) known() bool { return b != bootIncarnation{} }

// String renders the incarnation for operator output. Opaque and safe to log:
// a boot id is not a secret, and it is the only handle an operator has for
// "which peer boot is this".
func (b bootIncarnation) String() string {
	if !b.known() {
		return "none"
	}
	return hex.EncodeToString(b[:])
}

// bootIDPath is the kernel's per-boot UUID. A var so a test can point it
// elsewhere; production never reassigns it.
var bootIDPath = "/proc/sys/kernel/random/boot_id"

var (
	localBootOnce sync.Once
	localBootID   bootIncarnation
)

// localBootIncarnation returns this node's boot id, read once and cached.
//
// A read or parse failure yields the ZERO value, which puts this node in the
// un-incarnated class — the same fail-open posture as an old peer, and the only
// safe answer: a synthesised or random substitute would be a value that changes
// when it must not, making every reconnect look like a reboot and clearing the
// peer's high-water on a node that never rebooted.
func localBootIncarnation() bootIncarnation {
	localBootOnce.Do(func() { localBootID = readBootIncarnation(bootIDPath) })
	return localBootID
}

// readBootIncarnation parses a boot_id file. Returns the zero value on any
// failure.
func readBootIncarnation(path string) bootIncarnation {
	var out bootIncarnation
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	// The kernel renders it as a dashed UUID with a trailing newline.
	text := strings.TrimSpace(string(raw))
	text = strings.ReplaceAll(text, "-", "")
	if len(text) != bootIncarnationLen*2 {
		return out
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return out
	}
	copy(out[:], decoded)
	return out
}

// appendBootIncarnation extends a BulkStart payload with this node's
// incarnation, per the #2170 trailing-field discipline every prior extension in
// this protocol used (`syncMsgBulkStart` gates on `len >= 8`, the delete frames
// on `>= 24` / `>= 48`). An old receiver reads payload[:8] and ignores the tail;
// the HMAC trailer covers the whole payload, so the authenticated path needs no
// change.
//
// A node whose own boot id could not be read appends NOTHING rather than 16
// zero bytes: an explicit zero would be indistinguishable on the wire from a
// real incarnation the receiver must compare against, and the absent-field path
// is the one already specified to fail open.
//
// `local` is a parameter rather than an internal `localBootIncarnation()` call
// so the unreadable-boot-id arm is reachable from a test without mutating the
// process-wide cache; the single production call site passes
// `localBootIncarnation()`.
func appendBootIncarnation(payload []byte, local bootIncarnation) []byte {
	if !local.known() {
		return payload
	}
	return append(payload, local[:]...)
}

// parseBootIncarnation extracts the incarnation from a BulkStart payload, or
// the zero value when the peer sent the legacy 8-byte form.
func parseBootIncarnation(payload []byte) bootIncarnation {
	var out bootIncarnation
	if len(payload) < 8+bootIncarnationLen {
		return out
	}
	copy(out[:], payload[8:8+bootIncarnationLen])
	return out
}

// notePeerBootIncarnation applies rules 1 and 2 of the plan's §6 to a BulkStart
// that has just arrived, and reports whether the namespace SWITCHED.
//
//	rule 1  an incarnation DIFFERENT from the current one switches the
//	        namespace: the caller clears the generation high-waters (which
//	        resetRecvGen already does) and this records the new incarnation.
//	rule 2  the SAME incarnation is a mid-connection re-prime (the #5450 forced
//	        resync) and must NOT invalidate queued payloads — same incarnation,
//	        comparable generations. This is the case #6900's equal-id exemption
//	        was approximating.
//
// An un-incarnated prime records nothing and switches nothing: it leaves any
// incarnation already learned in place, so a peer that primes once with an
// incarnation and once without does not lose the fence. That asymmetry is
// deliberate — the absent field means "no information", not "a different boot".
func (s *SessionSync) notePeerBootIncarnation(inc bootIncarnation) (switched bool) {
	if !inc.known() {
		s.stats.BulkPrimesWithoutIncarnation.Add(1)
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peerBootIncarnation == inc {
		return false
	}
	if s.peerBootIncarnation.known() {
		// A genuinely new peer boot invalidates the old boot's apply ACK.
		s.peerAppliedConfigGen.Store(0)
	}
	s.peerBootIncarnation = inc
	return true
}

// PeerBootIncarnation returns the incarnation of the peer boot that most
// recently primed, or the zero value when none has. Safe to render.
func (s *SessionSync) PeerBootIncarnation() bootIncarnation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerBootIncarnation
}

// configItemIncarnationStale applies rule 3: a queued payload whose incarnation
// differs from the current one is dead PERMANENTLY and is never re-admitted.
//
// Rule 4 is the `!known()` arm: an un-incarnated payload is never dropped on
// incarnation grounds.
//
// Rule 3 is also what removes the hazard that killed #6900 — there, skipping a
// payload also skipped the generation gate, so a dropped payload could strand
// the high-water. Here a dropped payload comes from a DEAD incarnation whose
// generations are incomparable with the current one, so its generation carries
// no information the current high-water needs. That is true only because
// membership is an equivalence rather than a ranking.
func (s *SessionSync) configItemIncarnationStale(item configApplyItem) bool {
	if !item.incarnation.known() {
		return false
	}
	current := s.PeerBootIncarnation()
	if !current.known() {
		// Nothing has primed with an incarnation yet, so there is no namespace
		// to be outside of.
		//
		// UNREACHABLE while the two records are made together: the only writer
		// of a connection's stamp is noteConnBootIncarnation, called from the
		// same BulkStart arm that calls notePeerBootIncarnation, so an item
		// cannot carry an incarnation the receiver has never seen. A mutation
		// flipping this arm to `true` therefore changes nothing observable —
		// it is kept as an explicit FAIL-OPEN so that if a future change ever
		// splits the two records, the outcome is today's generation-only
		// ordering rather than every payload being dropped against a namespace
		// that does not exist.
		return false
	}
	return !bytes.Equal(item.incarnation[:], current[:])
}

// noteConnBootIncarnation records the incarnation a BulkStart on this
// connection primed under. An un-incarnated prime records nothing, leaving any
// incarnation the connection already learned in place: the absent field means
// "no information", not "a different boot".
//
// Guarded by s.mu, like every other per-connection field.
func (s *SessionSync) noteConnBootIncarnation(conn net.Conn, inc bootIncarnation) {
	ac, ok := conn.(*authConn)
	if !ok || !inc.known() {
		return
	}
	s.mu.Lock()
	ac.bootIncarnation = inc
	s.mu.Unlock()
}

// connBootIncarnation returns the incarnation this connection primed under, or
// the zero value for a connection that never received an incarnated prime —
// including the second fabric, which may carry config without having primed.
// Zero puts the payload in the never-dropped class (plan §6 rule 4), which is
// the correct fail-open answer: no prime means no evidence of which boot the
// payload belongs to.
func (s *SessionSync) connBootIncarnation(conn net.Conn) bootIncarnation {
	ac, ok := conn.(*authConn)
	if !ok {
		return bootIncarnation{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return ac.bootIncarnation
}

// warnUnincarnatedPrimeOnce emits the fail-open notice a single time per
// connection. Per the plan, observability here is mandatory rather than
// optional: the fallback is silent by construction, and a half-upgraded cluster
// that hides is the failure mode.
func (s *SessionSync) warnUnincarnatedPrimeOnce(conn net.Conn) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	s.mu.Lock()
	already := ac.unincarnatedWarned
	ac.unincarnatedWarned = true
	s.mu.Unlock()
	if already {
		return
	}
	slog.Warn("cluster sync: peer primed without a boot incarnation — config ordering on this "+
		"connection falls back to generation-only, exactly as before #5084. Expected while the "+
		"peer is on an older build; if both nodes are upgraded, investigate.",
		"remote", connRemoteAddrString(conn))
}
