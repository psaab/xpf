package userspace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// MaxControlRequestBytes is the maximum serialized size, in bytes, of a
// single control-socket request body. It MUST stay in lockstep with the
// Rust receiver's MAX_CONTROL_REQUEST_BYTES in
// userspace-dp/src/protocol/control.rs: the helper reads at most this
// many bytes (plus the terminating newline) before rejecting a request
// before decode (#2523). A sender that emits a body larger than the
// receiver's cap is rejected at the read, so the two caps move together.
//
// #2744 sized this off the dominant scaling dimension — dynamic-feed
// address books carry feed prefixes inline as CIDR text and are bounded
// only by a per-line scanner cap, not a total-entry cap. 64 MiB / ~45 B
// per IPv6 CIDR ≈ 1.4M prefixes, comfortably above realistic large
// threat-intel feeds (the #2744 case cited ~500K prefixes ≈ 20+ MiB,
// which the original 16 MiB ceiling rejected). The cap remains a hard
// allocation ceiling: a request larger than this is surfaced as a
// config error here (a real operator-facing diagnostic) instead of a
// silent control-socket rejection after a successful commit.
const MaxControlRequestBytes = 64 * 1024 * 1024

const (
	// controlBaseDeadline is the round-trip read/write deadline for a SMALL
	// control-socket request (the 1/s status poll, forwarding arm/disarm,
	// HA-state push, per-session install, ...). It is preserved unchanged at
	// the historical 3s so the frequent status poll stays responsive per the
	// #182 control-socket-contention discipline: a sub-1-MiB request gets
	// exactly this deadline, no more.
	controlBaseDeadline = 3 * time.Second
	// controlDeadlinePerMiB is the additional round-trip budget granted per
	// mebibyte of serialized request body. A large apply_snapshot — up to
	// MaxControlRequestBytes (64 MiB, #2744) of feed-backed address-book CIDR
	// text — needs the helper to receive, JSON-decode, and APPLY the whole
	// body (building the address-book LPM tables, planning bindings,
	// reconciling AF_XDP) and then write its response inside the deadline.
	// A fixed 3s falsely timed a large apply out (#4036): Go reported the
	// apply FAILED while the Rust helper had actually applied the snapshot and
	// the dataplane was forwarding live with the new config — a spurious
	// commit failure / needless rollback / false HA dp-failure.
	controlDeadlinePerMiB = 1 * time.Second
	// controlMaxDeadline caps the scaled deadline so a genuinely-hung helper
	// still eventually times out rather than blocking the caller (which holds
	// m.mu across the round-trip) forever.
	//
	// IT IS NOT THE REACHABLE BOUND, AND MUST NOT BE QUOTED AS ONE. The only
	// production caller of controlRoundtripDeadline is requestDetailedLocked
	// below, strictly AFTER the #2744 pre-flight rejects a body over
	// MaxControlRequestBytes — so the largest body that ever reaches the sizing
	// function is 64 MiB, giving base + 64s = 67s. This 120s clamp only binds
	// on a body that cannot occur, and exists so the sizing function is total.
	//
	// The reachable bound is what any stop-budget analysis must use: 67s
	// against the unit's TimeoutStopSec=20 is a 3.35x overrun, not the 6x that
	// reading this constant alone suggests. #7675 made exactly that error and
	// promoted the inflated figure into a design constraint;
	// control_deadline_reachable_bound_7675_test.go pins the reachable bound,
	// the pre-flight ordering it depends on, and the ratio band.
	controlMaxDeadline = 120 * time.Second
)

// errSessionHelperUnreachable classifies a session-socket round-trip that
// failed at the TRANSPORT layer (dial, write, or read) rather than being
// rejected by the helper's handler. syncSessionRequestsLocked uses it to abort
// a bulk batch early (#5380): if one request cannot complete a round-trip, the
// helper is down or hung and every remaining request in the same batch would
// pay the full per-request deadline too. A bulk delete chunk is up to
// sessionHelperDeleteChunk (256) requests, so without the early abort a single
// hung helper stalls the whole batch for ~256 * sessionSyncRoundtripDeadline
// (~13 min) while repeatedly holding sessionMu — starving live session
// installs. An APPLICATION-level rejection (the helper answered but set
// resp.OK=false for this one request) is NOT wrapped with this sentinel, so the
// batch keeps going: the helper is alive and only this request was refused.
var errSessionHelperUnreachable = errors.New("session helper unreachable")

// syncedImportRefusedPrefix is the machine-readable token the helper prefixes
// onto a SEMANTIC synced-import refusal (SYNCED_IMPORT_REFUSED_PREFIX in
// userspace-dp/src/afxdp/ha/session_import.rs). The two spellings must agree;
// TestSyncedImportRefusedPrefixMatchesTheHelper asserts the AGREEMENT by
// reading the Rust constant rather than pinning either side to a literal, so a
// rename on either side reds instead of silently reclassifying every refusal as
// a transport failure.
const syncedImportRefusedPrefix = "synced-import-refused:"

// sessionSyncDialTimeout and sessionSyncRoundtripDeadline bound a single
// session-socket round-trip so a hung helper fails one mirror request in a few
// seconds instead of the OS default (which can be minutes). They match the
// per-session control-socket convention (2s dial, controlBaseDeadline 3s
// round-trip). They are package vars, not consts, ONLY so the #5380 hung-helper
// regression test can shrink them to keep its bulk-batch timing fast; nothing
// in production mutates them.
var (
	sessionSyncDialTimeout       = 2 * time.Second
	sessionSyncRoundtripDeadline = controlBaseDeadline
)

// controlRoundtripDeadline sizes the control-socket read/write deadline to the
// serialized request length so a large apply_snapshot is not falsely timed out
// (#4036). It is a pure function of the body length: a sub-1-MiB request keeps
// the base deadline (small requests unchanged — the status poll stays
// responsive), and each additional mebibyte adds controlDeadlinePerMiB up to
// controlMaxDeadline. The deadline is generous enough for a legitimate 64 MiB
// feed-heavy apply while still bounding a hung helper.
func controlRoundtripDeadline(bodyLen int) time.Duration {
	if bodyLen < 0 {
		bodyLen = 0
	}
	// floor(bodyLen / 1 MiB): 0 for any request under 1 MiB, so small
	// requests keep exactly controlBaseDeadline.
	mib := bodyLen >> 20
	d := controlBaseDeadline + time.Duration(mib)*controlDeadlinePerMiB
	if d > controlMaxDeadline {
		d = controlMaxDeadline
	}
	return d
}

func (m *Manager) requestDetailedLocked(req ControlRequest) (ControlResponse, error) {
	if m.cfg.ControlSocket == "" {
		return ControlResponse{}, errors.New("userspace dataplane control socket not configured")
	}
	// Pre-flight size check (#2744). Serialize the request once and reject
	// it here if it would exceed the receiver's cap, so the operator sees
	// an actionable config error at apply time rather than a silent
	// control-socket EOF after the config is already committed. The most
	// common offender is a feed-heavy apply_snapshot whose inline feed
	// prefixes push the body past MaxControlRequestBytes.
	body, err := json.Marshal(&req)
	if err != nil {
		return ControlResponse{}, err
	}
	if len(body) > MaxControlRequestBytes {
		return ControlResponse{}, fmt.Errorf(
			"userspace control request %q is %d bytes, exceeding the dataplane "+
				"control-socket limit of %d bytes; this is most often a "+
				"dynamic-address feed with too many prefixes — reduce the feed "+
				"size or split the address book (the dataplane would reject this "+
				"request before applying it)",
			req.Type, len(body), MaxControlRequestBytes)
	}
	// #9003: SO_PEERCRED before a single byte is written. `apply_snapshot`
	// carries the WireGuard local private key and every per-peer preshared key
	// in CLEARTEXT (tunnels.go), so "whoever holds this path" is not an
	// acceptable answer to "who am I talking to". The check is race-free where a
	// path check is not: the kernel answers for the socket THIS connection is
	// attached to, so swapping the path between a stat and the connect defeats
	// nothing.
	conn, err := dialTrustedHelperSocket("control socket", m.cfg.ControlSocket, 2*time.Second)
	if err != nil {
		return ControlResponse{}, err
	}
	defer conn.Close()
	// Size the round-trip deadline to the request body (#4036). A fixed 3s was
	// too short for a large apply_snapshot (up to MaxControlRequestBytes / 64
	// MiB of feed-backed address-book CIDRs): the helper receives+decodes+
	// applies the whole body before replying, which can exceed 3s, so Go timed
	// out and reported the apply FAILED while the dataplane had applied it live.
	// controlRoundtripDeadline keeps the 3s base for small requests (status
	// poll stays responsive) and scales up for a large apply, capped so a hung
	// helper still times out.
	//
	// #8526: the deadline is applied through armControlIO rather than set
	// directly, so a stop in progress can bound it. EVERY *Manager method that
	// holds m.mu across a control round trip reaches the socket here, so this
	// single site is what keeps a 67s hold from outrunning the unit's 20s
	// TimeoutStopSec. See control_shutdown_8526.go; the census and the
	// single-site property are asserted, not asserted-by-comment, in
	// control_shutdown_census_8526_test.go.
	// #9344: the deadline is sized off the body AND raised to the verb's work
	// floor. `export_owner_rg_sessions` carries a ~60-byte body and so got the
	// 3 s small-request base, while the helper spends up to 15 s waiting for
	// worker acks before writing its first byte — the caller could abandon a
	// round trip the helper was still legitimately performing.
	m.armControlIO(conn, controlWorkDeadline(req.Type, len(body)))
	defer m.releaseControlIO(conn)
	// Reuse the pre-flight-serialized body; the Rust receiver frames on a
	// single trailing newline (json.Encoder appends one).
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return ControlResponse{}, err
	}
	var resp ControlResponse
	// #9003: byte-bounded, not merely deadline-bounded. Over AF_UNIX a 3 s
	// deadline still admits GB-scale allocation at memory bandwidth, and
	// ControlResponse retains four unbounded slice fields.
	bounded := boundedResponseReader(conn)
	if err := json.NewDecoder(bufio.NewReader(bounded)).Decode(&resp); err != nil {
		// #9322: the cap is checked FIRST. A truncated body reaches
		// json.Decoder as io.ErrUnexpectedEOF, byte-identical to a helper that
		// died mid-write, so without this the #1961 sentence below claims the
		// helper rejected a request it actually ANSWERED — and sends the
		// operator to a helper log with nothing in it.
		if bounded.truncated {
			return ControlResponse{}, responseCapError(req.Type, err)
		}
		// A bare EOF here means the helper closed the socket without writing a
		// response — it rejected the request before replying (e.g. a request
		// that failed to decode, like the #1961 wire-type mismatch). Surface an
		// actionable hint instead of the opaque "EOF" that masked #1961 across
		// multiple sessions.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ControlResponse{}, fmt.Errorf(
				"control socket closed with no response to %q request (EOF); the "+
					"helper rejected it before replying — check the helper log "+
					"for a decode/handler error: %w", req.Type, err)
		}
		return ControlResponse{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return ControlResponse{}, newHelperRejection(resp.Error)
	}
	return resp, nil
}

// errHelperRejected marks an IN-BAND refusal: the helper decoded the request,
// ran its handler (for apply_snapshot, the non-mutating integrity preflight)
// and answered `{"ok":false}`. It is the ONLY error class from which "the
// helper still holds the state it held before this request" follows.
//
// Every other failure of a control round trip — dial, write, response-decode,
// EOF, deadline — leaves the helper's state UNKNOWN, and not merely in
// principle: controlRoundtripDeadline exists because a fixed 3s deadline
// "reported the apply FAILED while the dataplane had applied it live"
// (requestDetailedLocked above). Treating that as "the helper kept the old
// snapshot" is precisely the inversion that turns a fail-closed compensation
// into a fail-open one, which is why #7468's atomic retain is gated on this
// sentinel and not on `err != nil`.
var errHelperRejected = errors.New("userspace helper rejected the request")

// helperRejectedError carries the helper's own message VERBATIM while matching
// errHelperRejected under errors.Is.
//
// A wrapping fmt.Errorf("%w: %s", ...) would prepend a prefix to every in-band
// refusal the helper can produce, changing operator-facing text on paths that
// have nothing to do with #7468. The classification is new information about an
// existing error, so it is added beside the message rather than in front of it.
type helperRejectedError struct{ msg string }

func newHelperRejection(msg string) error { return &helperRejectedError{msg: msg} }

func (e *helperRejectedError) Error() string { return e.msg }

func (e *helperRejectedError) Is(target error) bool { return target == errHelperRejected }

// sessionSocketPath returns the path to the dedicated session sync socket.
func (m *Manager) sessionSocketPath() string {
	if m.cfg.ControlSocket == "" {
		return ""
	}
	dir := filepath.Dir(m.cfg.ControlSocket)
	return filepath.Join(dir, "userspace-dp-sessions.sock")
}

// requestSessionSync sends a session sync request via the dedicated session
// socket, using sessionMu instead of mu. This ensures session installs from
// HA sync never block behind snapshot publishes on the main control socket.
//
// It is the per-request locking wrapper: sessionMu is taken and released around
// THIS round trip alone, so unrelated session-socket callers interleave freely
// between consecutive calls. That is the right discipline for a bulk batch (a
// delete chunk is up to sessionHelperDeleteChunk requests — holding sessionMu
// across the whole chunk would starve live session installs), and since #8015
// it is the discipline for EVERY session-socket caller: the local mirror sends
// one upsert, so no group has to reach the helper with nothing in between. A
// future caller that needs that takes sessionMu itself and drives
// requestSessionSyncLocked per request, which is why the unlocked inner stays
// separable.
func (m *Manager) requestSessionSync(req ControlRequest) error {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	return m.requestSessionSyncLocked(req)
}

// requestSessionSyncLocked performs ONE session-socket round trip. The caller
// MUST already hold m.sessionMu; it is not reentrant.
func (m *Manager) requestSessionSyncLocked(req ControlRequest) error {
	sockPath := m.sessionSocketPath()
	if sockPath == "" {
		return errors.New("session socket not configured")
	}
	// A bounded dial + round-trip deadline so a hung helper (accepts the
	// connection but never reads/replies) fails THIS request in a few seconds
	// instead of the OS default. Transport failures (dial/write/read) are
	// wrapped with errSessionHelperUnreachable so a bulk caller can abort the
	// rest of the batch instead of paying this deadline once per request
	// (#5380).
	// #9003: same peer check as the control socket. The session socket sits in
	// the same directory, is bound by the same helper, and reaches the same
	// handler dispatch — a squatter on it installs and reads sessions.
	conn, err := dialTrustedHelperSocket("session socket", sockPath, sessionSyncDialTimeout)
	if err != nil {
		return fmt.Errorf("%w: dial session socket: %w", errSessionHelperUnreachable, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sessionSyncRoundtripDeadline))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return fmt.Errorf("%w: write session request: %w", errSessionHelperUnreachable, err)
	}
	var resp ControlResponse
	// #9003: byte-bounded as well as deadline-bounded — see requestDetailedLocked.
	bounded := boundedResponseReader(conn)
	if err := json.NewDecoder(bufio.NewReader(bounded)).Decode(&resp); err != nil {
		// #9322: name the cap. The CLASSIFICATION is deliberately unchanged —
		// this stays errSessionHelperUnreachable, which gates takeover-readiness
		// (#5247) — because a response we could not read is a response we could
		// not read, whatever ended it. What changes is that the operator is told
		// WHICH of the two ended it; reclassifying a truncation as healthy would
		// be a #6785-shaped decision with HA blast radius, and it is not this
		// change's to make.
		if bounded.truncated {
			return fmt.Errorf("%w: read session response: %w",
				errSessionHelperUnreachable, responseCapError(req.Type, err))
		}
		return fmt.Errorf("%w: read session response: %w", errSessionHelperUnreachable, err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		// #6785: discriminate a SEMANTIC refusal from a transport failure. Both
		// arrive as an error, but they mean opposite things about helper health:
		// a transport failure says the session socket is sick and must gate
		// takeover-readiness (#5247), while a refusal is the correct answer from
		// a HEALTHY helper — the peer sent a stale generation, this node is at
		// its own import ceiling, or the translated tuple could not be reserved.
		// Treating a refusal as a mirror failure would latch a working standby
		// "not takeover-ready" the first time a peer oversubscribed it, which is
		// a worse failure than the split truth this reporting exists to fix.
		//
		// Matched on the helper's stable machine-readable prefix, never on the
		// human-readable remainder, so the sentence can be reworded without
		// silently reclassifying a refusal as a transport failure.
		if strings.HasPrefix(resp.Error, syncedImportRefusedPrefix) {
			return fmt.Errorf("%w: %s", dataplane.ErrSyncedImportRefused,
				strings.TrimPrefix(resp.Error, syncedImportRefusedPrefix))
		}
		return errors.New(resp.Error)
	}
	return nil
}

func (m *Manager) requestLocked(req ControlRequest, status *ProcessStatus) error {
	// #9684: count every partial update sent, whatever its outcome, so Compile
	// can tell whether one ran while it built its snapshot outside m.mu.
	if req.Type == "update_neighbors" || req.Type == "update_fabrics" {
		m.partialUpdateEpoch.Add(1)
	}
	if m.controlRequestHook != nil {
		return m.controlRequestHook(req, status)
	}
	resp, err := m.requestDetailedLocked(req)
	if err != nil {
		return err
	}
	if status != nil && resp.Status != nil {
		*status = *resp.Status
	}
	return nil
}
