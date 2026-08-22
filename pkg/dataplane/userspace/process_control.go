package userspace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
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
	// m.mu across the round-trip) forever. At the 64 MiB request ceiling the
	// scaled deadline is base + 64s = 67s, comfortably under this cap.
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
	conn, err := net.DialTimeout("unix", m.cfg.ControlSocket, 2*time.Second)
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
	_ = conn.SetDeadline(time.Now().Add(controlRoundtripDeadline(len(body))))
	// Reuse the pre-flight-serialized body; the Rust receiver frames on a
	// single trailing newline (json.Encoder appends one).
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return ControlResponse{}, err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
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
		return ControlResponse{}, errors.New(resp.Error)
	}
	return resp, nil
}

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
// across the whole chunk would starve live session installs), but NOT for a
// forward/reverse pair, which must not be split. A caller that needs a group of
// requests to reach the helper with nothing in between takes sessionMu itself
// and drives requestSessionSyncLocked per request — see syncSessionPairLocked
// (#5698).
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
	conn, err := net.DialTimeout("unix", sockPath, sessionSyncDialTimeout)
	if err != nil {
		return fmt.Errorf("%w: dial session socket: %w", errSessionHelperUnreachable, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sessionSyncRoundtripDeadline))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return fmt.Errorf("%w: write session request: %w", errSessionHelperUnreachable, err)
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return fmt.Errorf("%w: read session response: %w", errSessionHelperUnreachable, err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return errors.New(resp.Error)
	}
	return nil
}

func (m *Manager) requestLocked(req ControlRequest, status *ProcessStatus) error {
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
