package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// setSSEHeaders configures the response for Server-Sent Events streaming AND
// flushes the header block to the client.
//
// #7655: the flush is not an optimisation. net/http sends no response headers
// until the first Write or Flush, so setting values alone left a client
// connecting to a QUIET feed blocked waiting for headers that were never sent.
// A browser EventSource on an idle firewall hung rather than establishing the
// stream.
//
// The consequence is not cosmetic: until the first event arrives -- which on a
// quiet box could be hours -- an SSE consumer cannot distinguish "connected and
// quiet" from "not connected", and every reconnect/backoff decision it makes
// rests on exactly that distinction. It also inverts the debugging order: the
// operator sees a hung client and goes looking for a network or auth problem
// while the stream is established and simply silent.
//
// THE FLUSH LIVES HERE, NOT AT THE CALL SITES. Both SSE handlers had the same
// shape, and a per-site flush is a line the next handler forgets. Binding it to
// the function that sets the headers makes "headers set" and "headers sent" one
// step, which is the property callers actually need.
//
// A ResponseWriter that does not implement http.Flusher cannot stream at all,
// so there is nothing to do for it and nothing is lost by skipping.
func setSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// --- #7632: bounding a SLOW SSE READER -------------------------------------
//
// An SSE stream writes straight to the ResponseWriter and flushes, and
// http.Server runs with WriteTimeout deliberately 0 process-wide so these
// long-lived streams are not severed. So a subscriber that stays CONNECTED and
// stops reading fills the socket buffers and parks this handler goroutine in
// Write indefinitely, holding a subscriber slot with it — the same mechanism
// #6809 bounded on the BGP route stream.
//
// A per-handler CONTEXT deadline does not help: it bounds a handler's work, not
// a write already blocked in the kernel. Only a socket write deadline ends
// that. See the corrected note in server.go's timeout block.
//
// WHY A PER-WRITE DEADLINE AND *NOT* AN ELAPSED BUDGET. An SSE stream is
// SUPPOSED to sit idle with no data for long stretches — that is the normal
// operating state of an event feed on a quiet firewall, not a symptom. An
// elapsed budget would sever exactly the healthy case. A per-write deadline
// bounds a write that has BEGUN and says nothing about the gap between events,
// so idling is untouched and only a peer that has stopped draining is cut.
// This is the axis on which SSE genuinely differs from the RIB dump, where a
// total budget was a sensible backstop.
//
// THE ERROR RETURNS ARE PRECAUTIONARY, NOT BOUND — labelled as such because I
// first claimed the opposite and then measured it.
//
// The claim was that arming the deadline without propagating the error would be
// WORSE than the pin: the write failing on every later event while the loop kept
// draining the subscription and discarding. Measured over 9 runs per variant
// against a 250ms deadline, on both paths a small event can take — the flood
// that overruns net/http's 2 KiB response buffer and produces direct socket
// writes, and the single small event whose only socket contact is the flush:
//
//	variant                  write path (flood)          flush path (1 event)
//	as shipped               min 251.0 med 251.9 max 254.9   250.3 / 250.7 / 250.8
//	write check discarded    min 251.1 med 251.5 max 252.4   250.3 / 250.5 / 250.8
//	flush check discarded    min 251.1 med 251.4 max 252.9   250.6 / 250.6 / 250.7
//
// Every variant returns inside one deadline window and the distributions
// overlap completely. The reason is measurable too: net/http cancels the
// request context when a connection write fails —
//
//	PROBE: request context CANCELLED 250.693838ms after the blocking write began
//
// — so the loop exits through its ctx.Done() arm whether or not anything here
// inspects an error.
//
// So THE DEADLINE is what fixes the pin, and the error returns currently change
// nothing observable. They are kept for one reason that survives the
// measurement: that exit depends on net/http cancelling the context on a write
// error, which is behaviour rather than contract. A wrapping ResponseWriter, or
// a different server, that does not do it would leave this loop draining the
// subscription into a dead connection. Checking makes the exit local and
// explicit instead of inherited.
//
// Stated this way deliberately: a guard described as load-bearing when it is
// defence in depth is the kind of claim that survives into someone else's
// reasoning. The mutation matrix agrees — removing either check leaves the
// suite green, and that is recorded rather than papered over.
//
// What the flush check DOES fix is a false claim rather than a live pin; see
// sseStream.flush.

// sseWriteDeadline bounds a SINGLE downstream SSE write. A subscriber that
// cannot accept one small event within this window is not reading. Generous by
// design: an SSE event is a few hundred bytes and fits in any socket buffer
// instantly unless the peer has stopped draining. A package var so a test can
// compress it without a real slow reader.
//
// Deliberately NOT shared with bgpStreamWriteDeadline (routing.go): the two
// endpoints have different traffic shapes and a shared knob would couple a
// change to one into the other.
var sseWriteDeadline = 30 * time.Second

// sseWriteChunk bounds how many payload bytes go out under ONE write deadline
// (#7654 review, finding 2). Each chunk re-arms, so the budget is per-chunk
// progress rather than a single window for the whole event. 32 KiB is large
// enough that an ordinary event is one chunk and the common path is unchanged.
const sseWriteChunk = 32 * 1024

// sseStream is one SSE response: a deadline-arming writer over the
// ResponseWriter plus its flusher. It single-sources the deadline, the flush
// and the error return for both stream handlers, so neither can drift into
// discarding a write failure again.
type sseStream struct {
	w  io.Writer
	rc *http.ResponseController
	// deadlineUnsupported mirrors deadlineArmingWriter's own probe: once
	// SetWriteDeadline has failed there is nothing to clear either.
	deadlineUnsupported bool
	// flushUnsupported records a ResponseWriter that cannot flush at all, so
	// the not-supported answer is not mistaken for a peer failure.
	flushUnsupported bool
}

// newSSEStream wraps w so every SSE write arms a fresh write deadline first.
// It reuses deadlineArmingWriter (routing.go, #6809): arming at the WRITE
// rather than at a call site makes the coverage structural, which is what
// #6809's own first attempt got wrong.
func newSSEStream(w http.ResponseWriter, d time.Duration) *sseStream {
	rc := http.NewResponseController(w)
	return &sseStream{w: &deadlineArmingWriter{w: w, rc: rc, d: d}, rc: rc}
}

// clearDeadline drops the write deadline once an event is fully on the wire
// (#7654 review, finding 1).
//
// ARMING ALONE IS NOT ENOUGH, and this is the correction that finding forced.
// A deadline set before a write is not cancelled by the write succeeding — it
// stays live. Under HTTP/1.1 that is invisible, because a stale absolute
// deadline only matters when something writes again and deadlineArmingWriter
// re-arms first. Under HTTP/2 Go implements the write deadline with a timer
// that RESETS THE STREAM when it fires, so an idle SSE stream was torn down one
// deadline after its last event, with a client that had consumed everything.
//
// Reproduced before fixing, not argued:
//
//	PROBE: response proto=HTTP/2.0
//	PROBE: first read n=233 err=<nil>   (the establishing event)
//	after idling 4x the deadline:
//	PROBE RESULT: read n=0 err=stream error: stream ID 1; INTERNAL_ERROR
//
// So "per-write, not elapsed" was necessary and NOT sufficient: per-write still
// severs an idle stream if the deadline outlives the write. The window has to
// CLOSE as well as open — armed before the bytes go out, cleared once they are
// out and the stream goes quiet again.
//
// Cleared AFTER the flush rather than after the last Write, deliberately.
// http.Flusher.Flush() does not go through deadlineArmingWriter, so clearing
// any earlier would leave the flush itself unbounded and re-open the very pin
// this file exists to close.
func (s *sseStream) clearDeadline() {
	if s.deadlineUnsupported {
		return
	}
	if err := s.rc.SetWriteDeadline(time.Time{}); err != nil {
		s.deadlineUnsupported = true
	}
}

// writeEvent writes a single SSE event and RETURNS the first failure — from a
// write OR from the flush, which for a small event is the only one that reaches
// the socket at all (#7654 review, finding 2).
// A non-nil return is terminal for the stream: the peer is not reading, and
// continuing would drain the subscription into a connection that cannot take
// it.
func (s *sseStream) writeEvent(id, event, data string) error {
	if _, err := fmt.Fprintf(s.w, "id: %s\n", id); err != nil {
		return err
	}
	if event != "" {
		if _, err := fmt.Fprintf(s.w, "event: %s\n", event); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(s.w, "data: "); err != nil {
		return err
	}
	// #7654 review, finding 2: write the PAYLOAD in bounded chunks so each one
	// re-arms the deadline. One Fprintf of the whole event gave the entire
	// payload a single absolute window, so a large event to a slow-but-
	// PROGRESSING reader was cut off partway — the deadline measured elapsed
	// time rather than lack of progress, which is the same conflation this file
	// rejects at the stream level.
	//
	// The "an SSE event is a few hundred bytes" premise is unenforced: event
	// JSON carries operator-authored strings (policy names and the like) whose
	// only external bound is the 16 MiB config limit. Chunking makes the budget
	// per-chunk, so a reader that keeps draining keeps the stream however large
	// the event.
	for off := 0; off < len(data); off += sseWriteChunk {
		end := off + sseWriteChunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := io.WriteString(s.w, data[off:end]); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(s.w, "\n\n"); err != nil {
		return err
	}
	// The FLUSH is where a small event actually reaches the socket, so its
	// error is the one that matters most (#7654 review, finding 2).
	if err := s.flush(); err != nil {
		return err
	}
	// The event is on the wire; the stream is idle again until the next one.
	s.clearDeadline()
	return nil
}

// flush pushes the buffered event to the connection and REPORTS a failure.
//
// WHAT WAS ACTUALLY WRONG (#7654 review, finding 2). http.Flusher.Flush() has
// no error return, and net/http's response.Flush calls FlushError() and throws
// the error away. net/http buffers the response in a 2 KiB bufio.Writer and an
// SSE event is a few hundred bytes, so for an ordinary event the handler's
// Write calls never touch the socket at all — the write that can block is the
// one INSIDE the flush. So writeEvent's own doc comment ("returns the first
// write error") was FALSE for the common case: measured against a
// ResponseWriter whose flush fails, writeEvent returned nil while the flush
// error was discarded.
//
// http.ResponseController.Flush() returns what response.Flush swallows.
// ErrNotSupported is a property of the ResponseWriter, not of the peer, so it
// is latched and treated as "no flush available" rather than as a dead stream.
//
// AND IT IS PRECAUTIONARY, NOT LOAD-BEARING — measured, like the write-error
// check above, and for the same reason. With the flush error deliberately
// discarded, a stalled peer still releases the handler in 245.5ms against a
// 250ms deadline, indistinguishable from 245.6ms with the check, because
// net/http cancels the request context when a connection write fails:
//
//	PROBE: request context CANCELLED 250.693838ms after the blocking write began
//
// So this fixes a false CLAIM and makes the exit local instead of inherited; it
// does not change when the handler returns under net/http. Recorded that way
// deliberately — the whole reason this file already carries one retraction is
// that a guard described as load-bearing when it is defence in depth survives
// into someone else's reasoning.
//
// A NOTE ON HOW THIS WAS NEARLY MIS-REPORTED, because the instrument matters
// more than the result. The first end-to-end probe of this said "handler STILL
// RUNNING after 6s" and looked like a live pin that the PR had missed. It was
// not: stalledConn6809's byte budget is checked BEFORE the write and then lets
// the whole write through, so any positive budget passed the entire flush and
// the handler was sitting IDLE in its select with nothing to write. "Has not
// returned" and "is blocked in Write" are different facts and a timeout cannot
// tell them apart — the same confusion that produced two wrong readings about
// HTTP/2 earlier in this PR. The fixture now witnesses a PARKED WRITE
// (stalledListener6809.waitForParkedWrite) so no cell here can make that claim
// without evidence, and maxWrites gives an exact "the buffer filled after the
// first event" that a byte budget cannot express.
func (s *sseStream) flush() error {
	if s.flushUnsupported {
		return nil
	}
	err := s.rc.Flush()
	if errors.Is(err, http.ErrNotSupported) {
		s.flushUnsupported = true
		return nil
	}
	return err
}

// writeSSEEvent writes a single SSE event to the response.
//
// #7632: retained as the unbounded form for callers that are NOT a long-lived
// stream — it has no write deadline and discards errors, which is only safe
// where the response ends immediately afterwards. A streaming handler must use
// sseStream.
func writeSSEEvent(w http.ResponseWriter, id string, event string, data string) {
	fmt.Fprintf(w, "id: %s\n", id)
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// eventStreamHandler streams firewall events via SSE.
// Supports ?category= filter (comma-separated: session,policy,screen,firewall).
func (s *Server) eventStreamHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeError(w, http.StatusServiceUnavailable, "event buffer not available")
		return
	}

	// Parse category filter. Reject a typo before switching to SSE so a
	// misspelled query does not silently stream everything (#3383).
	categoryFilter, err := parseCategories(r.URL.Query().Get("category"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bound concurrent SSE subscribers before switching to event-stream
	// (#4484 L-2): a nil return means the cap is reached — respond 503 while
	// we can still send a normal error (after setSSEHeaders we no longer can).
	sub := s.eventBuf.TrySubscribe(128)
	if sub == nil {
		writeError(w, http.StatusServiceUnavailable, "too many concurrent event subscribers")
		return
	}
	defer sub.Close()

	setSSEHeaders(w)

	// #7632: bound a subscriber that stays connected and stops reading.
	stream := newSSEStream(w, sseWriteDeadline)
	var seq uint64
	var gaps logging.EventGapTracker
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
			if lost, gap := gaps.Observe(sub, rec); gap {
				seq++
				data, err := json.Marshal(eventOverrunEntry{
					Message: logging.OverrunLine(lost),
					Dropped: sub.Dropped(),
				})
				if err == nil {
					if err := stream.writeEvent(fmt.Sprintf("%d", seq), "overrun", string(data)); err != nil {
						return
					}
				}
			}
			if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
				continue
			}
			seq++
			data, err := json.Marshal(eventEntryFromRecord(rec))
			if err != nil {
				continue
			}
			// #7632: a write failure is TERMINAL. Continuing would drain the
			// subscription into a connection that cannot take it, holding a
			// subscriber slot while silently discarding the feed.
			if err := stream.writeEvent(fmt.Sprintf("%d", seq), rec.Type, string(data)); err != nil {
				return
			}
		}
	}
}

// logStreamHandler streams firewall events formatted as log messages via SSE.
// Supports ?severity= and ?category= filters.
func (s *Server) logStreamHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeError(w, http.StatusServiceUnavailable, "event buffer not available")
		return
	}

	// Reject a typo'd severity/category before switching to SSE (#3383):
	// a misspelled filter must not silently widen the live feed to all
	// events. Distinguish absent ("" -> 0, no filter) from unrecognized.
	severityFilter, err := logging.ParseSeverityStrict(r.URL.Query().Get("severity"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	categoryFilter, err := parseCategories(r.URL.Query().Get("category"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bound concurrent SSE subscribers before switching to event-stream
	// (#4484 L-2); see eventStreamHandler for the rationale.
	sub := s.eventBuf.TrySubscribe(128)
	if sub == nil {
		writeError(w, http.StatusServiceUnavailable, "too many concurrent event subscribers")
		return
	}
	defer sub.Close()

	setSSEHeaders(w)

	// #7632: same bound as the event stream.
	stream := newSSEStream(w, sseWriteDeadline)
	var seq uint64
	var gaps logging.EventGapTracker
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
			if lost, gap := gaps.Observe(sub, rec); gap {
				seq++
				data, err := json.Marshal(eventOverrunEntry{
					Message: logging.OverrunLine(lost),
					Dropped: sub.Dropped(),
				})
				if err == nil {
					if err := stream.writeEvent(fmt.Sprintf("%d", seq), "overrun", string(data)); err != nil {
						return
					}
				}
			}
			severity := eventRecordSeverity(rec)
			if severityFilter != 0 && severity > severityFilter {
				continue
			}
			if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
				continue
			}
			seq++
			logEntry := LogStreamEntry{
				Time:     rec.Time.Format(time.RFC3339),
				Severity: severityName(severity),
				Message:  formatLogMessage(rec),
			}
			data, err := json.Marshal(logEntry)
			if err != nil {
				continue
			}
			// #7632: terminal on a write failure — see eventStreamHandler.
			if err := stream.writeEvent(fmt.Sprintf("%d", seq), "log", string(data)); err != nil {
				return
			}
		}
	}
}

type eventOverrunEntry struct {
	Message string `json:"message"`
	Dropped uint64 `json:"dropped"`
}

// LogStreamEntry is a log message sent via SSE.
type LogStreamEntry struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// eventEntryFromRecord maps a logging.EventRecord to the REST/SSE EventEntry.
// It is the single SSOT for both the GET /security/events response and the SSE
// event stream, so the two surfaces never drift (#3337). The timestamp uses
// RFC3339Nano so high-rate RT_FLOW events keep sub-second ordering for
// cross-system correlation (the CLI keeps human-friendly seconds).
func eventEntryFromRecord(rec logging.EventRecord) EventEntry {
	return EventEntry{
		Time:            rec.Time.Format(time.RFC3339Nano),
		Type:            rec.Type,
		SrcAddr:         rec.SrcAddr,
		DstAddr:         rec.DstAddr,
		Protocol:        rec.Protocol,
		Action:          rec.Action,
		PolicyID:        rec.PolicyID,
		InZone:          rec.InZone,
		OutZone:         rec.OutZone,
		InZoneName:      rec.InZoneName,
		OutZoneName:     rec.OutZoneName,
		ScreenCheck:     rec.ScreenCheck,
		SessionPkts:     rec.SessionPkts,
		SessionBytes:    rec.SessionBytes,
		RevSessionPkts:  rec.RevSessionPkts,
		RevSessionBytes: rec.RevSessionBytes,
		PolicyName:      rec.PolicyName,
		AppName:         rec.AppName,
		IngressIface:    rec.IngressIface,
		CloseReason:     rec.CloseReason,
		Reason:          rec.Reason,
		NATSrcAddr:      rec.NATSrcAddr,
		NATDstAddr:      rec.NATDstAddr,
		SessionID:       rec.SessionID,
		ElapsedTime:     rec.ElapsedTime,
		Created:         rec.Created,
		CreatedNanos:    rec.CreatedNanos,
		EgressIfindex:   rec.EgressIfindex,
		IngressIfindex:  rec.IngressIfindex,
		TOS:             rec.TOS,
		TCPControlBits:  rec.TCPControlBits,
	}
}

// parseCategories parses a comma-separated category string into a bitmask.
// It is fail-closed (#3383): an unrecognized OR empty token returns an error
// rather than silently collapsing to 0 ("no filter"), which would widen the
// live SSE feed to everything on a typo or a malformed list (a leading,
// trailing, or doubled comma). A fully-ABSENT category param ("") still means
// match-all and yields a 0 mask with no error; only the named "all" token is
// the explicit no-filter request within a present list.
func parseCategories(s string) (uint8, error) {
	if s == "" {
		return 0, nil
	}
	var mask uint8
	for _, c := range strings.Split(s, ",") {
		tok := strings.TrimSpace(c)
		if tok == "" {
			return 0, fmt.Errorf("empty category token in %q (no leading/trailing/double comma)", s)
		}
		bit, err := logging.ParseCategoryStrict(tok)
		if err != nil {
			return 0, err
		}
		mask |= bit
	}
	return mask, nil
}

// matchCategory checks if an event type matches a category bitmask.
func matchCategory(eventType string, mask uint8) bool {
	var bit uint8
	switch eventType {
	case "SESSION_OPEN", "SESSION_CLOSE":
		bit = logging.CategorySession
	case "POLICY_DENY":
		bit = logging.CategoryPolicy
	case "SCREEN_DROP":
		bit = logging.CategoryScreen
	case "FILTER_LOG":
		bit = logging.CategoryFirewall
	default:
		// Fail-closed (#3383): a future/unknown event type does not belong
		// to any requested category, so a narrow category mask must not
		// deliver it. (A zero mask = "no filter" is handled by the caller,
		// which only calls matchCategory when mask != 0.)
		return false
	}
	return mask&bit != 0
}

// eventRecordSeverity maps an event record to a syslog severity, classifying
// by BOTH type and action (#3383). This mirrors logging.eventSeverity: a
// SCREEN_DROP with action=permit is the #2234 scan-table-pressure alarm — the
// packet still forwards, so it is informational (SyslogNotice), not an error.
// Only a screen event that actually dropped (deny/reject) is SyslogError.
// Classifying every SCREEN_DROP as error emitted false error-severity alerts
// and let permitted packets pass a severity=error filter.
func eventRecordSeverity(rec logging.EventRecord) int {
	switch rec.Type {
	case "SCREEN_DROP":
		if strings.EqualFold(rec.Action, "permit") {
			return logging.SyslogNotice
		}
		return logging.SyslogError
	case "POLICY_DENY":
		return logging.SyslogWarning
	default:
		return logging.SyslogInfo
	}
}

func severityName(s int) string {
	switch s {
	case logging.SyslogError:
		return "error"
	case logging.SyslogWarning:
		return "warning"
	case logging.SyslogNotice:
		return "notice"
	default:
		return "info"
	}
}

func formatLogMessage(rec logging.EventRecord) string {
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("RT_FLOW %s screen=%s src=%s dst=%s proto=%s action=%s zone=%d",
			rec.Type, rec.ScreenCheck, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, rec.InZone)
	}
	if rec.Type == "SESSION_CLOSE" {
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d pkts=%d bytes=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.PolicyID, rec.InZone, rec.OutZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "FILTER_LOG" {
		source := rec.Reason
		if source == "" {
			source = "unknown"
		}
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%d->%d source=%s filter=%d term=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.InZone, rec.OutZone, source, rec.RuleID, rec.TermID)
	}
	message := fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d",
		rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, rec.InZone, rec.OutZone)
	if rec.Reason != "" {
		message += fmt.Sprintf(" reason=%q", rec.Reason)
	}
	return message
}
