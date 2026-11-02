package userspace

// #18752: an owner-RG export window that the Go pager abandoned stayed open on
// the helper until its 60 s idle expiry, and the helper answers every fresh
// kick BUSY while a window is open. On udp that stranded the HA cold prime
// after a peer reboot: the first bulk's paged export aborted on a config
// generation change between pages, every re-drive for the next minute failed
// "owner-RG export busy (window N open)", ColdPrimeOwedWithoutPendingBulk
// stayed true, and every manual failback was refused.
//
// The fake helper below implements the helper's window contract (the parts of
// userspace-dp/src/afxdp/ha/export.rs and coordinator/session_manager.rs that
// matter here): a page reporting more keeps the window open; a fresh kick
// while it is open is refused BUSY; a terminal page closes it; and the
// #18752 abandon verb closes it iff the token names the open window.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type windowHelper18752 struct {
	mu         sync.Mutex
	open       uint64 // open window sequence, 0 = none
	openClient uint64 // client window id the open window was kicked with
	nextSeq    uint64
	pagesLeft  int // pages after page 1 in the open window
	abandons   []SessionExportRequest
	busy       int
	// beforeReply runs after a request is read and before it is answered,
	// with no helper lock held: the cell uses it to change the Manager's
	// config generation while a page is in flight.
	beforeReply func(req ControlRequest)
	// dropReply, when it returns true, makes the helper process the request
	// (opening the window) and then close the connection without answering:
	// page 1's response is lost.
	dropReply func(req ControlRequest) bool
	// noAbandonVerb models a helper built before #18752: it refuses the
	// abandon verb with the real dispatcher's unknown-verb wording.
	noAbandonVerb bool
}

func startWindowHelper18752(t *testing.T, sock string, pagesPerWindow int) *windowHelper18752 {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &windowHelper18752{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				var req ControlRequest
				if json.Unmarshal(line, &req) != nil {
					return
				}
				if f := h.beforeReply; f != nil {
					f(req)
				}
				resp := h.answer(req, pagesPerWindow)
				if f := h.dropReply; f != nil && f(req) {
					return
				}
				body, _ := json.Marshal(&resp)
				_, _ = c.Write(append(body, '\n'))
			}(conn)
		}
	}()
	return h
}

func (h *windowHelper18752) answer(req ControlRequest, pagesPerWindow int) ControlResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	ex := req.SessionExport
	switch {
	case req.Type == "abandon_owner_rg_export" && h.noAbandonVerb:
		h.abandons = append(h.abandons, *ex)
		return ControlResponse{OK: false, Error: "unknown request type " + req.Type}
	case req.Type == "abandon_owner_rg_export":
		h.abandons = append(h.abandons, *ex)
		byToken := ex.ContinuationIncarnation == 1 && ex.ContinuationSequence == h.open
		byClient := ex.ClientWindow != 0 && ex.ClientWindow == h.openClient
		cleared := h.open != 0 && (byToken || byClient)
		if cleared {
			h.open, h.pagesLeft, h.openClient = 0, 0, 0
		}
		return ControlResponse{OK: true, SessionExportAbandoned: cleared}
	case req.Type != "export_owner_rg_sessions":
		return ControlResponse{OK: false, Error: "unknown request type " + req.Type}
	case !ex.Continuation:
		if h.open != 0 {
			h.busy++
			return ControlResponse{OK: false, Error: fmt.Sprintf(
				"owner-RG export busy (window %d open); retry with backoff", h.open)}
		}
		h.nextSeq++
		h.open, h.pagesLeft, h.openClient = h.nextSeq, pagesPerWindow-1, ex.ClientWindow
	default:
		if h.open == 0 || ex.ContinuationSequence != h.open {
			return ControlResponse{OK: false, Error: "no open export window"}
		}
		h.pagesLeft--
	}
	resp := ControlResponse{
		OK:                       true,
		SessionExportIncarnation: 1,
		SessionExportSeq:         h.open,
		SessionExportMore:        h.pagesLeft > 0,
		SessionDeltas:            []SessionDeltaInfo{{Event: "open", SrcIP: "10.0.0.1"}},
	}
	if !resp.SessionExportMore {
		h.open, h.openClient = 0, 0
	}
	return resp
}

func (h *windowHelper18752) snapshot() (open uint64, busy int, abandons []SessionExportRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.open, h.busy, append([]SessionExportRequest(nil), h.abandons...)
}

// The stuck state, hermetically: export 1 aborts between pages on a config
// generation change; export 2, the cold-prime re-drive, must not be refused
// BUSY. Before #18752 it was, and stayed so for the helper's idle expiry.
func TestAbortedOwnerRGExportDoesNotLeaveTheWindowBusy18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 3)
	var once sync.Once
	h.beforeReply = func(req ControlRequest) {
		if req.Type == "export_owner_rg_sessions" && !req.SessionExport.Continuation {
			// Page 1 of export 1 is in flight: a snapshot/FIB publish bumps
			// the config generation, as a peer reboot's churn does.
			once.Do(func() {
				m.mu.Lock()
				m.generation++
				m.mu.Unlock()
			})
		}
	}

	_, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if !errors.Is(err, ErrOwnerRGExportIncomplete) || !strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("export 1 err = %v, want the generation-change abort", err)
	}
	open, _, abandons := h.snapshot()
	if len(abandons) != 1 || abandons[0].ContinuationIncarnation != 1 || abandons[0].ContinuationSequence != 1 ||
		abandons[0].ClientWindow == 0 || abandons[0].ProtocolVersion != MinProtocolOwnerRGExportPaging {
		t.Fatalf("abandons after the aborted export = %+v, want exactly one naming client window and token (1,1) at protocol %d",
			abandons, MinProtocolOwnerRGExportPaging)
	}
	if open != 0 {
		t.Fatalf("helper window %d still open after the aborted export", open)
	}

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err != nil {
		t.Fatalf("export 2 (the cold-prime re-drive) failed: %v — the aborted window still blocks it", err)
	}
	if len(deltas) != 3 {
		t.Fatalf("export 2 collected %d deltas, want 3 (one per page of a 3-page window)", len(deltas))
	}
	if _, busy, _ := h.snapshot(); busy != 0 {
		t.Fatalf("helper refused %d fresh kick(s) BUSY", busy)
	}
}

// A complete export closes its window with the terminal page; it must not
// send an abandon (which would be harmless, but is a control round trip on
// every healthy export).
func TestCompleteOwnerRGExportSendsNoAbandon18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 3)
	if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if _, _, abandons := h.snapshot(); len(abandons) != 0 {
		t.Fatalf("a complete export sent %d abandon(s): %+v", len(abandons), abandons)
	}
}

// A single-page window never opens on the helper (its only page is
// terminal), so even a sink error after it must not send an abandon.
func TestSinglePageExportErrorSendsNoAbandon18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 1)
	_, _, err := m.ExportOwnerRGSessionsPagedStream([]int{1}, OwnerRGExportPageFunc(func([]SessionDeltaInfo) error {
		return errors.New("sink refused")
	}))
	if err == nil {
		t.Fatal("sink error did not abort the export")
	}
	if _, _, abandons := h.snapshot(); len(abandons) != 0 {
		t.Fatalf("a single-page export sent %d abandon(s)", len(abandons))
	}
}

// A sink error on page 1 of a multi-page window is a Go-side abort with the
// window open: it must be abandoned too, not only the generation-change path.
func TestSinkErrorAbandonsTheOpenWindow18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 3)
	_, _, err := m.ExportOwnerRGSessionsPagedStream([]int{1}, OwnerRGExportPageFunc(func([]SessionDeltaInfo) error {
		return errors.New("sink refused")
	}))
	if err == nil {
		t.Fatal("sink error did not abort the export")
	}
	open, _, abandons := h.snapshot()
	if len(abandons) != 1 || open != 0 {
		t.Fatalf("after a page-1 sink error: abandons=%d open=%d, want 1 and 0", len(abandons), open)
	}
}

// A sink error on the TERMINAL page of a multi-page window: the helper already
// closed the window with that page, so nothing is abandoned.
func TestSinkErrorOnTerminalPageSendsNoAbandon18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 2)
	pages := 0
	_, _, err := m.ExportOwnerRGSessionsPagedStream([]int{1}, OwnerRGExportPageFunc(func([]SessionDeltaInfo) error {
		pages++
		if pages == 2 {
			return errors.New("sink refused the terminal page")
		}
		return nil
	}))
	if err == nil || pages != 2 {
		t.Fatalf("err=%v after %d pages, want the terminal page's sink error", err, pages)
	}
	if open, _, abandons := h.snapshot(); len(abandons) != 0 || open != 0 {
		t.Fatalf("terminal-page sink error: abandons=%d open=%d, want 0 and 0", len(abandons), open)
	}
}

// Lost page 1 (#18752 review): the helper opened the window, but its page-1
// response never reached the pager, so the pager has no helper token. It
// named the window itself before sending, and the abandon carries that id.
// Before the client id existed, this shape left the window BUSY for the full
// idle expiry even with the abandon in place.
func TestLostPageOneResponseStillAbandonsTheWindow18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 3)
	var dropped sync.Once
	h.dropReply = func(req ControlRequest) bool {
		drop := false
		if req.Type == "export_owner_rg_sessions" && !req.SessionExport.Continuation {
			dropped.Do(func() { drop = true })
		}
		return drop
	}

	if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); err == nil {
		t.Fatal("export 1 succeeded although page 1's response was dropped")
	}
	open, _, abandons := h.snapshot()
	if len(abandons) != 1 || abandons[0].ClientWindow == 0 ||
		abandons[0].ContinuationIncarnation != 0 || abandons[0].ContinuationSequence != 0 {
		t.Fatalf("abandons after the lost page 1 = %+v, want exactly one carrying only the client window id", abandons)
	}
	if open != 0 {
		t.Fatalf("helper window %d still open after the lost-page-1 abandon", open)
	}
	if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); err != nil {
		t.Fatalf("export 2 failed after the lost page 1: %v", err)
	}
	if _, busy, _ := h.snapshot(); busy != 0 {
		t.Fatalf("helper refused %d fresh kick(s) BUSY", busy)
	}
}

// Every page-1 kick names its window, and two exports never reuse an id.
func TestEachExportNamesItsWindow18752(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startPagingHelper9344(t, sock, []pageReply9344{{deltas: 1}, {deltas: 1}})
	for i := 0; i < 2; i++ {
		if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); err != nil {
			t.Fatalf("export %d: %v", i+1, err)
		}
	}
	var ids []uint64
	for _, req := range h.got {
		if req.Type == "export_owner_rg_sessions" && !req.SessionExport.Continuation {
			ids = append(ids, req.SessionExport.ClientWindow)
		}
	}
	if len(ids) != 2 || ids[0] == 0 || ids[1] == 0 || ids[0] == ids[1] {
		t.Fatalf("page-1 client window ids = %v, want two distinct nonzero ids", ids)
	}
}

// syncBuf18752 is a goroutine-safe log sink: the fake helper and the pager log
// from different goroutines.
type syncBuf18752 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf18752) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// lines returns the captured records at level that contain substr.
func (b *syncBuf18752) lines(level, substr string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, l := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(l, "level="+level) && strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return out
}

func captureLogs18752(t *testing.T) *syncBuf18752 {
	t.Helper()
	b := &syncBuf18752{}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return b
}

// bumpGenerationOnEveryPageOne18752 makes every export abort between pages,
// the way a peer reboot's commit churn does.
func bumpGenerationOnEveryPageOne18752(m *Manager, h *windowHelper18752) {
	h.beforeReply = func(req ControlRequest) {
		if req.Type == "export_owner_rg_sessions" && !req.SessionExport.Continuation {
			m.mu.Lock()
			m.generation++
			m.mu.Unlock()
		}
	}
}

const (
	abandonClosedMsg18752  = "abandoned aborted owner-RG export window"
	abandonNoMatchMsg18752 = "abandon matched no open window"
	abandonNoVerbMsg18752  = "does not support abandon_owner_rg_export"
	abandonFailedMsg18752  = "could not abandon the aborted owner-RG export window"
)

// The Info line claims a window was closed, so it must appear only when the
// helper says it closed one. An abandon after page 1 was refused BUSY names a
// window that never opened (another export holds the helper's single window):
// that is routine on every re-drive during a BUSY spell and must stay at Debug,
// and the other export's window must be left alone.
func TestAbandonLogsInfoOnlyWhenItClosedAWindow18752(t *testing.T) {
	logs := captureLogs18752(t)
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 3)

	// Matched: the generation-change abort closes our own open window.
	bumpGenerationOnEveryPageOne18752(m, h)
	if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); !errors.Is(err, ErrOwnerRGExportIncomplete) {
		t.Fatalf("export 1 err = %v, want the generation-change abort", err)
	}
	if got := logs.lines("INFO", abandonClosedMsg18752); len(got) != 1 {
		t.Fatalf("matched abandon logged %d Info %q line(s), want 1: %q", len(got), abandonClosedMsg18752, got)
	}
	if got := logs.lines("DEBUG", abandonNoMatchMsg18752); len(got) != 0 {
		t.Fatalf("matched abandon logged the no-match Debug line: %q", got)
	}

	// Unmatched: another export's window (client 777) is open, so page 1 is
	// refused BUSY and our abandon names a window that never opened.
	h.mu.Lock()
	h.beforeReply = nil
	h.nextSeq++
	h.open, h.pagesLeft, h.openClient = h.nextSeq, 2, 777
	foreign := h.open
	h.mu.Unlock()
	if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("export 2 err = %v, want the BUSY refusal", err)
	}
	open, _, abandons := h.snapshot()
	if len(abandons) != 2 {
		t.Fatalf("abandons = %d, want 2 (one per aborted export)", len(abandons))
	}
	if open != foreign {
		t.Fatalf("helper window = %d after the unmatched abandon, want the other export's window %d left open", open, foreign)
	}
	if got := logs.lines("INFO", abandonClosedMsg18752); len(got) != 1 {
		t.Fatalf("after the unmatched abandon there are %d Info %q lines, want still 1 — it closed nothing: %q",
			len(got), abandonClosedMsg18752, got)
	}
	if got := logs.lines("DEBUG", abandonNoMatchMsg18752); len(got) != 1 {
		t.Fatalf("unmatched abandon logged %d Debug %q line(s), want 1", len(got), abandonNoMatchMsg18752)
	}
}

// A helper built before #18752 refuses the verb. That is a capability gap, not
// a failed abandon: Warn once per helper generation, Debug after, and never the
// generic could-not-abandon Warn, which would repeat on every aborted export.
func TestAbandonUnsupportedVerbWarnsOncePerHelperGeneration18752(t *testing.T) {
	logs := captureLogs18752(t)
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startWindowHelper18752(t, sock, 3)
	h.noAbandonVerb = true
	bumpGenerationOnEveryPageOne18752(m, h)

	abort := func(n int) {
		t.Helper()
		// The old helper keeps the aborted window until its idle expiry;
		// model that expiry so the next export opens a fresh window.
		h.mu.Lock()
		h.open, h.pagesLeft, h.openClient = 0, 0, 0
		h.mu.Unlock()
		if _, _, err := m.ExportOwnerRGSessionsPaged([]int{1}); !errors.Is(err, ErrOwnerRGExportIncomplete) {
			t.Fatalf("export %d err = %v, want the generation-change abort", n, err)
		}
	}

	abort(1)
	abort(2)
	if _, _, abandons := h.snapshot(); len(abandons) != 2 {
		t.Fatalf("abandons sent = %d, want 2 (the Go side cannot know the helper lacks the verb until it asks)", len(abandons))
	}
	if got := logs.lines("WARN", abandonNoVerbMsg18752); len(got) != 1 {
		t.Fatalf("two aborts on one helper generation logged %d unsupported-verb Warn(s), want 1: %q", len(got), got)
	}
	if got := logs.lines("DEBUG", abandonNoVerbMsg18752); len(got) != 1 {
		t.Fatalf("the repeat logged %d unsupported-verb Debug line(s), want 1", len(got))
	}
	if got := logs.lines("WARN", abandonFailedMsg18752); len(got) != 0 {
		t.Fatalf("an unknown-verb refusal was logged as a failed abandon: %q", got)
	}

	// A new helper process may be a different build: say it again.
	m.mu.Lock()
	m.procGen++
	m.mu.Unlock()
	abort(3)
	if got := logs.lines("WARN", abandonNoVerbMsg18752); len(got) != 2 {
		t.Fatalf("after a helper restart there are %d unsupported-verb Warn(s), want 2", len(got))
	}
}
