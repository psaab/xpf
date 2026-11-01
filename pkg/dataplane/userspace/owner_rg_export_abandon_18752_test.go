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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type windowHelper18752 struct {
	mu        sync.Mutex
	open      uint64 // open window sequence, 0 = none
	nextSeq   uint64
	pagesLeft int // pages after page 1 in the open window
	abandons  []SessionExportRequest
	busy      int
	// beforeReply runs after a request is read and before it is answered,
	// with no helper lock held: the cell uses it to change the Manager's
	// config generation while a page is in flight.
	beforeReply func(req ControlRequest)
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
	case req.Type == "abandon_owner_rg_export":
		h.abandons = append(h.abandons, *ex)
		if ex.ContinuationIncarnation == 1 && ex.ContinuationSequence == h.open {
			h.open, h.pagesLeft = 0, 0
		}
		return ControlResponse{OK: true}
	case req.Type != "export_owner_rg_sessions":
		return ControlResponse{OK: false, Error: "unknown request type " + req.Type}
	case !ex.Continuation:
		if h.open != 0 {
			h.busy++
			return ControlResponse{OK: false, Error: fmt.Sprintf(
				"owner-RG export busy (window %d open); retry with backoff", h.open)}
		}
		h.nextSeq++
		h.open, h.pagesLeft = h.nextSeq, pagesPerWindow-1
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
		h.open = 0
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
		abandons[0].ProtocolVersion != MinProtocolOwnerRGExportPaging {
		t.Fatalf("abandons after the aborted export = %+v, want exactly one for token (1,1) at protocol %d",
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
