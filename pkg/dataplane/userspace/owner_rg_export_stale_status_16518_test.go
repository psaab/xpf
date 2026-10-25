package userspace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// #16518: ExportOwnerRGSessionsPaged drops m.mu for each page RPC and, pre-fix,
// applied that page's attached helper status on re-lock behind only a
// proc/procGen/generation/socket fence. A disarm that queued behind the page
// RPC on controlReqMu applies its fresh DISARMED status first; the pager then
// overwrote it with the older ARMED page status, leaving userspace_ctrl
// Enabled=1 and lastStatus.ForwardingArmed=true while the helper was disarmed
// until the next page or the 1 Hz poll.
//
// The fix: every page request sets SuppressStatus and the pager never applies
// an attached page status. Both production callers discard the returned
// status, so nothing is lost; helper truth continues via the poll.
//
// This cell is arranged so it cannot pass for the wrong reason:
//
//   - The fake helper DELIBERATELY ignores SuppressStatus and attaches a ready
//     ARMED status to page 1 (emulating a helper that answers with the status
//     it captured before a concurrent disarm). If the pager still applied it,
//     applyHelperStatusLocked would enable ctrl and record ForwardingArmed.
//   - The manager is seamed (#6994 hooks) so that apply WOULD succeed and
//     write ctrl Enabled=1 — verified by the explicit control arm below,
//     which drives the same status through applyHelperStatusLocked directly.
//   - The cell asserts the observable end state the issue specifies: after
//     the export, ctrl was never enabled, the cached status is not armed, and
//     every request on the wire carried suppress_status=true.
//
// RED on revert: restore the per-page applyHelperStatusLocked (drop
// SuppressStatus) and page 1's ready status enables ctrl — the first
// assertion fails. Keep SuppressStatus but re-add the apply and it still
// fails, because a helper that ignores the flag (or raced it) can attach a
// stale status; the pager must not apply it.

type staleStatusHelper16518 struct {
	got []ControlRequest
}

func startStaleStatusHelper16518(t *testing.T, path string) *staleStatusHelper16518 {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	h := &staleStatusHelper16518{}
	idx := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				var req ControlRequest
				if err := json.Unmarshal(line, &req); err != nil {
					return
				}
				h.got = append(h.got, req)
				page := pageReply9344{}
				pages := []pageReply9344{{deltas: 1, more: true}, {deltas: 1, more: false}}
				if idx < len(pages) {
					page = pages[idx]
				}
				idx++
				resp := ControlResponse{
					OK:                       true,
					SessionExportMore:        page.more,
					SessionExportIncarnation: 1,
					SessionExportSeq:         1,
				}
				// Deliberately ignore req.SuppressStatus: attach the stale
				// ARMED status a pre-disarm helper snapshot would carry.
				// readyHelperStatus has ForwardingArmed unset; set it so the
				// lastStatus leg of the defect is also exercised.
				st := readyHelperStatus()
				st.ForwardingArmed = true
				st.SessionExportPagingProtocolVersion = MinProtocolOwnerRGExportPaging
				st.SessionExportIncarnation = 1
				resp.Status = st
				for i := range page.deltas {
					resp.SessionDeltas = append(resp.SessionDeltas, SessionDeltaInfo{
						Event: "open", SrcIP: fmt.Sprintf("10.0.0.%d", i%251),
					})
				}
				body, _ := json.Marshal(&resp)
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_, _ = c.Write(append(body, '\n'))
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return h
}

func TestExportPagedDoesNotApplyStalePageStatus16518(t *testing.T) {
	m, ctrl := seamedManager(t)
	dir, err := os.MkdirTemp("", "x16518")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	m.lastStatus.SessionExportPagingProtocolVersion = MinProtocolOwnerRGExportPaging
	m.lastStatus.SessionExportIncarnation = 1
	// Helper is DISARMED truth at export start: the cached status must stay
	// disarmed; only the stale page status says armed.
	m.lastStatus.ForwardingArmed = false

	h := startStaleStatusHelper16518(t, sock)

	deltas, status, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err != nil {
		t.Fatalf("ExportOwnerRGSessionsPaged: %v", err)
	}
	if len(deltas) != 2 {
		t.Fatalf("collected %d deltas, want 2 across two pages", len(deltas))
	}
	if len(h.got) != 2 {
		t.Fatalf("helper saw %d requests, want 2", len(h.got))
	}
	for i, req := range h.got {
		if !req.SuppressStatus {
			t.Fatalf("request %d SuppressStatus = false, want true (#16518: "+
				"the pager must not ask the helper to attach a per-page status)", i)
		}
	}
	if ctrl.haveStored && ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after paged export, want 0/disabled: the "+
			"pager applied page 1's stale ARMED status over the disarmed "+
			"cached truth (#16518)", ctrl.stored.Enabled)
	}
	if m.lastStatus.ForwardingArmed {
		t.Fatal("lastStatus.ForwardingArmed = true after paged export: the " +
			"pager recorded the stale page status as helper truth (#16518)")
	}
	if status.ForwardingArmed {
		t.Fatalf("returned status.ForwardingArmed = true, want the cached "+
			"disarmed status; got %+v", status)
	}

	// Control: the same ready/armed status DOES enable ctrl when applied
	// through applyHelperStatusLocked directly. Without this arm the
	// assertions above could pass merely because the fixture status never
	// satisfied the readiness gates.
	control, controlCtrl := seamedManager(t)
	st := readyHelperStatus()
	st.ForwardingArmed = true
	if err := control.applyHelperStatusLocked(st); err != nil {
		t.Fatalf("control applyHelperStatusLocked: %v", err)
	}
	if !controlCtrl.haveStored || controlCtrl.stored.Enabled != 1 {
		t.Fatalf("control: ctrl = %+v (haveStored=%v), want Enabled=1 — the "+
			"fixture status does not arm, so the defect arm above is vacuous",
			controlCtrl.stored, controlCtrl.haveStored)
	}
	if !control.lastStatus.ForwardingArmed {
		t.Fatal("control: lastStatus.ForwardingArmed = false after a direct " +
			"armed apply — the fixture cannot reproduce the recorded-status leg")
	}
}
