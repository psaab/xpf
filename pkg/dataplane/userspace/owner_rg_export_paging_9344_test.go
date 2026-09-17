package userspace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// #9344: the owner-RG session export had no terminating bound. `max=0` (the
// only complete request a caller could make) answers with the UNBOUNDED session
// set and crosses the 64 MiB response cap at ~7.8k sessions/worker on a
// six-worker box, so the HA cold prime fails permanently on a busy cluster.
//
// Before this change NO test drove `max > 0` on this verb at all, which is why
// the paging primitive could be built and discarded (`_overflow`) without
// anything noticing.

// pagingHelper9344 is a fake helper that records every request it receives and
// answers from a scripted list of pages.
type pagingHelper9344 struct {
	t     *testing.T
	pages []pageReply9344
	// got records the decoded requests, in order.
	got  []ControlRequest
	done chan struct{}
}

type pageReply9344 struct {
	deltas int
	more   bool
}

func startPagingHelper9344(t *testing.T, path string, pages []pageReply9344) *pagingHelper9344 {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	h := &pagingHelper9344{t: t, pages: pages, done: make(chan struct{})}
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
				if idx < len(h.pages) {
					page = h.pages[idx]
				}
				idx++
				resp := ControlResponse{
					OK:                       true,
					SessionExportMore:        page.more,
					SessionExportIncarnation: 1,
					SessionExportSeq:         1,
				}
				for i := 0; i < page.deltas; i++ {
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

func pagingManager9344(t *testing.T, pagingVersion int) (*Manager, *pagingHelper9344, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "x9344")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	m.lastStatus.SessionExportPagingProtocolVersion = pagingVersion
	if pagingVersion >= MinProtocolOwnerRGExportPaging {
		m.lastStatus.SessionExportIncarnation = 1
	}
	return m, nil, sock
}

// TestOwnerRGExportPagesUntilTheHelperSaysNoMore9344 is the fix.
//
// Three pages, the first two reporting more. The caller must issue exactly
// three requests, concatenate all three payloads, and mark every request after
// the first as a CONTINUATION — a non-continuation would re-run the helper's
// phase 1 and stack a second full set from a different instant onto the
// remainder of this one, which is the duplicate-window harm, not paging.
func TestOwnerRGExportPagesUntilTheHelperSaysNoMore9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startPagingHelper9344(t, sock, []pageReply9344{
		{deltas: 3, more: true},
		{deltas: 4, more: true},
		{deltas: 2, more: false},
	})

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1, 2})
	if err != nil {
		t.Fatalf("ExportOwnerRGSessionsPaged: %v", err)
	}
	if len(deltas) != 9 {
		t.Errorf("collected %d deltas, want 9 — the pages must CONCATENATE into one "+
			"window; a caller that returns only the last page hands the peer a window "+
			"missing everything before it, and #5085 deletes the difference", len(deltas))
	}
	if len(h.got) != 3 {
		t.Fatalf("helper saw %d requests, want 3", len(h.got))
	}
	for i, req := range h.got {
		if req.Type != "export_owner_rg_sessions" {
			t.Errorf("request %d type = %q", i, req.Type)
			continue
		}
		if req.SessionExport == nil {
			t.Errorf("request %d carries no SessionExport", i)
			continue
		}
		if req.SessionExport.Max != ownerRGExportPageDeltas {
			t.Errorf("request %d Max = %d, want %d — an uncapped page is the defect "+
				"this issue is about", i, req.SessionExport.Max, ownerRGExportPageDeltas)
		}
		wantCont := i > 0
		if req.SessionExport.Continuation != wantCont {
			t.Errorf("request %d Continuation = %v, want %v. A non-continuation page "+
				"re-kicks phase 1 and produces ANOTHER full set on top of the "+
				"remainder, so the caller would assemble a window out of two "+
				"different instants", i, req.SessionExport.Continuation, wantCont)
		}
		if len(req.SessionExport.OwnerRGs) != 2 {
			t.Errorf("request %d OwnerRGs = %v, want the caller's set on every page",
				i, req.SessionExport.OwnerRGs)
		}
	}
}

// TestOwnerRGExportStopsAtOnePageWhenNothingRemains9344 is the boundary the
// paging cell above cannot see: a window that fits in one page must cost ONE
// round trip, not one plus a probe.
func TestOwnerRGExportStopsAtOnePageWhenNothingRemains9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startPagingHelper9344(t, sock, []pageReply9344{{deltas: 5, more: false}})

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err != nil {
		t.Fatalf("ExportOwnerRGSessionsPaged: %v", err)
	}
	if len(deltas) != 5 {
		t.Errorf("collected %d deltas, want 5", len(deltas))
	}
	if len(h.got) != 1 {
		t.Errorf("helper saw %d requests, want 1 — a continuation issued after "+
			"more=false would drain deltas produced by the STEADY-STATE path and "+
			"fold them into a bulk window", len(h.got))
	}
}

// TestOwnerRGExportEmptyOwnerRGSetReturnsWithoutAZeroToken9856 preserves the
// empty-owner compatibility path while the paged contract rejects zero tokens.
func TestOwnerRGExportEmptyOwnerRGSetReturnsWithoutAZeroToken9856(t *testing.T) {
	m, _, _ := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	deltas, status, err := m.ExportOwnerRGSessionsPaged(nil)
	if err != nil {
		t.Fatalf("empty owner-RG export: %v", err)
	}
	if deltas != nil {
		t.Fatalf("empty owner-RG export returned %d deltas", len(deltas))
	}
	if status.SessionExportPagingProtocolVersion != MinProtocolOwnerRGExportPaging {
		t.Fatalf("status protocol = %d, want %d",
			status.SessionExportPagingProtocolVersion, MinProtocolOwnerRGExportPaging)
	}
}

// TestOwnerRGExportAllowsTerminalProbeAfterExactDataPageBudget9344 covers the
// worker push-before-ACK seam: a full final data page can report more=true
// before its ACK is visible, so the caller needs one empty terminal probe.
func TestOwnerRGExportAllowsTerminalProbeAfterExactDataPageBudget9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	pages := make([]pageReply9344, maxOwnerRGExportPages)
	for i := range maxOwnerRGExportDataPages {
		pages[i] = pageReply9344{deltas: 1, more: true}
	}
	pages[maxOwnerRGExportDataPages] = pageReply9344{more: false}
	h := startPagingHelper9344(t, sock, pages)

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err != nil {
		t.Fatalf("ExportOwnerRGSessionsPaged: %v", err)
	}
	if len(deltas) != maxOwnerRGExportDataPages {
		t.Fatalf("collected %d deltas, want %d data pages", len(deltas), maxOwnerRGExportDataPages)
	}
	if len(h.got) != maxOwnerRGExportPages {
		t.Fatalf("helper saw %d requests, want %d data pages plus one terminal probe",
			len(h.got), maxOwnerRGExportPages)
	}
	probe := h.got[maxOwnerRGExportDataPages].SessionExport
	if probe == nil || !probe.Continuation {
		t.Fatalf("terminal probe must continue the exact export window: %#v", probe)
	}
}

// TestOwnerRGExportReleasesManagerLockWhilePageWaits9344 proves that paging
// does not monopolize the Manager mutex during helper I/O. A stalled response
// still lets another Manager operation acquire m.mu; the export revalidates
// the helper/config generations before applying the response.
func TestOwnerRGExportReleasesManagerLockWhilePageWaits9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	requestRead := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if _, err := bufio.NewReader(conn).ReadBytes('\n'); err != nil {
			serverDone <- err
			return
		}
		close(requestRead)
		<-release
		resp := ControlResponse{
			OK:                       true,
			SessionExportIncarnation: 1,
			SessionExportSeq:         1,
		}
		if err := json.NewEncoder(conn).Encode(&resp); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	exportDone := make(chan error, 1)
	go func() {
		_, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
		exportDone <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not receive export request")
	}
	if !m.mu.TryLock() {
		t.Fatal("Manager mutex remained held while export response was stalled")
	}
	m.mu.Unlock()
	close(release)
	if err := <-exportDone; err != nil {
		t.Fatalf("ExportOwnerRGSessionsPaged: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("stalled helper: %v", err)
	}
}

// TestOwnerRGExportRejectsResponseAfterHelperGenerationChange9344 proves that
// releasing m.mu does not admit a response from a retired helper generation.
func TestOwnerRGExportRejectsResponseAfterHelperGenerationChange9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	requestRead := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if _, err := bufio.NewReader(conn).ReadBytes('\n'); err != nil {
			serverDone <- err
			return
		}
		close(requestRead)
		<-release
		resp := ControlResponse{
			OK:                       true,
			SessionExportIncarnation: 1,
			SessionExportSeq:         1,
		}
		serverDone <- json.NewEncoder(conn).Encode(&resp)
	}()

	exportDone := make(chan error, 1)
	go func() {
		_, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
		exportDone <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not receive export request")
	}
	m.mu.Lock()
	m.procGen++
	m.mu.Unlock()
	close(release)
	if err := <-exportDone; !errors.Is(err, ErrOwnerRGExportIncomplete) {
		t.Fatalf("err = %v, want ErrOwnerRGExportIncomplete after helper generation change", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("stalled helper: %v", err)
	}
}

// TestOwnerRGExportRejectsOversizedDataPage9344 keeps the helper's per-response
// contract fail closed: an oversized page must not be appended to the bounded
// accumulator or treated as a valid terminal page.
func TestOwnerRGExportRejectsOversizedDataPage9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	h := startPagingHelper9344(t, sock, []pageReply9344{
		{deltas: ownerRGExportPageDeltas + 1, more: false},
	})

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if !errors.Is(err, ErrOwnerRGExportIncomplete) {
		t.Fatalf("err = %v, want ErrOwnerRGExportIncomplete", err)
	}
	if deltas != nil {
		t.Fatalf("returned %d deltas alongside oversized page", len(deltas))
	}
	if len(h.got) != 1 {
		t.Fatalf("helper saw %d requests, want 1", len(h.got))
	}
}

// TestOwnerRGExportRejectsAccumulatorBudget9344 prevents the multi-page
// collector from turning a bounded response into an unbounded Go allocation.
func TestOwnerRGExportRejectsAccumulatorBudget9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	pages := make([]pageReply9344, maxOwnerRGExportAccumulatorPages+1)
	for i := range maxOwnerRGExportAccumulatorPages + 1 {
		pages[i] = pageReply9344{deltas: ownerRGExportPageDeltas, more: true}
	}
	h := startPagingHelper9344(t, sock, pages)

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if !errors.Is(err, ErrOwnerRGExportIncomplete) {
		t.Fatalf("err = %v, want ErrOwnerRGExportIncomplete", err)
	}
	if deltas != nil {
		t.Fatalf("returned %d deltas alongside accumulator-budget error", len(deltas))
	}
	if len(h.got) != maxOwnerRGExportAccumulatorPages+1 {
		t.Fatalf("helper saw %d requests, want %d before the budget refusal",
			len(h.got), maxOwnerRGExportAccumulatorPages+1)
	}
}

// TestOwnerRGExportFailsClosedWhenTheHelperNeverStops9344 pins the bound.
//
// "The answer is unbounded" is no better when the unboundedness is a page count
// instead of a byte count. It must FAIL, not return the pages collected so far:
// a partial window is what #5085 turns into deleted live sessions on the peer,
// so the one thing this must never do is succeed with less than everything.
func TestOwnerRGExportFailsClosedWhenTheHelperNeverStops9344(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	// An empty script means every reply is the zero page with more=false...
	// so script one page that always says more by making the list long enough.
	pages := make([]pageReply9344, maxOwnerRGExportPages+5)
	for i := range pages {
		pages[i] = pageReply9344{deltas: 1, more: true}
	}
	h := startPagingHelper9344(t, sock, pages)

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if !errors.Is(err, ErrOwnerRGExportUnterminated) {
		t.Fatalf("err = %v, want ErrOwnerRGExportUnterminated", err)
	}
	if deltas != nil {
		t.Errorf("returned %d deltas alongside the error; a partial window must not "+
			"escape, because the receiver would DELETE every session missing from it",
			len(deltas))
	}
	if len(h.got) != maxOwnerRGExportPages {
		t.Errorf("helper saw %d requests, want exactly %d — the loop must stop AT the "+
			"bound, not one past it or short of it", len(h.got), maxOwnerRGExportPages)
	}
}

// TestOwnerRGExportFallsBackToUnboundedWithoutThePagingContract9344 is the
// skew arm, and it is the one that decides whether this change is safe to ship
// against a helper that has not been upgraded yet.
//
// A helper predating #9344 honours `max` by TRUNCATING and reports no more-bit.
// Paging it would return exactly one page and silently drop the rest — trading
// a LOUD failure (the 64 MiB cap, which #9322 made diagnosable) for a SILENT
// one that deletes live sessions on the peer. The caller must therefore ask
// such a helper for the unbounded set, exactly as it always did.
func TestOwnerRGExportRefusesWithoutThePagingContract9856(t *testing.T) {
	m, _, sock := pagingManager9344(t, 0)
	startPagingHelper9344(t, sock, []pageReply9344{{deltas: 7, more: false}})

	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if !errors.Is(err, ErrOwnerRGExportIncomplete) {
		t.Fatalf("err = %v, want ErrOwnerRGExportIncomplete for v1 helper", err)
	}
	if deltas != nil {
		t.Fatalf("returned %d deltas alongside v1 refusal; a partial window must not escape", len(deltas))
	}
}

// TestOwnerRGExportPageFitsTheResponseCap9344 derives the page size against the
// worst case rather than trusting the constant's comment.
//
// The worst case is built by REFLECTION over SessionDeltaInfo — every string
// field a full-width IPv6 literal, every numeric at its type maximum — so a
// field added to the wire schema moves this measurement instead of leaving a
// stale number in a comment. The measured value is also the lower bound for
// ownerRGExportEstimatedDeltaBytes, which sizes retained pages.
func TestOwnerRGExportPageFitsTheResponseCap9344(t *testing.T) {
	worst := worstCaseDeltaBytes9344(t)
	if worst < 200 {
		t.Fatalf("VOID: the worst-case delta measured %d bytes, which is too small to "+
			"be a worst case — the synthesizer is not filling the struct and every "+
			"comparison below would pass for the wrong reason", worst)
	}
	if ownerRGExportEstimatedDeltaBytes < worst {
		t.Fatalf("estimated delta size %d is below reflected worst-case %d; the "+
			"accumulator bound would undercount memory", ownerRGExportEstimatedDeltaBytes, worst)
	}
	page := ownerRGExportPageDeltas * worst
	if page >= MaxControlResponseBytes {
		t.Errorf("a full page is %d bytes of deltas against a %d-byte response cap; "+
			"ownerRGExportPageDeltas (%d) x worst-case delta (%d) must leave room for "+
			"the rest of the response", page, MaxControlResponseBytes,
			ownerRGExportPageDeltas, worst)
	}
	// A page that merely fits is a page that fails the first time the worst
	// case is underestimated. Require real margin, and say what it is.
	const wantMargin = 4
	if got := MaxControlResponseBytes / page; got < wantMargin {
		t.Errorf("page margin is %dx (%d bytes of %d), want at least %dx",
			got, page, MaxControlResponseBytes, wantMargin)
	}
	t.Logf("worst-case delta %d B; page %d deltas = %d B; margin %.1fx of the %d B cap",
		worst, ownerRGExportPageDeltas, page,
		float64(MaxControlResponseBytes)/float64(page), MaxControlResponseBytes)
}

// worstCaseDeltaBytes9344 marshals a SessionDeltaInfo with every field at its
// most expensive value.
func worstCaseDeltaBytes9344(t *testing.T) int {
	t.Helper()
	const wideIPv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	v := reflect.New(reflect.TypeOf(SessionDeltaInfo{})).Elem()
	filled := 0
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString(wideIPv6)
			filled++
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			f.SetUint(^uint64(0) >> (64 - f.Type().Bits()))
			filled++
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			f.SetInt(int64(^uint64(0) >> (65 - f.Type().Bits())))
			filled++
		case reflect.Bool:
			f.SetBool(true)
			filled++
		}
	}
	if filled == 0 {
		t.Fatalf("VOID: filled no field of SessionDeltaInfo")
	}
	body, err := json.Marshal(v.Interface())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return len(body)
}

// TestOwnerRGExportAckWaitMatchesTheHelper9344 binds the Go constant to the
// Rust one by READING it, not by restating the number.
//
// The Go deadline floor is derived from the helper's ack-wait, so if the helper
// raises its wait and this constant stays put, the caller goes back to
// abandoning round trips the helper is still performing — silently, because the
// symptom is a timeout that looks like a dead helper.
func TestOwnerRGExportAckWaitMatchesTheHelper9344(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/afxdp/ha/export.rs")
	if err != nil {
		t.Fatalf("read the helper source: %v — this cell cannot check the agreement "+
			"without it, and passing anyway would be asserting nothing", err)
	}
	re := regexp.MustCompile(`OWNER_RG_EXPORT_ACK_WAIT:\s*Duration\s*=\s*Duration::from_secs\((\d+)\)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("could not find OWNER_RG_EXPORT_ACK_WAIT in the helper source. Either "+
			"it was renamed or its shape changed; this cell is now blind and must be "+
			"repointed rather than deleted. Source contains %q: %v",
			"OWNER_RG_EXPORT_ACK_WAIT", strings.Contains(string(src), "OWNER_RG_EXPORT_ACK_WAIT"))
	}
	var secs int
	if _, err := fmt.Sscanf(string(m[1]), "%d", &secs); err != nil {
		t.Fatalf("parse %q: %v", m[1], err)
	}
	if got := time.Duration(secs) * time.Second; got != ownerRGExportAckWait {
		t.Errorf("the helper waits %v for export acks but ownerRGExportAckWait is %v; "+
			"the Go round-trip floor is derived from this, so a drift puts the caller "+
			"back to timing out on a helper that is working", got, ownerRGExportAckWait)
	}
}

// TestExportOwnerRGSessionsGetsAWorkDeadlineFloor9344 is the adjacent finding.
//
// controlRoundtripDeadline sizes off the REQUEST BODY. This verb's body is ~60
// bytes, so it landed on the 3 s small-request base while the helper spends up
// to 15 s waiting for worker acks before writing its first byte. Both arms
// matter: the floor must apply to this verb, and it must NOT leak to the
// frequent small verbs whose responsiveness the #182 contention discipline
// depends on.
func TestExportOwnerRGSessionsGetsAWorkDeadlineFloor9344(t *testing.T) {
	const smallBody = 60
	if got := controlRoundtripDeadline(smallBody); got != controlBaseDeadline {
		t.Fatalf("CONTROL: a %d-byte body sizes to %v, want the %v base — if this "+
			"changed, the arms below are not measuring the floor", smallBody, got,
			controlBaseDeadline)
	}
	got := controlWorkDeadline("export_owner_rg_sessions", smallBody)
	if got <= controlBaseDeadline {
		t.Errorf("export_owner_rg_sessions deadline = %v, still the small-request "+
			"base; the helper can spend %v on worker acks alone before replying",
			got, ownerRGExportAckWait)
	}
	if got < ownerRGExportAckWait {
		t.Errorf("export_owner_rg_sessions deadline = %v, below the helper's own %v "+
			"ack-wait — the caller would abandon a round trip the helper is still "+
			"legitimately performing", got, ownerRGExportAckWait)
	}
	// The status poll runs 1/s and every session install shares this socket.
	for _, verb := range []string{"status", "apply_snapshot", "drain_session_deltas"} {
		if d := controlWorkDeadline(verb, smallBody); d != controlBaseDeadline {
			t.Errorf("%q with a small body = %v, want the %v base unchanged — a floor "+
				"that leaks to the frequent verbs trades a rare timeout for a slow "+
				"control plane", verb, d, controlBaseDeadline)
		}
	}
	// It must not raise the ceiling the #7675 reachable-bound analysis uses.
	if max := controlWorkDeadline("export_owner_rg_sessions", MaxControlRequestBytes); max > controlMaxDeadline {
		t.Errorf("the floor pushed the deadline to %v, past the %v clamp", max, controlMaxDeadline)
	}
	if ownerRGExportAckWait+controlBaseDeadline >= controlBaseDeadline+64*controlDeadlinePerMiB {
		t.Errorf("the export floor (%v) is at or above the #7675 REACHABLE bound "+
			"(%v, a 64 MiB apply). Raising the reachable bound changes what a stop "+
			"can be holding against the unit's TimeoutStopSec, which is a decision "+
			"that belongs with #8526's shutdown census, not a side effect here",
			ownerRGExportAckWait+controlBaseDeadline,
			controlBaseDeadline+64*controlDeadlinePerMiB)
	}
}

// TestRequestDetailedArmsTheWorkDeadline9344 binds the WIRING, not the sizing
// function.
//
// The cell above (TestExportOwnerRGSessionsGetsAWorkDeadlineFloor9344) calls
// controlWorkDeadline directly, and a mutation proved that is not enough:
// swapping the call site in requestDetailedLocked back to
// controlRoundtripDeadline left the whole suite GREEN. The floor was correct
// and unreachable. This drives a real round trip and reads back what
// armControlIO actually applied to the socket.
//
// Both arms are required. Without the control verb, a change that armed the
// export floor on EVERY request would pass — and that is not a smaller mistake:
// it slows the 1/s status poll and every session install on the same socket,
// which is what the #182 contention discipline is about.
func TestRequestDetailedArmsTheWorkDeadline9344(t *testing.T) {
	arm := func(t *testing.T, verb string) time.Duration {
		t.Helper()
		dir, err := os.MkdirTemp("", "x9344d")
		if err != nil {
			t.Fatalf("mkdtemp: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock := filepath.Join(dir, "c.sock")
		startPagingHelper9344(t, sock, []pageReply9344{{deltas: 0, more: false}})
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = sock
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, err := m.requestDetailedLocked(ControlRequest{
			Type:          verb,
			SessionExport: &SessionExportRequest{OwnerRGs: []int{1}},
		}); err != nil {
			t.Fatalf("%s round trip: %v", verb, err)
		}
		m.ctrlIOMu.Lock()
		defer m.ctrlIOMu.Unlock()
		return m.lastArmedControlDeadline
	}

	// CONTROL: a small request on an ordinary verb must still get the base.
	if got := arm(t, "status"); got != controlBaseDeadline {
		t.Fatalf("status armed %v, want the %v base — a floor that leaks to the "+
			"frequent verbs trades a rare timeout for a slow control plane",
			got, controlBaseDeadline)
	}
	got := arm(t, "export_owner_rg_sessions")
	if got < ownerRGExportAckWait {
		t.Errorf("export_owner_rg_sessions armed %v on the socket, below the helper's "+
			"own %v ack-wait. The sizing function may be right and still not be "+
			"REACHED — that is what this cell exists to catch, and it is how the "+
			"defect was found", got, ownerRGExportAckWait)
	}
	if want := controlVerbDeadlineFloors9344["export_owner_rg_sessions"]; got != want {
		t.Errorf("export_owner_rg_sessions armed %v, want the declared floor %v", got, want)
	}
}
