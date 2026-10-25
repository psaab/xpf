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
	"testing"
	"time"
)

// #16589: export_idle_leases / export_persistent_lease_display were
// single unpaged responses. Past the 64 MiB control cap the bounded
// reader refused the answer and the standby rebuilt NOTHING. These
// cells drive the real Manager methods over a real socket against a
// scripted helper that pages, plus the fail-closed arms. RED on the
// pre-fix manager: it issued one request with no lease_export and
// returned only the first page (or, against a real helper, an error).

type leasePage16589 struct {
	idle    int
	display int
	more    bool
	next    string
	errText string
}

type leaseHelper16589 struct {
	pages []leasePage16589
	got   []ControlRequest
}

func startLeaseHelper16589(t *testing.T, path string, pages []leasePage16589) *leaseHelper16589 {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	h := &leaseHelper16589{pages: pages}
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
				page := leasePage16589{}
				if idx < len(h.pages) {
					page = h.pages[idx]
				}
				idx++
				resp := ControlResponse{OK: true, LeaseExportMore: page.more, LeaseExportContinuation: page.next}
				if page.errText != "" {
					resp.OK = false
					resp.Error = page.errText
				}
				scope := uint32(0)
				for i := 0; i < page.idle; i++ {
					resp.IdleLeases = append(resp.IdleLeases, IdleLeaseWire{
						Pool: "p1", Protocol: 6, SrcIP: fmt.Sprintf("10.0.0.%d", i%251),
						SrcPort: uint16(1000 + i), RoutingScope: &scope, EgressScope: &scope,
						TranslatedIP: "203.0.113.1", TranslatedPort: uint16(2000 + i),
						RemainingNs: 5, TimeoutNs: 10,
					})
				}
				for i := 0; i < page.display; i++ {
					resp.DisplayLeases = append(resp.DisplayLeases, DisplayLeaseWire{
						Pool: "p1", Protocol: 6, SrcIP: fmt.Sprintf("10.0.1.%d", i%251),
						SrcPort: uint16(3000 + i), RoutingScope: &scope, EgressScope: &scope,
						TranslatedIP: "203.0.113.1", TranslatedPort: uint16(4000 + i),
						RemainingNs: 5, TimeoutNs: 10,
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

func leaseManager16589(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := shortSockDir9322(t)
	sock := filepath.Join(dir, "c.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	m.helperStatusObserved = true
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	return m, sock
}

func TestExportIdleLeasesPagesToCompletion16589(t *testing.T) {
	m, sock := leaseManager16589(t)
	h := startLeaseHelper16589(t, sock, []leasePage16589{
		{idle: 3, more: true, next: "3"},
		{idle: 2, more: true, next: "5"},
		{idle: 1, more: false},
	})
	leases, err := m.ExportIdleLeases()
	if err != nil {
		t.Fatalf("ExportIdleLeases: %v", err)
	}
	if len(leases) != 6 {
		t.Fatalf("leases = %d, want 6 across 3 pages", len(leases))
	}
	if len(h.got) != 3 {
		t.Fatalf("helper got %d requests, want 3", len(h.got))
	}
	wantCursors := []string{"", "3", "5"}
	for i, req := range h.got {
		if req.Type != "export_idle_leases" || req.LeaseExport == nil || !req.LeaseExport.Paged {
			t.Fatalf("request %d = %+v, want paged export_idle_leases", i, req)
		}
		if req.LeaseExport.Cursor != wantCursors[i] {
			t.Errorf("request %d cursor = %q, want %q", i, req.LeaseExport.Cursor, wantCursors[i])
		}
		if !req.SuppressStatus {
			t.Errorf("request %d must suppress status", i)
		}
	}
}

func TestExportPersistentLeaseDisplayPagesToCompletion16589(t *testing.T) {
	m, sock := leaseManager16589(t)
	h := startLeaseHelper16589(t, sock, []leasePage16589{
		{display: 2, more: true, next: "2"},
		{display: 2, more: false},
	})
	rows, err := m.ExportPersistentLeaseDisplay()
	if err != nil {
		t.Fatalf("ExportPersistentLeaseDisplay: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4 across 2 pages", len(rows))
	}
	if len(h.got) != 2 || h.got[1].LeaseExport == nil || h.got[1].LeaseExport.Cursor != "2" {
		t.Fatalf("requests = %+v, want 2 paged with cursor 2 second", h.got)
	}
}

// Small population stays single-page: one request, no continuation.
func TestLeaseExportSmallPopulationSinglePage16589(t *testing.T) {
	m, sock := leaseManager16589(t)
	h := startLeaseHelper16589(t, sock, []leasePage16589{{idle: 2, more: false}})
	leases, err := m.ExportIdleLeases()
	if err != nil {
		t.Fatalf("ExportIdleLeases: %v", err)
	}
	if len(leases) != 2 || len(h.got) != 1 {
		t.Fatalf("leases=%d requests=%d, want 2/1", len(leases), len(h.got))
	}
}

// Fail-closed arms: a partial population is never returned as complete.
func TestLeaseExportFailClosedArms16589(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pages []leasePage16589
	}{
		{"incomplete without continuation", []leasePage16589{{idle: 1, more: true, next: ""}}},
		{"repeated continuation", []leasePage16589{{idle: 1, more: true, next: "1"}, {idle: 1, more: true, next: "1"}}},
		{"complete with continuation", []leasePage16589{{idle: 1, more: false, next: "9"}}},
		{"page error", []leasePage16589{{errText: "boom"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, sock := leaseManager16589(t)
			startLeaseHelper16589(t, sock, tc.pages)
			if _, err := m.ExportIdleLeases(); err == nil {
				t.Fatal("must fail closed, got nil error")
			}
		})
	}
}

// Below the paging floor the export refuses BEFORE any lease request:
// an old helper would answer unpaged and be refused past the cap.
func TestLeaseExportsRefusePrePagingHelper16589(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   func(*Manager) error
	}{
		{"idle", func(m *Manager) error { _, err := m.ExportIdleLeases(); return err }},
		{"display", func(m *Manager) error { _, err := m.ExportPersistentLeaseDisplay(); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
			m.helperStatusObserved = true
			m.lastStatus.ConfigSnapshotProtocolVersion = MinProtocolPersistentNatLeasePaging - 1
			leaseCrossed := false
			m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				if req.Type == "status" {
					// Observed 70 passes the permission/scope gates
					// from cache, so a status call here is the paging
					// gate re-probing (its >= fast path cannot pass at
					// 70 < 71, by design). Answer the same version so
					// it refuses on the floor.
					status.ConfigSnapshotProtocolVersion = MinProtocolPersistentNatLeasePaging - 1
					return nil
				}
				leaseCrossed = true
				return errors.New("lease verb crossed to a pre-paging helper")
			}
			if err := tc.op(m); !errors.Is(err, ErrPersistentNatLeaseScopeProtocolIncompatible) {
				t.Fatalf("err = %v, want ErrPersistentNatLeaseScopeProtocolIncompatible", err)
			}
			if leaseCrossed {
				t.Fatal("a lease request crossed to a pre-paging helper")
			}
		})
	}
}

// The pure pager terminates a helper that always says more.
func TestPagedLeaseExport16589PageCeiling(t *testing.T) {
	calls := 0
	_, err := pagedLeaseExport16589(func(cursor string) ([]int, bool, string, error) {
		calls++
		return []int{1}, true, fmt.Sprintf("%d", calls), nil
	})
	if err == nil {
		t.Fatal("non-terminating export must error")
	}
	if calls != maxLeaseExportPages16589 {
		t.Fatalf("calls = %d, want %d", calls, maxLeaseExportPages16589)
	}
}

// Work-deadline floors exist for both verbs (#11840 shape).
func TestLeaseExportWorkDeadlineFloors16589(t *testing.T) {
	for _, verb := range []string{"export_idle_leases", "export_persistent_lease_display"} {
		floor, ok := controlVerbDeadlineFloors9344[verb]
		if !ok {
			t.Fatalf("no work-deadline floor for %s", verb)
		}
		if got := controlWorkDeadline(verb, 60); got != floor || got <= controlBaseDeadline {
			t.Errorf("%s deadline = %v, want floor %v above base", verb, got, floor)
		}
	}
}
