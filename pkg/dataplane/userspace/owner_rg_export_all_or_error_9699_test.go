package userspace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"testing"
	"time"
)

// #9699: the owner-RG export contract is ONE COMPLETE WINDOW OR AN ERROR (#5085's
// receiver deletes every session missing from a window). Three Manager return
// sites returned the deltas collected so far together with a failed helper-status
// apply, and the runtime passthrough wrapped them into a snapshot returned with
// the error.
//
// startStatusHelper9699 answers every export request with `deltas` deltas and a
// helper Status, so the manager runs applyHelperStatusLocked on the response.
// With no shim maps loaded in a test manager that apply fails deterministically
// ("userspace_ctrl map not loaded"), which is exactly the error these exits
// mishandled.
func startStatusHelper9699(t *testing.T, path string, deltas int, more bool) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := bufio.NewReader(c).ReadBytes('\n'); err != nil {
					return
				}
				resp := ControlResponse{OK: true, SessionExportMore: more, Status: &ProcessStatus{Enabled: true}}
				for i := 0; i < deltas; i++ {
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
}

func requireNoDeltasOnError9699(t *testing.T, site string, n int, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: the failing helper-status apply returned no error; this cell is not exercising the error exit", site)
	}
	if n != 0 {
		t.Fatalf("%s returned %d deltas together with an error (%v): a partial window beside an error breaks the one-complete-window-or-error contract", site, n, err)
	}
}

func TestPagedOwnerRGExportReturnsNoDeltasWithAStatusError9699(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	startStatusHelper9699(t, sock, 3, true)
	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	requireNoDeltasOnError9699(t, "ExportOwnerRGSessionsPaged (paged)", len(deltas), err)
}

func TestUnpagedOwnerRGExportReturnsNoDeltasWithAStatusError9699(t *testing.T) {
	m, _, sock := pagingManager9344(t, 0)
	startStatusHelper9699(t, sock, 3, false)
	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	requireNoDeltasOnError9699(t, "ExportOwnerRGSessionsPaged (unpaged fallback)", len(deltas), err)
}

func TestExportOwnerRGSessionsReturnsNoDeltasWithAStatusError9699(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	startStatusHelper9699(t, sock, 3, false)
	deltas, _, err := m.ExportOwnerRGSessions([]int{1}, 0)
	requireNoDeltasOnError9699(t, "ExportOwnerRGSessions", len(deltas), err)
}

func TestRuntimeOwnerRGExportPassthroughCarriesNoDeltasOnError9699(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	startStatusHelper9699(t, sock, 3, false)
	snap, err := runtimeSessionDeltaSource{manager: m}.ExportOwnerRGSessions([]int{1}, 0)
	requireNoDeltasOnError9699(t, "runtimeSessionDeltaSource.ExportOwnerRGSessions", len(snap.Deltas), err)
}

// TestRuntimeOwnerRGExportSnapshotDropsDeltasOnError9699 exercises the
// passthrough's own rule. The runtime cell above cannot: the manager already
// returns nil deltas on error, so that cell passed with the rule reverted (the
// first matrix scored that mutant ESCAPED).
func TestRuntimeOwnerRGExportSnapshotDropsDeltasOnError9699(t *testing.T) {
	deltas := []SessionDeltaInfo{{Event: "open", SrcIP: "10.0.0.1"}, {Event: "open", SrcIP: "10.0.0.2"}}
	snap, err := runtimeOwnerRGExportSnapshot(deltas, ProcessStatus{Enabled: true}, 0, errors.New("apply helper status: boom"))
	requireNoDeltasOnError9699(t, "runtimeOwnerRGExportSnapshot", len(snap.Deltas), err)
	ok, err := runtimeOwnerRGExportSnapshot(deltas, ProcessStatus{Enabled: true}, 0, nil)
	if err != nil || len(ok.Deltas) != len(deltas) {
		t.Fatalf("control: a successful export must carry all %d deltas (got %d, err=%v)", len(deltas), len(ok.Deltas), err)
	}
}

// TestRuntimeOwnerRGExportPassthroughUsesTheSnapshotRule9699 binds the wiring:
// the passthrough must route its result through runtimeOwnerRGExportSnapshot.
func TestRuntimeOwnerRGExportPassthroughUsesTheSnapshotRule9699(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "runtime_delta.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "ExportOwnerRGSessions" || fd.Recv == nil {
			return true
		}
		ast.Inspect(fd, func(m ast.Node) bool {
			if call, ok := m.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "runtimeOwnerRGExportSnapshot" {
					found = true
				}
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatal("runtimeSessionDeltaSource.ExportOwnerRGSessions must build its result with runtimeOwnerRGExportSnapshot")
	}
}
