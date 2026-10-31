package daemon

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #9751: the VRF-rebind apply step called d.cluster.RestartHeartbeat() and
// discarded the result, so a restart that left the heartbeat stopped was
// invisible in the commit result.

type fakeRestarter9751 struct {
	restarted, owed bool
	calls           int
}

func (f *fakeRestarter9751) RestartHeartbeat() bool     { f.calls++; return f.restarted }
func (f *fakeRestarter9751) HeartbeatRestartOwed() bool { return f.owed }

func TestHeartbeatRestartAfterRebindReportsOnlyAFailedRestart_9751(t *testing.T) {
	for _, tc := range []struct {
		name            string
		restarted, owed bool
		wantErr         bool
	}{
		{"restart succeeded", true, false, false},
		{"never running: nothing to restart", false, false, false},
		{"restart failed and left the heartbeat stopped", false, true, true},
	} {
		f := &fakeRestarter9751{restarted: tc.restarted, owed: tc.owed}
		err := restartHeartbeatAfterRebind(f)
		if f.calls != 1 {
			t.Errorf("%s: RestartHeartbeat called %d times, want 1", tc.name, f.calls)
		}
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, want error=%v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr && !errors.Is(err, errHeartbeatRestartFailed) {
			t.Errorf("%s: err = %v, want errHeartbeatRestartFailed", tc.name, err)
		}
	}
}

// The helper reports nothing unless the apply step uses the epoch-fenced
// wrapper and keeps its error. Pin that call on the apply path and reject a
// bare, discarded RestartHeartbeat() call.
func TestVRFRebindApplyJoinsTheHeartbeatRestartError_9751(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon_apply_dataplane.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_dataplane.go: %v", err)
	}
	var joined, discarded int
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.IfStmt:
			init, ok := s.Init.(*ast.AssignStmt)
			if !ok || len(init.Rhs) != 1 {
				return true
			}
			call, ok := init.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			// #18597: the apply step now goes through the move gate, which
			// returns the epoch-fenced wrapper's error unchanged
			// (heartbeat_rebind_gate_18597.go).
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "restartHeartbeatIfControlLinkMoved" {
				return true
			}
			for _, st := range s.Body.List {
				as, ok := st.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 {
					continue
				}
				if l, ok := as.Lhs[0].(*ast.SelectorExpr); ok && l.Sel.Name == "Networkd" {
					joined++
				}
			}
		case *ast.ExprStmt:
			if call, ok := s.X.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RestartHeartbeat" {
					discarded++
				}
			}
		}
		return true
	})
	if joined != 1 {
		t.Errorf("found %d epoch-fenced heartbeat restart calls whose error is joined into networkdErr, want 1", joined)
	}
	if discarded != 0 {
		t.Errorf("found %d RestartHeartbeat() calls whose result is discarded, want 0", discarded)
	}
}
