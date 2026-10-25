// #16168: census for the handleMessage switch after the verbatim
// extraction of its case bodies into per-family handle* methods.
//
// The handled set is the 43 case clauses / 45 case labels in
// handleMessage (sync_conn_read.go) — NOT "every syncMsg* 1..49":
// AuthHello/AuthProof/AuthConfirm are handled pre-install, gaps and
// retired numbers (19) exist, and 27/28/44 are phase-shared. A census
// over the declaration space would red on day one; this one pins the
// dispatch space, so "added a post-install constant, forgot the case"
// (or dropped a label from a multi-label arm) goes red instead.
//
// The scan parses the file with go/parser and walks the switch with
// go/ast, so line comments AND /* */ block comments quoting a case
// cannot satisfy (or inflate) the gate, and cases in other functions
// cannot leak in. Floors on both the clause and label counts keep a
// broken scan — one that matches nothing — from reporting a
// complete census.

package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// wantHandleMessageLabels is the exact 45-label handled set, sorted.
// Two clauses carry two labels each (PersistentNatLeaseGeneration /
// PersistentNatLeaseDeterministic and DHCPLeaseV4Chunk /
// DHCPLeaseV6Chunk), so the label count (45) exceeds the clause
// count (43); pinning labels, not clauses, catches a dropped label.
var wantHandleMessageLabels = []string{
	"syncMsgAuthUpgradeConfirm",
	"syncMsgAuthUpgradeHello",
	"syncMsgAuthUpgradeProof",
	"syncMsgAuthUpgradeRequest",
	"syncMsgBarrier",
	"syncMsgBarrierAck",
	"syncMsgBulkAck",
	"syncMsgBulkEnd",
	"syncMsgBulkRequest",
	"syncMsgBulkStart",
	"syncMsgClockSync",
	"syncMsgConfig",
	"syncMsgConfigApplyAck",
	"syncMsgConfigApplyNack",
	"syncMsgConfigEncrypted",
	"syncMsgConfigKeyExchange",
	"syncMsgDHCPLeaseV4",
	"syncMsgDHCPLeaseV4Chunk",
	"syncMsgDHCPLeaseV6",
	"syncMsgDHCPLeaseV6Chunk",
	"syncMsgDeleteV4",
	"syncMsgDeleteV6",
	"syncMsgFailover",
	"syncMsgFailoverAbort",
	"syncMsgFailoverAck",
	"syncMsgFailoverBatch",
	"syncMsgFailoverBatchAbort",
	"syncMsgFailoverBatchAck",
	"syncMsgFailoverBatchCommit",
	"syncMsgFailoverBatchCommitAck",
	"syncMsgFailoverCommit",
	"syncMsgFailoverCommitAck",
	"syncMsgFence",
	"syncMsgFenceAck",
	"syncMsgHeartbeat",
	"syncMsgHeartbeatAck",
	"syncMsgIPsecSA",
	"syncMsgIPsecSAChunk",
	"syncMsgPeerCapabilities",
	"syncMsgPersistentNatLease",
	"syncMsgPersistentNatLeaseDeterministic",
	"syncMsgPersistentNatLeaseDeterministicProvenance",
	"syncMsgPersistentNatLeaseGeneration",
	"syncMsgPersistentNatLeaseProvenance",
	"syncMsgPersistentNatLeaseScoped",
	"syncMsgSessionV4",
	"syncMsgSessionV6",
}

// scanHandleMessageLabels parses body and returns the case clause
// count, the sorted label set, and whether the switch has a default
// arm, all from the handleMessage switch only. Commented-out cases
// (// or /* */) never appear in the AST and so never count.
func scanHandleMessageLabels(t *testing.T, body string) (clauses int, labels []string, hasDefault bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sync_conn_read.go", body, 0)
	if err != nil {
		t.Fatalf("parse sync_conn_read.go: %v — the scan is broken", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "handleMessage" {
			fn = fd
			break
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatalf("handleMessage not found in sync_conn_read.go — the scan is broken")
	}
	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			if cc.List == nil {
				hasDefault = true
				continue
			}
			clauses++
			for _, expr := range cc.List {
				ident, ok := expr.(*ast.Ident)
				if !ok {
					t.Errorf("handleMessage case label is not an identifier: %T", expr)
					continue
				}
				if seen[ident.Name] {
					t.Errorf("duplicate case label %s in handleMessage", ident.Name)
				}
				seen[ident.Name] = true
				labels = append(labels, ident.Name)
			}
		}
		return false // only the outer dispatch switch is the census target
	})
	sort.Strings(labels)
	return clauses, labels, hasDefault
}

func TestHandleMessageCaseCensus16168(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("sync_conn_read.go")
	if err != nil {
		t.Fatalf("read sync_conn_read.go: %v", err)
	}
	clauses, got, hasDefault := scanHandleMessageLabels(t, string(body))

	// Floors: a scan that matched nothing would sweep zero clauses
	// and report a complete census — a check that fails to a value
	// indistinguishable from healthy.
	if clauses < 43 {
		t.Fatalf("the AST scan found only %d handleMessage case clauses, which cannot be "+
			"right — the scan is broken, and a broken scan reports a complete census", clauses)
	}
	if clauses != 43 {
		t.Errorf("handleMessage has %d case clauses, want exactly 43", clauses)
	}
	if len(got) < 45 {
		t.Fatalf("the AST scan found only %d handleMessage case labels, which cannot be "+
			"right — the scan is broken, and a broken scan reports a complete census", len(got))
	}
	if len(got) != len(wantHandleMessageLabels) {
		t.Errorf("handleMessage handles %d labels, want %d: got %v", len(got), len(wantHandleMessageLabels), got)
	}
	for i := 0; i < len(got) && i < len(wantHandleMessageLabels); i++ {
		if got[i] != wantHandleMessageLabels[i] {
			t.Errorf("handleMessage label[%d] = %s, want %s (full got: %v)", i, got[i], wantHandleMessageLabels[i], got)
			break
		}
	}

	// No default arm: unknown or retired types are ignored by design
	// (a peer that predates a message simply never gets a reaction).
	// The extraction must not introduce one.
	if hasDefault {
		t.Errorf("handleMessage gained a default arm; unknown sync types must stay ignored")
	}
}

// TestHandleMessageCaseCensus16168Mutations proves the census is not
// test-only-green: dropping a label, dropping a clause, commenting a
// case out, or a scan that finds nothing must all be detected.
func TestHandleMessageCaseCensus16168Mutations(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("sync_conn_read.go")
	if err != nil {
		t.Fatalf("read sync_conn_read.go: %v", err)
	}
	src := string(body)

	// Dropping one label from a two-label arm keeps 42 clauses but
	// must change the label set.
	mut := strings.Replace(src,
		"case syncMsgDHCPLeaseV4Chunk, syncMsgDHCPLeaseV6Chunk:",
		"case syncMsgDHCPLeaseV4Chunk:", 1)
	if mut == src {
		t.Fatalf("mutation setup failed: two-label DHCP chunk arm not found")
	}
	clauses, labels, _ := scanHandleMessageLabels(t, mut)
	if clauses != 43 || len(labels) != 44 {
		t.Errorf("label-drop mutation: got %d clauses / %d labels, want 43/44 — the census would not catch a dropped label", clauses, len(labels))
	}

	// Dropping a whole clause must change both counts.
	mut2 := strings.Replace(src, "case syncMsgBarrierAck:\n\t\treturn s.handleBarrierAck(conn, payload)\n", "", 1)
	if mut2 == src {
		t.Fatalf("mutation setup failed: BarrierAck arm not found")
	}
	clauses, labels, _ = scanHandleMessageLabels(t, mut2)
	if clauses != 42 || len(labels) != 44 {
		t.Errorf("clause-drop mutation: got %d clauses / %d labels, want 42/44 — the census would not catch a dropped case", clauses, len(labels))
	}

	// A case inside a /* */ block comment is not dispatch: it must
	// NOT count. (The line-regex scanner this replaces counted it,
	// because it stripped only // comments.)
	mut3 := strings.Replace(src,
		"case syncMsgBarrierAck:\n\t\treturn s.handleBarrierAck(conn, payload)",
		"/*\n\tcase syncMsgBarrierAck:\n\t\treturn s.handleBarrierAck(conn, payload)\n\t*/", 1)
	if mut3 == src {
		t.Fatalf("mutation setup failed: BarrierAck arm not found for block-comment mutation")
	}
	clauses, labels, _ = scanHandleMessageLabels(t, mut3)
	if clauses != 42 || len(labels) != 44 {
		t.Errorf("block-comment mutation: got %d clauses / %d labels, want 42/44 — a commented-out case was counted as active dispatch", clauses, len(labels))
	}

	// Likewise, an extra case quoted inside a /* */ comment must not
	// inflate the census.
	mut4 := strings.Replace(src,
		"case syncMsgBarrierAck:",
		"/* case syncMsgBarrier: */\n\tcase syncMsgBarrierAck:", 1)
	if mut4 == src {
		t.Fatalf("mutation setup failed: BarrierAck arm not found for quoted-case mutation")
	}
	clauses, labels, _ = scanHandleMessageLabels(t, mut4)
	if clauses != 43 || len(labels) != 45 {
		t.Errorf("quoted-case mutation: got %d clauses / %d labels, want 43/45 — a case inside a block comment was counted", clauses, len(labels))
	}

	// A scan over an empty switch must hit the floor path (zero
	// clauses), never a vacuous pass.
	clauses, labels, _ = scanHandleMessageLabels(t,
		"package cluster\n\nimport \"net\"\n\nfunc (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {\n\tswitch msgType {\n\t}\n}\n")
	if clauses != 0 || len(labels) != 0 {
		t.Errorf("empty-switch scan: got %d clauses / %d labels, want 0/0", clauses, len(labels))
	}
}
