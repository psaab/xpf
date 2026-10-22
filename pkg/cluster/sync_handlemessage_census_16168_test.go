// #16168: census for the handleMessage switch after the verbatim
// extraction of its case bodies into per-family handle* methods.
//
// The handled set is the 42 case clauses / 44 case labels in
// handleMessage (sync_conn_read.go) — NOT "every syncMsg* 1..48":
// AuthHello/AuthProof/AuthConfirm are handled pre-install, gaps and
// retired numbers (19) exist, and 27/28/44 are phase-shared. A census
// over the declaration space would red on day one; this one pins the
// dispatch space, so "added a post-install constant, forgot the case"
// (or dropped a label from a multi-label arm) goes red instead.
//
// The scan is SOURCE-based, mirroring TestLiveSyncMessageCensusIsComplete7163:
// comment lines are stripped first (a doc comment quoting a case must
// not satisfy the gate), and floors on both the clause and label counts
// keep a broken scan — one that matches nothing — from reporting a
// complete census.

package cluster

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// wantHandleMessageLabels is the exact 44-label handled set, sorted.
// Two clauses carry two labels each (PersistentNatLeaseGeneration /
// PersistentNatLeaseDeterministic and DHCPLeaseV4Chunk /
// DHCPLeaseV6Chunk), so the label count (44) exceeds the clause
// count (42); pinning labels, not clauses, catches a dropped label.
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
	"syncMsgPeerCapabilities",
	"syncMsgPersistentNatLease",
	"syncMsgPersistentNatLeaseDeterministic",
	"syncMsgPersistentNatLeaseGeneration",
	"syncMsgPersistentNatLeaseScoped",
	"syncMsgSessionV4",
	"syncMsgSessionV6",
}

var handleMessageCaseRe = regexp.MustCompile(`^\s*case\s+((?:syncMsg[A-Za-z0-9_]+)(?:\s*,\s*syncMsg[A-Za-z0-9_]+)*)\s*:\s*$`)

// scanHandleMessageLabels returns the case clause count and the sorted
// label set found in the handleMessage switch. It locates the switch
// by its function header so cases in other functions (or tests) in the
// same file cannot leak in, and it strips comments before matching.
func scanHandleMessageLabels(t *testing.T, body string) (clauses int, labels []string) {
	t.Helper()
	lines := strings.Split(body, "\n")
	start := -1
	for i, line := range lines {
		if strings.Contains(line, "func (s *SessionSync) handleMessage(") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("handleMessage not found in sync_conn_read.go — the scan is broken")
	}
	seen := map[string]bool{}
	for _, line := range lines[start:] {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if k := strings.Index(line, "//"); k >= 0 {
			line = line[:k]
		}
		if clauses > 0 && line == "}" {
			break // closing brace of handleMessage
		}
		m := handleMessageCaseRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		clauses++
		for _, lab := range strings.Split(m[1], ",") {
			lab = strings.TrimSpace(lab)
			if seen[lab] {
				t.Errorf("duplicate case label %s in handleMessage", lab)
			}
			seen[lab] = true
			labels = append(labels, lab)
		}
	}
	sort.Strings(labels)
	return clauses, labels
}

func TestHandleMessageCaseCensus16168(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("sync_conn_read.go")
	if err != nil {
		t.Fatalf("read sync_conn_read.go: %v", err)
	}
	clauses, got := scanHandleMessageLabels(t, string(body))

	// Floors: a regex that matched nothing would sweep zero clauses
	// and report a complete census — a check that fails to a value
	// indistinguishable from healthy.
	if clauses < 42 {
		t.Fatalf("the source scan found only %d handleMessage case clauses, which cannot be "+
			"right — the scan is broken, and a broken scan reports a complete census", clauses)
	}
	if clauses != 42 {
		t.Errorf("handleMessage has %d case clauses, want exactly 42", clauses)
	}
	if len(got) < 44 {
		t.Fatalf("the source scan found only %d handleMessage case labels, which cannot be "+
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
	// The extraction must not introduce one. Scoped to the
	// handleMessage switch itself — receiveLoop and
	// handleConfigPayload in the same file legitimately use default.
	{
		lines := strings.Split(string(body), "\n")
		inSwitch := false
		for _, line := range lines {
			if strings.Contains(line, "func (s *SessionSync) handleMessage(") {
				inSwitch = true
				continue
			}
			if !inSwitch {
				continue
			}
			if line == "}" {
				break
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.TrimSpace(line) == "default:" {
				t.Errorf("handleMessage gained a default arm; unknown sync types must stay ignored")
				break
			}
		}
		if !inSwitch {
			t.Fatalf("handleMessage not found while checking for a default arm")
		}
	}
}

// TestHandleMessageCaseCensus16168Mutations proves the census is not
// test-only-green: dropping a label, dropping a clause, or a scan
// that finds nothing must all be detected.
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
	clauses, labels := scanHandleMessageLabels(t, mut)
	if clauses != 42 || len(labels) != 43 {
		t.Errorf("label-drop mutation: got %d clauses / %d labels, want 42/43 — the census would not catch a dropped label", clauses, len(labels))
	}

	// Dropping a whole clause must change both counts.
	mut2 := strings.Replace(src, "case syncMsgBarrierAck:\n\t\ts.handleBarrierAck(conn, payload)\n", "", 1)
	if mut2 == src {
		t.Fatalf("mutation setup failed: BarrierAck arm not found")
	}
	clauses, labels = scanHandleMessageLabels(t, mut2)
	if clauses != 41 || len(labels) != 43 {
		t.Errorf("clause-drop mutation: got %d clauses / %d labels, want 41/43 — the census would not catch a dropped case", clauses, len(labels))
	}

	// A scan over empty input must hit the floor path (zero clauses),
	// never a vacuous pass. scanHandleMessageLabels Fatalfs on a
	// missing function header, so exercise the counters on a header
	// with no cases instead.
	clauses, labels = scanHandleMessageLabels(t,
		"func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {\n}\n")
	if clauses != 0 || len(labels) != 0 {
		t.Errorf("empty-switch scan: got %d clauses / %d labels, want 0/0", clauses, len(labels))
	}
}
