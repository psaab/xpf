package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrepareActivationPathIsRetired13228 guards #13228 (D4-10): the
// syncMsgPrepareActivation wire path is orphaned. SendPrepareActivation has
// no production callers, OnPrepareActivation is never assigned, and yet
// handleMessage exposed a live case that only logged and invoked the
// always-nil callback -- a misleading pre-activation warm-up surface and an
// unwired log-amplification vector in the receive loop.
//
// The fix deletes the sender, the callback field, and the receive case, and
// marks the wire number retired so it is never reused. A retired frame then
// falls through to the default receive case (ignored), like any unknown
// message type from a mixed-base peer.
//
// RED on master: SendPrepareActivation / OnPrepareActivation / the case are
// present and the constant carries no retired marking.
func TestPrepareActivationPathIsRetired13228(t *testing.T) {
	t.Parallel()

	files := []string{"sync.go", "sync_failover.go", "sync_conn_read.go"}
	var all strings.Builder
	for _, name := range files {
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		all.Write(src)
		all.WriteByte('\n')
	}
	flat := strings.Join(strings.Fields(all.String()), " ")

	if strings.Contains(flat, "SendPrepareActivation") {
		t.Errorf("SendPrepareActivation must be deleted: it has zero production callers (#13228 D4-10)")
	}
	if strings.Contains(flat, "OnPrepareActivation") {
		t.Errorf("OnPrepareActivation must be deleted: it is never assigned anywhere (#13228 D4-10)")
	}

	// The wire value 19 must stay reserved, explicitly marked retired, so a
	// future message type never reuses it and a mixed-base peer's stale
	// prepare-activation frame is ignored by the default case.
	foundRetired := false
	for _, line := range strings.Split(all.String(), "\n") {
		if !strings.Contains(line, "syncMsgPrepareActivation") {
			continue
		}
		if strings.Contains(line, "=19") || strings.Contains(line, "= 19") {
			if strings.Contains(line, "retired") || strings.Contains(line, "reserved") {
				foundRetired = true
			}
		}
	}
	if !foundRetired {
		t.Errorf("syncMsgPrepareActivation = 19 must be retained and marked retired/reserved; " +
			"deleting the constant outright would free the wire number for reuse and break " +
			"mixed-base peers that still emit it (#13228 D4-10)")
	}
}
