package clusterfailover_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover"
)

// #18559: only the untargeted form of a DATA RG, run on its owner with a live
// peer, becomes the targeted transfer to the other chassis node. The peer's
// cached role is not an input (a stale view would resign the sole owner).
func TestUntargetedPeerTransfer18559(t *testing.T) {
	for _, tc := range []struct {
		name         string
		op           clusterfailover.Op
		local        int
		primary      bool
		peerAlive    bool
		want         clusterfailover.Op
		wantTransfer bool
	}{
		{"owner node0 RG1", clusterfailover.RGFailover(1), 0, true, true, clusterfailover.TargetedRGFailover(1, 1), true},
		{"owner node1 RG2", clusterfailover.RGFailover(2), 1, true, true, clusterfailover.TargetedRGFailover(2, 0), true},
		{"RG0 keeps the resign", clusterfailover.RGFailover(0), 0, true, true, clusterfailover.Op{}, false},
		{"non-owner keeps the resign", clusterfailover.RGFailover(1), 0, false, true, clusterfailover.Op{}, false},
		{"dead peer keeps the resign", clusterfailover.RGFailover(1), 0, true, false, clusterfailover.Op{}, false},
		{"unsupported local node", clusterfailover.RGFailover(1), 2, true, true, clusterfailover.Op{}, false},
		{"targeted form untouched", clusterfailover.TargetedRGFailover(1, 1), 0, true, true, clusterfailover.Op{}, false},
		{"data form untouched", clusterfailover.DataFailover(1), 0, true, true, clusterfailover.Op{}, false},
		{"reset untouched", clusterfailover.ResetFailover(1), 0, true, true, clusterfailover.Op{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := clusterfailover.UntargetedPeerTransfer(tc.op, tc.local, tc.primary, tc.peerAlive)
			if ok != tc.wantTransfer || got != tc.want {
				t.Fatalf("UntargetedPeerTransfer = (%+v, %v), want (%+v, %v)", got, ok, tc.want, tc.wantTransfer)
			}
		})
	}
}

// The local-resign reply is the pre-#18559 text without a note and carries the
// note otherwise, so the fallback and the dual-active resign are visible.
func TestLocalResignMessage18559(t *testing.T) {
	if got := clusterfailover.LocalResignMessage(2, ""); got != "Manual failover triggered for redundancy group 2" {
		t.Fatalf("plain text changed: %q", got)
	}
	if got := clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable); got !=
		"Manual failover triggered for redundancy group 1 (peer unreachable; resigned locally, break-before-make)" {
		t.Fatalf("fallback text = %q", got)
	}
}

// The refusal names the peer's group as the peer's, keeps the peer's reasons,
// and ends with the next step for its class: readiness (retry when ready;
// the in-service-upgrade drain, qualified), auth (clocks / keys, NTP), or the
// fabric path.
func TestUntargetedTransferRefusal18559(t *testing.T) {
	notReady := "local redundancy group 1 not ready for explicit failover ready=false reasons=[sync]"
	got := clusterfailover.UntargetedTransferRefusal(1, 1,
		clusterfailover.ClassifyRefusal("FailedPrecondition", notReady), notReady)
	for _, want := range []string{"the peer's redundancy group 1 not ready", "reasons=[sync]", "node 1",
		"no local resign", "Next: on node 1", "in-service-upgrade", "RG0", "safe only once node 1 shows Takeover ready"} {
		if !strings.Contains(got, want) {
			t.Errorf("readiness refusal %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "local redundancy group") || strings.Contains(got, "regardless") {
		t.Errorf("readiness refusal %q still says \"local redundancy group\" or advertises an unconditional drain", got)
	}
	auth := clusterfailover.UntargetedTransferRefusal(1, 1,
		clusterfailover.ClassifyRefusal("Unauthenticated", "fabric RPC authentication failed: invalid auth token"),
		"fabric RPC authentication failed: invalid auth token")
	for _, want := range []string{"chronyc tracking", "routing-instance mgmt", "#18585"} {
		if !strings.Contains(auth, want) {
			t.Errorf("auth refusal %q lacks %q", auth, want)
		}
	}
	if strings.Contains(auth, "in-service-upgrade") || strings.Contains(auth, "Takeover ready") {
		t.Errorf("auth refusal %q points at readiness or the drain", auth)
	}
	tr := clusterfailover.UntargetedTransferRefusal(1, 1,
		clusterfailover.ClassifyRefusal("Unavailable", "transport is closing"), "transport is closing")
	if !strings.Contains(tr, "fabric path to node 1") || strings.Contains(tr, "in-service-upgrade") {
		t.Errorf("transport refusal %q", tr)
	}
	busy := "failover already in progress for redundancy group 1, please wait"
	ip := clusterfailover.UntargetedTransferRefusal(1, 1, clusterfailover.ClassifyRefusal("Unavailable", busy), busy)
	if !strings.Contains(ip, "already running on node 1") || !strings.Contains(ip, "Wait for it to finish") ||
		strings.Contains(ip, "fabric path") || strings.Contains(ip, "in-service-upgrade") {
		t.Errorf("in-progress refusal %q must say wait, not check the fabric or drain", ip)
	}
	lost := "redundancy group 1 lost takeover readiness before transfer commit ready=false ready_since=<zero> reasons=[x]"
	lr := clusterfailover.UntargetedTransferRefusal(1, 1, clusterfailover.ClassifyRefusal("FailedPrecondition", lost), lost)
	if !strings.Contains(lr, "Takeover ready") || strings.Contains(lr, "fabric path") {
		t.Errorf("lost-readiness refusal %q must give the readiness step", lr)
	}
}

// ClassifyRefusal keys on the gRPC code first, then the readiness texts.
func TestClassifyRefusal18559(t *testing.T) {
	for _, tc := range []struct {
		code, msg string
		want      clusterfailover.RefusalClass
	}{
		{"Unauthenticated", "anything", clusterfailover.RefusalAuth},
		{"PermissionDenied", "anything", clusterfailover.RefusalAuth},
		{"Unavailable", "peer fabric address x rejected the liveness probe: fabric RPC authentication failed", clusterfailover.RefusalAuth},
		{"FailedPrecondition", "local redundancy group 2 not ready for explicit failover ready=false", clusterfailover.RefusalReadiness},
		{"FailedPrecondition", "local redundancy group 2 not transfer-ready for explicit failover reasons=[x]", clusterfailover.RefusalReadiness},
		{"FailedPrecondition", "redundancy group 1 lost takeover readiness before transfer commit ready=false ready_since=<zero> reasons=[x]", clusterfailover.RefusalReadiness},
		{"Unavailable", "failover already in progress for redundancy group 1, please wait", clusterfailover.RefusalInProgress},
		{"FailedPrecondition", "failover commit for redundancy group 1 failed", clusterfailover.RefusalTransport},
		{"Unavailable", "transport is closing", clusterfailover.RefusalTransport},
	} {
		if got := clusterfailover.ClassifyRefusal(tc.code, tc.msg); got != tc.want {
			t.Errorf("ClassifyRefusal(%q, %q) = %v, want %v", tc.code, tc.msg, got, tc.want)
		}
	}
}

// A superseded transfer is reported with the peer's reply and no resign.
func TestUntargetedSupersededMessage18559(t *testing.T) {
	got := clusterfailover.UntargetedSupersededMessage(1, 1, "Manual failover completed for redundancy group 1 (transfer committed)")
	for _, want := range []string{"ownership of redundancy group 1 changed during the request",
		"a newer move or an automatic election", "primary again at a newer ownership epoch",
		"did not move", "no local resign", "node 1 had replied"} {
		if !strings.Contains(got, want) {
			t.Errorf("superseded text %q lacks %q", got, want)
		}
	}
	// The cause is unknowable here: it must not be pinned on an operator.
	if strings.Contains(got, "operator") || strings.Contains(got, "newer move completed") {
		t.Errorf("superseded text %q asserts a cause the code cannot know", got)
	}
	// The ownership change leads; the quoted peer reply comes after it.
	if strings.Index(got, "changed during the request") > strings.Index(got, "(transfer committed)") {
		t.Errorf("superseded text %q quotes the peer's reply before saying ownership changed", got)
	}
}

func TestUntargetedNoLongerPrimaryMessage18559(t *testing.T) {
	got := clusterfailover.UntargetedNoLongerPrimaryMessage(1, "secondary", 1)
	for _, want := range []string{"Redundancy group 1 is no longer primary on this node (now secondary)",
		"node 1 reports it primary", "Nothing to resign"} {
		if !strings.Contains(got, want) {
			t.Errorf("no-longer-primary text %q lacks %q", got, want)
		}
	}
	if got := clusterfailover.UntargetedNoLongerPrimaryMessage(2, "secondary", -1); !strings.Contains(got, "no node reports it primary yet") {
		t.Errorf("no-owner text %q", got)
	}
}

// The soak (test/incus/rg_move_soak.py) recognises the local-resign notes by
// their exact text; a wording change on either side must fail here, not drift
// into a dual-active or fallback reply scored as "other".
func TestSoakReplyNotesMatchGo18559(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "test", "incus", "rg_move_soak.py"))
	if err != nil {
		t.Fatalf("read the soak: %v", err)
	}
	for _, note := range []string{clusterfailover.ResignNoteUnreachable, clusterfailover.ResignNoteDualActive} {
		if !strings.Contains(string(src), note) {
			t.Errorf("rg_move_soak.py's fallback pattern does not carry the Go note %q", note)
		}
	}
	if got := clusterfailover.LocalResignMessage(7, clusterfailover.ResignNoteDualActive); !strings.HasPrefix(got, "Manual failover triggered for redundancy group 7 (") {
		t.Errorf("LocalResignMessage %q no longer has the prefix the soak and H1 key on", got)
	}
	// The OK "no longer primary" reply is a fallback too (the transfer did
	// not run): the soak classes it CLI_FALLBACK and H1 counts it in
	// planned_reply_fallback. Both key on these fixed fragments of the Go
	// text, so a reword on either side fails here.
	got := clusterfailover.UntargetedNoLongerPrimaryMessage(7, "secondary", 1)
	if !strings.HasPrefix(got, "Redundancy group 7 is no longer primary on this node (now secondary); ") ||
		!strings.Contains(got, "Nothing to resign") {
		t.Errorf("UntargetedNoLongerPrimaryMessage %q no longer has the fragments the soak and H1 key on", got)
	}
	for _, frag := range []string{"is no longer primary on this node", "Nothing to resign"} {
		if !strings.Contains(string(src), frag) {
			t.Errorf("rg_move_soak.py's fallback pattern does not carry %q", frag)
		}
	}
	h1, err := os.ReadFile(filepath.Join("..", "..", "test", "incus", "test-failover.sh"))
	if err != nil {
		t.Fatalf("read H1: %v", err)
	}
	if !strings.Contains(string(h1), `*"Redundancy group $rg is no longer primary on this node"*`) {
		t.Error("test-failover.sh's ha_planned_reply_note does not count the no-longer-primary reply as a fallback")
	}
}
