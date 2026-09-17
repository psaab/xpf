package nfqueue

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestNfqueueDivertHoldsAndReleases9506 is the #9506 Phase-0 contract cell.
//
// Route-based IPsec plaintext surfaces on an xfrmi that is excluded from
// AF_XDP adjudication in both planes while the armed forward hook stays
// open, so decrypted ingress is kernel-forwarded with no zone policy
// (#9506). The r4 capture plan (research/9506-xfrm-capture) split its
// reviewers (GLM PLAN-READY vs Codex NEEDS-MAJOR) and the owner directed
// a Phase-0 measurement PR: an NFQUEUE divert prototype harness settling
// per-shape stage rates, memory accounting, teardown-from-source behavior
// and fragment head-of-line cost. Both r4 reviewers retain NFQUEUE as the
// research transport, so this cell pins the Phase-0 deliverable: a Go
// NFQNL speaker that binds a queue, receives held packets, and disposes
// each by verdict.
//
// RED on base: package nfqueue does not exist, so this file does not
// compile (undefined: Open). GREEN after Phase 0: the speaker holds a
// diverted packet in an isolated netns, ACCEPT releases it, DROP
// swallows it.
//
// Isolation: the body needs NETLINK_NETFILTER + nftables in its own
// network namespace. Without XPF_NFQUEUE_IN_NETNS the test re-execs
// itself under `unshare -Urn` (user + network namespace, no root) and
// runs the body there. Set XPF_NFQUEUE_IN_NETNS=1 to run the body
// directly when already isolated (re-exec child, cluster/CI runners).
func TestNfqueueDivertHoldsAndReleases9506(t *testing.T) {
	if os.Getenv("XPF_NFQUEUE_IN_NETNS") == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		cmd := exec.Command("unshare", "-Urn", self,
			"-test.run", "^TestNfqueueDivertHoldsAndReleases9506$",
			"-test.v",
		)
		cmd.Env = append(os.Environ(), "XPF_NFQUEUE_IN_NETNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("re-exec output:\n%s", out)
		if err != nil {
			t.Fatalf("netns re-exec failed: %v", err)
		}
		return
	}

	q, err := Open(60)
	if err != nil {
		t.Fatalf("Open(queue 60) in netns: %v", err)
	}
	defer q.Close()

	// Divert RFC1918 UDP across the hold so the speaker sees it.
	release, err := divertTestTraffic(t, q.ID())
	if err != nil {
		t.Fatalf("divertTestTraffic: %v", err)
	}
	defer release()

	deadline := time.Now().Add(10 * time.Second)
	if err := sendTestDatagram(deadline); err != nil {
		t.Fatalf("sendTestDatagram: %v", err)
	}
	pkt, err := q.Recv(deadline)
	if err != nil {
		t.Fatalf("Recv held packet: %v", err)
	}
	if len(pkt.Payload()) == 0 {
		t.Fatalf("held packet has empty payload")
	}
	if err := pkt.Verdict(VerdictAccept); err != nil {
		t.Fatalf("Verdict(ACCEPT): %v", err)
	}
	if err := awaitTestDatagram(deadline); err != nil {
		t.Fatalf("ACCEPTed datagram did not arrive: %v", err)
	}

	if err := sendTestDatagram(deadline); err != nil {
		t.Fatalf("sendTestDatagram (drop half): %v", err)
	}
	pkt, err = q.Recv(deadline)
	if err != nil {
		t.Fatalf("Recv held packet (drop half): %v", err)
	}
	if err := pkt.Verdict(VerdictDrop); err != nil {
		t.Fatalf("Verdict(DROP): %v", err)
	}
	if err := assertNoTestDatagram(500 * time.Millisecond); err != nil {
		t.Fatalf("DROPped datagram arrived anyway: %v", err)
	}
}
