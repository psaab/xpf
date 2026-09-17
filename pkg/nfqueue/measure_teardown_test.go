package nfqueue

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestMeasureTeardown9506 is M3 from the Phase-0 plan. It deliberately removes
// the diversion source before sending a distinct follow-up, then attempts to
// verdict and observe the already-held packet with its originating UDP socket
// kept open. The controlled result is a passing negative mechanism pin:
// source release makes the held packet unobservable even though the verdict
// submission succeeds. This is not a harness timeout/addr/netns artifact:
// verdict-before-release delivers, and the post-release follow-up delivers.
// Admission cutoff/atomic replacement and SA/tunnel-source teardown remain
// mechanism-phase work.
func TestMeasureTeardown9506(t *testing.T) {
	requireNetNS(t)
	q1, err := Open(63)
	if err != nil {
		t.Fatalf("M3 Open q1: %v", err)
	}
	defer q1.Close()
	q2, err := Open(64)
	if err != nil {
		_ = q1.Close()
		t.Fatalf("M3 Open q2: %v", err)
	}
	defer q2.Close()

	release1, err := divertTestTraffic(t, q1.ID())
	if err != nil {
		_ = q1.Close()
		_ = q2.Close()
		t.Fatalf("M3 divert q1: %v", err)
	}
	defer closeTestReceiver()
	defer release1()
	sender, err := openTestSender()
	if err != nil {
		t.Fatalf("M3 sender: %v", err)
	}
	defer sender.Close()
	deadline := time.Now().Add(10 * time.Second)
	heldPayload := []byte("9506-held-generation")
	if err := sendTestPayloadConn(sender, heldPayload, deadline); err != nil {
		t.Fatalf("M3 first send: %v", err)
	}
	held, err := q1.Recv(deadline)
	if err != nil {
		t.Fatalf("M3 q1 held receive: %v", err)
	}

	release1()
	followupPayload := []byte("9506-followup-generation")
	if err := sendTestPayloadConn(sender, followupPayload, deadline); err != nil {
		t.Fatalf("M3 post-release send: %v", err)
	}
	if err := awaitTestDatagramPayload(deadline, string(followupPayload)); err != nil {
		t.Fatalf("M3 post-release queue-free delivery: %v", err)
	}
	if err := held.Verdict(VerdictAccept); err != nil {
		t.Fatalf("M3 held verdict after rule release: %v", err)
	}
	stats := q1.Stats()
	if stats.VerdictSuccessful != 1 || stats.VerdictUncertain != 0 {
		t.Fatalf("M3 held verdict stats=%+v, want one successful and zero uncertain submissions", stats)
	}
	heldDeadline := time.Now().Add(1 * time.Second)
	err = awaitTestDatagramPayload(heldDeadline, string(heldPayload))
	if err == nil {
		t.Fatalf("M3 mechanism pin changed: held packet became observable after source release")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("M3 held packet after source release = %v, want the measured UDP timeout", err)
	}
	t.Logf("M3 mechanism pin: source release + successful verdict left held payload unobservable (%v)", err)
	if err := q1.Close(); err != nil {
		t.Fatalf("M3 q1 close: %v", err)
	}
	if err := q1.Close(); err != nil {
		t.Fatalf("M3 q1 second close: %v", err)
	}
	closeTestReceiver()

	// q2 was live while q1 closed. Install a new source rule and prove it
	// still receives, while closing q2 makes the held packet unverdictable.
	release2, err := divertTestTraffic(t, q2.ID())
	if err != nil {
		t.Fatalf("M3 divert q2 after q1 close: %v", err)
	}
	defer closeTestReceiver()
	defer release2()
	q2Payload := []byte("9506-q2-held")
	q2Deadline := time.Now().Add(10 * time.Second)
	if err := sendTestPayloadConn(sender, q2Payload, q2Deadline); err != nil {
		t.Fatalf("M3 q2 send: %v", err)
	}
	held2, err := q2.Recv(q2Deadline)
	if err != nil {
		t.Fatalf("M3 q2 held receive: %v", err)
	}
	if err := q2.Close(); err != nil {
		t.Fatalf("M3 q2 close with held packet: %v", err)
	}
	if err := held2.Verdict(VerdictAccept); !errors.Is(err, ErrClosed) {
		t.Fatalf("M3 verdict after q2 close = %v, want ErrClosed", err)
	}
	if err := q2.Close(); err != nil {
		t.Fatalf("M3 q2 second close: %v", err)
	}
	closeTestReceiver()
}
