package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// #7328 receiver/sender contract for the config-apply nack.
//
// The receiver tells the sender which generation did not take effect; the
// sender re-arms its push marker for that generation ONLY. These pin the parts
// that live in pkg/cluster: that a failed apply leaves the peer eligible (the
// #4151 property the nack exists to make reachable), and that the sender's
// acceptance is scoped to the generation it actually last sent.

// TestConfigApplyNackFiresOnlyOnFailure7328 pins both directions of the
// asymmetry at the SEND site: a failed apply nacks, a successful apply does
// not.
//
// FAIL-ON-REVERT: drop the sendConfigApplyNack call from configApplyLoop's
// failure branch and the failure leg reds. Move it above the `if err != nil`
// so it fires unconditionally and the success leg reds — that direction is the
// storm guard, since a nack on success would re-arm the sender's marker on
// every push and reintroduce exactly what #5863 prevents.
func TestConfigApplyNackFiresOnlyOnFailure7328(t *testing.T) {
	// Failure leg: the high-water stays pinned, so the SAME generation remains
	// admissible — which is precisely the eligibility the nack makes reachable.
	fail := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	fail.recordAppliedConfigGen(10)
	fail.OnConfigReceived = func(string) error { return errors.New("apply did not take effect") }

	const failedGen = 11
	if !fail.shouldApplyConfigGen(failedGen) {
		t.Fatal("setup: gen 11 must be admitted over applied 10")
	}
	fail.beginConfigApply(failedGen)
	if err := fail.OnConfigReceived("cfg-11"); err == nil {
		t.Fatal("setup: apply must fail")
	}
	fail.endConfigApply()

	if got := fail.lastAppliedConfigGen.Load(); got != 10 {
		t.Fatalf("M-2/#4151: a failed apply must leave the high-water pinned at 10; got %d", got)
	}
	if !fail.shouldApplyConfigGen(failedGen) {
		t.Fatal("the SAME generation must stay eligible for the authority's re-push (M-2/#4151) — " +
			"that eligibility is what the #7328 nack exists to make reachable")
	}

	// Success leg: the high-water advances, so a re-push of that generation is
	// correctly refused as stale and no re-arm is warranted.
	ok := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	ok.recordAppliedConfigGen(10)
	ok.beginConfigApply(failedGen)
	ok.recordAppliedConfigGen(failedGen)
	ok.endConfigApply()
	if got := ok.lastAppliedConfigGen.Load(); got != failedGen {
		t.Fatalf("a successful apply must advance the high-water to 11; got %d", got)
	}
	if ok.shouldApplyConfigGen(failedGen) {
		t.Fatal("after a SUCCESSFUL apply the same generation must be refused as stale — " +
			"there is nothing to re-push and nothing to re-arm")
	}
}

// TestConfigApplyNackAcceptedOnlyForLastSentGen7328 pins the sender-side scope
// guard: only a nack naming the generation this node most recently PUT ON THE
// WIRE may re-arm the marker.
//
// A nack for an older generation is a straggler for a push already superseded
// by a newer one. Acting on it would re-push a config the peer may already have
// applied, which is a spurious push on the shared control path.
//
// FAIL-ON-REVERT: delete the generation comparison against
// `configApplyDebtSnapshot16756().generation` in the syncMsgConfigApplyNack
// arm and the stale-nack leg reds. Drop the `recordLastSentConfigGen` call
// from QueueConfig and the matching leg reds, because the recorded generation
// stays 0.
func TestConfigApplyNackAcceptedOnlyForLastSentGen7328(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})

	var fired []uint64
	s.OnPeerConfigApplyFailed = func(gen uint64) { fired = append(fired, gen) }

	// Model QueueConfig having put generation 42 on the wire.
	s.recordLastSentConfigGen(42)

	nack := func(gen uint64) []byte {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], gen)
		return b[:]
	}

	// A straggler for a superseded push must be ignored.
	s.handleMessage(nil, syncMsgConfigApplyNack, nack(41))
	if len(fired) != 0 {
		t.Fatalf("a nack for a SUPERSEDED generation must not re-arm the marker; fired=%v", fired)
	}
	if got := s.stats.ConfigApplyNacksReceived.Load(); got != 0 {
		t.Fatalf("a stale nack must not be counted; got %d", got)
	}

	// A short payload must be ignored rather than read as generation 0, which
	// is a valid-looking "legacy/unconditional" value.
	s.handleMessage(nil, syncMsgConfigApplyNack, []byte{1, 2, 3})
	if len(fired) != 0 {
		t.Fatalf("a short nack payload must be ignored, not decoded; fired=%v", fired)
	}

	// The generation actually sent re-arms exactly once.
	s.handleMessage(nil, syncMsgConfigApplyNack, nack(42))
	if len(fired) != 1 || fired[0] != 42 {
		t.Fatalf("a nack for the last-sent generation must re-arm the marker once with that "+
			"generation; fired=%v", fired)
	}
	if got := s.stats.ConfigApplyNacksReceived.Load(); got != 1 {
		t.Fatalf("an accepted nack must be counted; got %d", got)
	}
}

// TestConfigApplyLoopSendsNackOnFailure7328 binds the production SEND WIRING,
// not the function it calls.
//
// The two tests above pin the state transitions and the sender-side scope
// guard, but neither would notice if configApplyLoop simply stopped calling
// sendConfigApplyNack — nothing else in the tree calls it, so the whole
// mechanism would go dark with every other test still green. This drives the
// real loop over a real connection and reads the frame off the wire.
//
// FAIL-ON-REVERT: delete the `s.sendConfigApplyNack(item.gen)` line from
// configApplyLoop's failure branch and this reds on the read deadline. Move it
// out of the `if err != nil` block and the success leg reds — that is the
// storm direction.
func TestConfigApplyLoopSendsNackOnFailure7328(t *testing.T) {
	readNack := func(t *testing.T, applyErr error, gen uint64) (uint64, bool) {
		t.Helper()
		s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()

		s.mu.Lock()
		s.conn0 = local
		s.stats.Connected.Store(true)
		s.mu.Unlock()

		s.OnConfigReceived = func(string) error { return applyErr }

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.configApplyLoop(ctx)

		type frame struct {
			typ uint8
			gen uint64
			ok  bool
		}
		got := make(chan frame, 1)
		go func() {
			hdr := make([]byte, 12)
			if _, err := io.ReadFull(peer, hdr); err != nil {
				got <- frame{}
				return
			}
			length := binary.LittleEndian.Uint32(hdr[8:12])
			body := make([]byte, length)
			if length > 0 {
				if _, err := io.ReadFull(peer, body); err != nil {
					got <- frame{}
					return
				}
			}
			f := frame{typ: hdr[4], ok: true}
			if len(body) >= 8 {
				f.gen = binary.LittleEndian.Uint64(body[:8])
			}
			got <- f
		}()

		s.configApplyCh <- configApplyItem{gen: gen, text: "cfg"}

		select {
		case f := <-got:
			if !f.ok {
				return 0, false
			}
			if f.typ != syncMsgConfigApplyNack {
				t.Fatalf("expected a config-apply nack frame, got message type %d", f.typ)
			}
			return f.gen, true
		case <-time.After(2 * time.Second):
			return 0, false
		}
	}

	// Failure: the loop must tell the sender which generation did not apply.
	if gen, ok := readNack(t, errors.New("apply did not take effect"), 77); !ok || gen != 77 {
		t.Fatalf("configApplyLoop must send a config-apply nack naming the failed generation "+
			"(#7328) — without it the sender's #5863 marker suppresses every re-push of it; "+
			"got gen=%d delivered=%v", gen, ok)
	}

	// Success: no nack, so nothing re-arms the sender's marker.
	if gen, ok := readNack(t, nil, 78); ok {
		t.Fatalf("a SUCCESSFUL apply must send no nack — a nack here would re-arm the sender's "+
			"marker on every push and reintroduce the #5863 push storm; got gen=%d", gen)
	}
}
