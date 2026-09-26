package cluster

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3931 — HA config-sync generation ordering guard tests.
//
// These exercise the config-sync wire codec (encodeConfigPayload /
// decodeConfigPayload), the receiver-side ordering guard (shouldApplyConfigGen
// admission + recordAppliedConfigGen apply-then-advance, M-2/#4151), and the
// single-consumer ordered apply loop (configApplyLoop). Every test is
// written so it FAILS against the pre-#3931 behavior, where a config was
// applied via a racing `go OnConfigReceived` with NO generation on the wire:
// a rapid commit pair (C1 then C2) could apply out of order and leave the
// standby on the older C1.

// --- wire codec round-trip -------------------------------------------------

func TestConfigPayloadRoundTrip(t *testing.T) {
	const text = "set system host-name node0\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n"
	payload := encodeConfigPayload(text, 42)
	gotText, gotGen := decodeConfigPayload(payload)
	if gotText != text {
		t.Fatalf("config text round-trip mismatch:\n got %q\nwant %q", gotText, text)
	}
	if gotGen != 42 {
		t.Fatalf("config gen round-trip mismatch: got %d want 42", gotGen)
	}
}

// A legacy sender emits the raw config text with no trailing framing; the new
// receiver must decode it with gen==0 (applied unconditionally).
func TestConfigPayloadLegacyNoMagic(t *testing.T) {
	const text = "set system host-name legacy\n"
	gotText, gotGen := decodeConfigPayload([]byte(text))
	if gotText != text {
		t.Fatalf("legacy config text mismatch: got %q want %q", gotText, text)
	}
	if gotGen != 0 {
		t.Fatalf("legacy config gen must be 0, got %d", gotGen)
	}
}

// Config text that happens to be short must not be misread as framed.
func TestConfigPayloadShortNotFramed(t *testing.T) {
	const text = "short"
	gotText, gotGen := decodeConfigPayload([]byte(text))
	if gotText != text || gotGen != 0 {
		t.Fatalf("short payload mis-decoded: got %q/%d", gotText, gotGen)
	}
}

// An empty config text still frames and decodes with its generation.
func TestConfigPayloadEmptyText(t *testing.T) {
	payload := encodeConfigPayload("", 7)
	gotText, gotGen := decodeConfigPayload(payload)
	if gotText != "" || gotGen != 7 {
		t.Fatalf("empty-text framing mis-decoded: got %q/%d", gotText, gotGen)
	}
}

func TestConfigPayloadAncestryRoundTrip(t *testing.T) {
	text := "set security policies from-zone trust to-zone untrust policy old\n"
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "old"},
		DestinationPath: []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "new"},
	}}
	payload := encodeConfigPayloadWithAncestry(text, 19, want)
	gotText, gotGen, got := decodeConfigPayloadWithAncestry(payload)
	if gotText != text || gotGen != 19 || !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestry payload round-trip mismatch: text=%q gen=%d ancestry=%#v", gotText, gotGen, got)
	}
}

func TestConfigPayloadMalformedAncestryFallsBackToGeneration(t *testing.T) {
	payload := encodeConfigPayload("set system host-name node0\n", 23)
	payload = append(payload, configAncestryMagic[:]...)
	payload = append(payload, 4, 0, 0, 0, '{')
	gotText, gotGen, got := decodeConfigPayloadWithAncestry(payload)
	if gotText == "" || gotGen != 23 || got != nil {
		t.Fatalf("malformed ancestry should be ignored without losing config framing: text=%q gen=%d ancestry=%#v", gotText, gotGen, got)
	}
}

// --- ordering guard --------------------------------------------------------

// The admission gate (shouldApplyConfigGen) is strictly monotonic against the
// last SUCCESSFULLY-applied generation (advanced only via recordAppliedConfigGen
// after a confirmed apply, M-2/#4151).
func TestShouldApplyConfigGenMonotonic(t *testing.T) {
	s := &SessionSync{}
	// First real config admits; the caller records it on successful apply.
	if !s.shouldApplyConfigGen(5) {
		t.Fatal("gen 5 should admit (first config)")
	}
	s.recordAppliedConfigGen(5)
	// A strictly-newer config admits.
	if !s.shouldApplyConfigGen(6) {
		t.Fatal("gen 6 should admit (newer than 5)")
	}
	s.recordAppliedConfigGen(6)
	// An older config (the reordered C1) is refused.
	if s.shouldApplyConfigGen(5) {
		t.Fatal("gen 5 must be refused after gen 6 applied (stale)")
	}
	// The same generation is refused (not strictly newer).
	if s.shouldApplyConfigGen(6) {
		t.Fatal("gen 6 must be refused after gen 6 applied (not strictly newer)")
	}
	if got := s.lastAppliedConfigGen.Load(); got != 6 {
		t.Fatalf("last-applied gen should be 6, got %d", got)
	}
}

// The gate does NOT advance the high-water mark on its own: admitting a
// generation must not record it. Only a confirmed apply (recordAppliedConfigGen)
// advances the mark — the M-2/#4151 apply-then-advance separation.
func TestShouldApplyConfigGenDoesNotAdvance(t *testing.T) {
	s := &SessionSync{}
	if !s.shouldApplyConfigGen(9) {
		t.Fatal("gen 9 should admit (first config)")
	}
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("the admission gate must NOT advance the high-water mark, got %d (want 0)", got)
	}
	// Admitting it again (no apply recorded yet) must still succeed — the same
	// generation stays eligible until an apply confirms it.
	if !s.shouldApplyConfigGen(9) {
		t.Fatal("gen 9 must stay admissible until a successful apply records it")
	}
	s.recordAppliedConfigGen(9)
	if got := s.lastAppliedConfigGen.Load(); got != 9 {
		t.Fatalf("recordAppliedConfigGen must advance the mark to 9, got %d", got)
	}
	if s.shouldApplyConfigGen(9) {
		t.Fatal("gen 9 must be refused once recorded (not strictly newer)")
	}
}

// gen==0 (legacy sender) is always admitted and never advances the high-water
// mark, so a subsequent real generation still orders correctly.
func TestShouldApplyConfigGenLegacyUnconditional(t *testing.T) {
	s := &SessionSync{}
	if !s.shouldApplyConfigGen(0) {
		t.Fatal("legacy gen 0 must always admit")
	}
	s.recordAppliedConfigGen(0)
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("gen 0 must not advance high-water mark, got %d", got)
	}
	if !s.shouldApplyConfigGen(3) {
		t.Fatal("real gen 3 should admit after a legacy gen 0")
	}
	s.recordAppliedConfigGen(3)
	if !s.shouldApplyConfigGen(0) {
		t.Fatal("legacy gen 0 must still admit after a real gen")
	}
	s.recordAppliedConfigGen(0)
	if got := s.lastAppliedConfigGen.Load(); got != 3 {
		t.Fatalf("high-water mark should remain 3, got %d", got)
	}
}

// After a peer bulk re-prime (resetRecvGen), the high-water mark resets so a
// rebooted primary — whose monotonic counter restarts LOWER — is accepted
// instead of refused as stale (#2198 F2 reasoning applied to config).
func TestResetRecvGenResetsConfigGen(t *testing.T) {
	s := &SessionSync{}
	s.recvGenV4 = nil
	s.recvGenV6 = nil
	if !s.shouldApplyConfigGen(100) {
		t.Fatal("gen 100 should admit")
	}
	s.recordAppliedConfigGen(100)
	s.resetRecvGen()
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("resetRecvGen must zero the config gen, got %d", got)
	}
	// A lower generation (rebooted peer) now applies.
	if !s.shouldApplyConfigGen(3) {
		t.Fatal("gen 3 should admit after reset (rebooted peer)")
	}
}

// --- end-to-end ordered apply (RED-on-revert) ------------------------------

// configRecorder captures the sequence of SUCCESSFULLY applied config texts
// under a mutex so the ordered-apply consumer can be observed deterministically.
//
// failN, if > 0, makes the next failN record() calls return an error WITHOUT
// recording the text — simulating an apply that failed before promoting the
// store (a compile/promote failure or a transient RG0-primary rejection). This
// exercises the M-2/#4151 apply-then-advance contract.
type configRecorder struct {
	mu       sync.Mutex
	applied  []string
	failN    int
	attempts int
}

func (r *configRecorder) record(text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	if r.failN > 0 {
		r.failN--
		return fmt.Errorf("simulated config apply failure for %q", text)
	}
	r.applied = append(r.applied, text)
	return nil
}

func (r *configRecorder) last() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return "", 0
	}
	return r.applied[len(r.applied)-1], len(r.applied)
}

// drainConfigApply waits for the ordered consumer to drain configApplyCh and
// finish the in-flight apply, so the recorder can be observed deterministically.
func drainConfigApply(t *testing.T, s *SessionSync) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.configApplyCh) == 0 {
			// Give the consumer a beat to finish the in-flight item.
			time.Sleep(5 * time.Millisecond)
			if len(s.configApplyCh) == 0 {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestConfigSyncOrderedApplyDropsReorderedOlder is the #3931 RED-on-revert
// test. It delivers C2 (newer) BEFORE C1 (older) — the reordered-apply case —
// and asserts the standby ends on C2 and drops the stale C1. Under the
// pre-#3931 racing/no-gen behavior both would apply and the final state could
// be C1 (diverged), so this fails on revert.
func TestConfigSyncOrderedApplyDropsReorderedOlder(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{}
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// Reordered delivery: C2 (gen 2) enqueued before C1 (gen 1).
	s.configApplyCh <- configApplyItem{gen: 2, text: "config-C2"}
	s.configApplyCh <- configApplyItem{gen: 1, text: "config-C1"}

	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-C2" {
		t.Fatalf("standby must end on the newest config C2, ended on %q (applied=%v)", last, rec.applied)
	}
	if count != 1 {
		t.Fatalf("only C2 should have applied; got %d applies: %v", count, rec.applied)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 1 {
		t.Fatalf("stale C1 must be counted as dropped, ConfigsStaleIgnored=%d", got)
	}
	if got := s.lastAppliedConfigGen.Load(); got != 2 {
		t.Fatalf("last-applied gen should be 2 (C2), got %d", got)
	}
}

// In-order delivery applies both configs and the standby ends on the newest.
func TestConfigSyncOrderedApplyInOrder(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{}
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.configApplyCh <- configApplyItem{gen: 1, text: "config-C1"}
	s.configApplyCh <- configApplyItem{gen: 2, text: "config-C2"}

	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-C2" {
		t.Fatalf("standby must end on C2, ended on %q", last)
	}
	if count != 2 {
		t.Fatalf("both configs should apply in order, got %d: %v", count, rec.applied)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 0 {
		t.Fatalf("no config should be dropped in-order, ConfigsStaleIgnored=%d", got)
	}
}

// A single config push applies normally (regression guard on the common path).
func TestConfigSyncSinglePushApplies(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{}
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.configApplyCh <- configApplyItem{gen: 9, text: "config-only"}
	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-only" || count != 1 {
		t.Fatalf("single push should apply once, got %q count=%d", last, count)
	}
}

// TestConfigSyncApplyFailureRetainsHighWater is the M-2 (#4151) RED-on-revert
// test. When the apply FAILS, the config high-water mark must NOT advance, so
// the primary's re-push of the SAME generation is re-admitted and re-attempted
// (the standby re-converges) instead of being silently dropped as stale.
//
// Under the pre-fix advance-before-apply order (admitConfigGen advanced the
// high-water BEFORE OnConfigReceived and ignored its result), the high-water
// jumped to the failed generation, the re-push was dropped as "not strictly
// newer," and the standby stayed stranded on the prior config — so this test
// fails on revert.
func TestConfigSyncApplyFailureRetainsHighWater(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{failN: 1} // fail the first apply, succeed after
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// (1) First delivery of gen 7 fails to apply.
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)

	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("apply failure must NOT advance the high-water mark, got %d (want 0)", got)
	}
	if got := s.stats.ConfigsApplyFailed.Load(); got != 1 {
		t.Fatalf("a failed apply must be counted in ConfigsApplyFailed, got %d", got)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 0 {
		t.Fatalf("a failed apply must NOT be counted as stale-dropped, got %d", got)
	}
	if _, count := rec.last(); count != 0 {
		t.Fatalf("no config should have been recorded after the failed apply, got %d", count)
	}

	// (2) Primary re-pushes the SAME generation 7; it must be re-admitted (not
	// dropped as stale) and now applies successfully — the standby re-converges.
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-C7" || count != 1 {
		t.Fatalf("re-push of gen 7 must re-apply after the earlier failure, got %q count=%d", last, count)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 0 {
		t.Fatalf("the re-push must NOT be dropped as stale, ConfigsStaleIgnored=%d", got)
	}
	if got := s.lastAppliedConfigGen.Load(); got != 7 {
		t.Fatalf("high-water must advance to 7 only AFTER the successful apply, got %d", got)
	}

	// (3) A THIRD push of gen 7, now AFTER a successful apply, is correctly
	// skipped as stale — proving the skip is legitimate only once the apply
	// actually succeeded (distinguishes it from the fail case in step 1).
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)
	if _, count := rec.last(); count != 1 {
		t.Fatalf("a same-gen push after a successful apply must be skipped, applies=%d", count)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 1 {
		t.Fatalf("the post-success same-gen push must be dropped as stale, ConfigsStaleIgnored=%d", got)
	}
}

// The QueueConfig sender + decodeConfigPayload receiver agree on the wire
// generation, and the drawn generations are strictly monotonic per push.
func TestNextConfigGenMonotonic(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	g1 := s.nextConfigGen()
	g2 := s.nextConfigGen()
	g3 := s.nextConfigGen()
	if !(g1 < g2 && g2 < g3) {
		t.Fatalf("config generations must be strictly monotonic, got %d,%d,%d", g1, g2, g3)
	}
	// A payload stamped with a drawn generation decodes back to the same value.
	payload := encodeConfigPayload("set system host-name x", g2)
	_, gen := decodeConfigPayload(payload)
	if gen != g2 {
		t.Fatalf("decoded gen %d != stamped gen %d", gen, g2)
	}
}

func TestConfigAncestryReceiveQueueApplyChain10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	const (
		text = "set security policies from-zone lan to-zone wan policy old\n"
		gen  = 77
	)
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	type result struct {
		text     string
		ancestry []configstore.RenameDescriptor
	}
	applied := make(chan result, 1)
	s.OnConfigReceivedWithAncestry = func(gotText string, gotAncestry []configstore.RenameDescriptor) error {
		applied <- result{text: gotText, ancestry: gotAncestry}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.handleMessage(nil, syncMsgConfig, encodeConfigPayloadWithAncestry(text, gen, want))
	select {
	case got := <-applied:
		if got.text != text || !reflect.DeepEqual(got.ancestry, want) {
			t.Fatalf("receive→queue→ancestry callback changed payload: got text=%q ancestry=%#v", got.text, got.ancestry)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("config ancestry payload never reached the apply callback")
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.lastAppliedConfigGen.Load() != gen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := s.lastAppliedConfigGen.Load(); got != gen {
		t.Fatalf("successful ancestry apply must advance applied generation: got %d want %d", got, gen)
	}
	if got := s.lastRecvConfigGen.Load(); got != gen {
		t.Fatalf("receive path must advance received generation before apply: got %d want %d", got, gen)
	}
}

func TestLegacyConfigReceiveQueueApplyChainWithoutAncestry10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	const (
		text = "set system host-name legacy\n"
		gen  = 78
	)
	applied := make(chan string, 1)
	s.OnConfigReceived = func(got string) error {
		applied <- got
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.handleMessage(nil, syncMsgConfig, encodeConfigPayload(text, gen))
	select {
	case got := <-applied:
		if got != text {
			t.Fatalf("legacy payload changed in receive/apply chain: got %q want %q", got, text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legacy config payload never reached the legacy apply callback")
	}
	if got := s.lastAppliedConfigGen.Load(); got != gen {
		t.Fatalf("legacy framed config must advance applied generation: got %d want %d", got, gen)
	}
}

func TestConfigQueueFullDropCanRetryAncestryPayload10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	fillConfigApplyQueue6778(t, s)
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	const gen = 79
	s.handleMessage(nil, syncMsgConfig, encodeConfigPayloadWithAncestry("retry-me", gen, want))
	if got := s.stats.ConfigsQueueFullDropped.Load(); got != 1 {
		t.Fatalf("full queue must count the dropped ancestry payload: got %d", got)
	}
	for len(s.configApplyCh) > 0 {
		<-s.configApplyCh
	}

	applied := make(chan []configstore.RenameDescriptor, 1)
	s.OnConfigReceivedWithAncestry = func(_ string, ancestry []configstore.RenameDescriptor) error {
		applied <- ancestry
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)
	s.handleMessage(nil, syncMsgConfig, encodeConfigPayloadWithAncestry("retry-me", gen, want))
	select {
	case got := <-applied:
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("retry must preserve ancestry sidecar: got %#v want %#v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("re-pushed ancestry payload never applied after queue drained")
	}
}

func TestLegacyConfigReceiveReorderedGenerationsApplyNewest10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	entered := make(chan struct{})
	release := make(chan struct{})
	applied := make(chan string, 2)
	s.OnConfigReceived = func(text string) error {
		select {
		case entered <- struct{}{}:
			<-release
		default:
		}
		applied <- text
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.handleMessage(nil, syncMsgConfig, encodeConfigPayload("config-C2", 2))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("newer config never entered apply callback")
	}
	s.handleMessage(nil, syncMsgConfig, encodeConfigPayload("config-C1", 1))
	close(release)
	select {
	case got := <-applied:
		if got != "config-C2" {
			t.Fatalf("newer config must apply first, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("newer config apply did not complete")
	}
	select {
	case got := <-applied:
		t.Fatalf("reordered stale config must not apply, got %q", got)
	case <-time.After(100 * time.Millisecond):
	}
	if got := s.lastAppliedConfigGen.Load(); got != 2 {
		t.Fatalf("reordered receive chain must retain newest applied generation: got %d", got)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 1 {
		t.Fatalf("reordered stale config must be counted once: got %d", got)
	}
}

func TestQueueConfigWithAncestryWireReceiveApplyChain10511(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	receiver := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	local, peer := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		peer.Close()
	})
	sender.installConn(0, local)
	sender.peerCapabilityFlags.Store(uint32(capFlagConfigAncestry))
	sender.peerSnapshotProtocol.Store(1)

	const (
		text = "set security policies from-zone lan to-zone wan policy old\n"
		gen  = 81
	)
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	applied := make(chan struct {
		text     string
		ancestry []configstore.RenameDescriptor
	}, 1)
	receiver.OnConfigReceivedWithAncestry = func(gotText string, gotAncestry []configstore.RenameDescriptor) error {
		applied <- struct {
			text     string
			ancestry []configstore.RenameDescriptor
		}{gotText, gotAncestry}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiver.configApplyLoop(ctx)

	queued := make(chan bool, 1)
	go func() {
		queued <- sender.QueueConfigWithAncestryAtGeneration(text, want, gen)
	}()
	msgType, payload, _ := readOneFrame(t, peer)
	if msgType != syncMsgConfig {
		t.Fatalf("QueueConfig must emit a config frame: got type %d", msgType)
	}
	if ok := <-queued; !ok {
		t.Fatal("QueueConfigWithAncestry reported that the negotiated sidecar write failed")
	}
	gotText, gotGen, gotAncestry := decodeConfigPayloadWithAncestry(payload)
	if gotText != text || gotGen != gen || !reflect.DeepEqual(gotAncestry, want) {
		t.Fatalf("wire sender changed config sidecar: text=%q gen=%d ancestry=%#v", gotText, gotGen, gotAncestry)
	}
	receiver.handleMessage(nil, syncMsgConfig, payload)
	select {
	case got := <-applied:
		if got.text != text || !reflect.DeepEqual(got.ancestry, want) {
			t.Fatalf("wire→receive→apply changed config sidecar: text=%q ancestry=%#v", got.text, got.ancestry)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wire config frame never reached the ancestry apply callback")
	}
}

func TestConfigAncestryCapabilityStateAndLegacyGate10511(t *testing.T) {
	s := &SessionSync{}
	if s.ConfigAncestryNegotiated() {
		t.Fatal("a fresh peer must not report negotiated ancestry capability")
	}
	if s.ConfigAncestryCapable() {
		t.Fatal("a fresh peer must not advertise ancestry capability")
	}
	s.peerSnapshotProtocol.Store(1)
	if !s.ConfigAncestryNegotiated() {
		t.Fatal("a peer protocol advertisement must mark capability discovery complete")
	}
	if s.ConfigAncestryCapable() {
		t.Fatal("discovery without the ancestry bit must stay on the legacy payload")
	}
	s.peerCapabilityFlags.Store(uint32(capFlagConfigAncestry))
	if !s.ConfigAncestryCapable() {
		t.Fatal("the config-ancestry capability bit was not recognized")
	}
}

func TestQueueConfigAncestryUnknownAndIncapablePeersUseLegacyPayload10511(t *testing.T) {
	const text = "set system host-name mixed-version\n"
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	for _, tc := range []struct {
		name  string
		known bool
	}{
		{name: "unknown", known: false},
		{name: "known-incapable", known: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
			local, peer := net.Pipe()
			t.Cleanup(func() {
				local.Close()
				peer.Close()
			})
			s.installConn(0, local)
			if tc.known {
				s.peerSnapshotProtocol.Store(1)
			}
			queued := make(chan bool, 1)
			go func() {
				queued <- s.QueueConfigWithAncestryAtGeneration(text, want, 91)
			}()
			msgType, payload, _ := readOneFrame(t, peer)
			if msgType != syncMsgConfig {
				t.Fatalf("legacy-gated queue emitted frame type %d, want config", msgType)
			}
			if !<-queued {
				t.Fatal("legacy-gated queue reported a write failure")
			}
			gotText, gotGen, gotAncestry := decodeConfigPayloadWithAncestry(payload)
			if gotText != text || gotGen != 91 {
				t.Fatalf("legacy-gated payload changed text/gen: text=%q gen=%d", gotText, gotGen)
			}
			if gotAncestry != nil {
				t.Fatalf("unknown/incapable peer received a rename sidecar: %#v", gotAncestry)
			}
		})
	}
}

func TestConfigAncestryPayloadIsFailSafeForOldParser10511(t *testing.T) {
	const text = "set system host-name sidecar\n"
	payload := encodeConfigPayloadWithAncestry(text, 92, []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}})
	if bytes.Equal(payload, []byte(text)) || !bytes.Contains(payload[len(text):], configAncestryMagic[:]) {
		t.Fatalf("sidecar payload lost its additive binary framing: %x", payload)
	}
	legacyText := string(payload)
	if legacyText == text {
		t.Fatal("an old parser must not silently see the sidecar as the original text")
	}
}

func TestQueueConfigWithAncestryWrapperUsesNegotiatedSidecar10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	local, peer := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		peer.Close()
	})
	s.installConn(0, local)
	s.peerSnapshotProtocol.Store(1)
	s.peerCapabilityFlags.Store(uint32(capFlagConfigAncestry))
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	queued := make(chan bool, 1)
	go func() {
		queued <- s.QueueConfigWithAncestry("set system host-name wrapper\n", want)
	}()
	msgType, payload, _ := readOneFrame(t, peer)
	if msgType != syncMsgConfig || !<-queued {
		t.Fatal("QueueConfigWithAncestry wrapper did not emit a config frame")
	}
	_, _, got := decodeConfigPayloadWithAncestry(payload)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrapper dropped negotiated ancestry: got %#v want %#v", got, want)
	}
}

func TestPeerCapabilitiesChangedOnlyOnStateTransition10511(t *testing.T) {
	s := &SessionSync{}
	changed := make(chan struct{}, 4)
	s.OnPeerCapabilitiesChanged = func() { changed <- struct{}{} }
	base := capabilityFrame9714(t, capFlagConfigAncestry)
	s.handleMessage(nil, syncMsgPeerCapabilities, base)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("first capability advertisement did not trigger a changed callback")
	}
	s.handleMessage(nil, syncMsgPeerCapabilities, base)
	select {
	case <-changed:
		t.Fatal("an identical repeated capability frame re-triggered the callback")
	case <-time.After(50 * time.Millisecond):
	}
	s.handleMessage(nil, syncMsgPeerCapabilities, capabilityFrame9714(t, capFlagConfigAncestry))
	select {
	case <-changed:
		t.Fatal("another identical capability frame re-triggered the callback")
	case <-time.After(50 * time.Millisecond):
	}
	s.handleMessage(nil, syncMsgPeerCapabilities, capabilityFrame9714(t, 0))
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("a capability downgrade did not trigger a changed callback")
	}
}

// A reordered STALE ancestry pair must drop whole: neither its text nor its
// sidecar may reach the apply callback. The legacy reorder cell pins the
// generation gate for text-only payloads; this one pins that the gate drops
// the pair, so a superseded rename cannot arm a capture for a config that no
// longer converges.
func TestAncestryReorderedGenerationsDropStalePair10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	entered := make(chan struct{})
	release := make(chan struct{})
	type pair struct {
		text     string
		ancestry []configstore.RenameDescriptor
	}
	applied := make(chan pair, 2)
	s.OnConfigReceivedWithAncestry = func(text string, ancestry []configstore.RenameDescriptor) error {
		select {
		case entered <- struct{}{}:
			<-release
		default:
		}
		applied <- pair{text: text, ancestry: ancestry}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	s.handleMessage(nil, syncMsgConfig, encodeConfigPayloadWithAncestry("config-C2", 2, want))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("newer ancestry config never entered apply callback")
	}
	s.handleMessage(nil, syncMsgConfig, encodeConfigPayloadWithAncestry("config-C1", 1, want))
	close(release)
	select {
	case got := <-applied:
		if got.text != "config-C2" || !reflect.DeepEqual(got.ancestry, want) {
			t.Fatalf("newer pair must apply intact: text=%q ancestry=%#v", got.text, got.ancestry)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("newer ancestry apply did not complete")
	}
	select {
	case got := <-applied:
		t.Fatalf("reordered stale ancestry pair must not apply: text=%q ancestry=%#v", got.text, got.ancestry)
	case <-time.After(100 * time.Millisecond):
	}
	if got := s.lastAppliedConfigGen.Load(); got != 2 {
		t.Fatalf("reordered ancestry chain must retain newest applied generation: got %d", got)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 1 {
		t.Fatalf("stale ancestry pair must count exactly one stale-ignore: got %d", got)
	}
}

// The #5084 binder for ancestry payloads: a pair QUEUED from a REPLACED peer
// boot must drop whole at apply time — its sidecar must never arm a capture
// for a dead incarnation's generation — while the rebooted peer's own lower-
// generation pair still applies intact. Reuses the #5084 incarnation env; the
// loop prefers the ancestry callback, which mirrors the env's hold/entered/
// applied rendezvous and additionally records the delivered sidecar.
func TestQueuedPriorIncarnationAncestryPairNeverApplies10511(t *testing.T) {
	e := newIncEnv(t, 1)
	type pair struct {
		text     string
		ancestry []configstore.RenameDescriptor
	}
	delivered := make(chan pair, 16)
	e.s.OnConfigReceivedWithAncestry = func(text string, ancestry []configstore.RenameDescriptor) error {
		e.mu.Lock()
		h := e.hold
		e.hold = nil
		e.mu.Unlock()
		if h != nil {
			e.entered <- text
			<-h
		}
		e.applied <- text
		delivered <- pair{text: text, ancestry: ancestry}
		return nil
	}
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	pushAncestry := func(idx int, text string, gen uint64) {
		e.s.handleMessage(e.conns[idx], syncMsgConfig, encodeConfigPayloadWithAncestry(text, gen, want))
	}
	e.prime(0, 1, &incA)
	hold := e.holdNext()
	pushAncestry(0, "config-from-boot-A", 5)
	e.waitEntered(t, "config-from-boot-A")
	pushAncestry(0, "stale-from-boot-A", 9_000_001)
	e.waitQueued(t, 1)
	e.prime(0, 2, &incB)
	close(hold)
	if got := e.waitApplied(3 * time.Second); got != "config-from-boot-A" {
		t.Fatalf("setup: boot A's first pair must apply normally; got %q", got)
	}
	select {
	case got := <-delivered:
		if got.text != "config-from-boot-A" || !reflect.DeepEqual(got.ancestry, want) {
			t.Fatalf("boot A's first pair must deliver its sidecar intact: text=%q ancestry=%#v", got.text, got.ancestry)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("boot A's first pair never reached the ancestry callback")
	}
	if got := e.waitApplied(1500 * time.Millisecond); got != "" {
		t.Fatalf("an ancestry pair QUEUED from a REPLACED peer boot must never apply; it applied as %q", got)
	}
	select {
	case got := <-delivered:
		t.Fatalf("the replaced boot's sidecar leaked to the callback: text=%q ancestry=%#v", got.text, got.ancestry)
	case <-time.After(100 * time.Millisecond):
	}
	if n := e.s.stats.ConfigsDeadIncarnationDropped.Load(); n != 1 {
		t.Fatalf("the pair drop must be counted; got %d", n)
	}
	pushAncestry(0, "current-from-boot-B", 42)
	if got := e.waitApplied(3 * time.Second); got != "current-from-boot-B" {
		t.Fatalf("the rebooted peer's pair must apply despite its lower generation; got %q", got)
	}
	select {
	case got := <-delivered:
		if got.text != "current-from-boot-B" || !reflect.DeepEqual(got.ancestry, want) {
			t.Fatalf("boot B's pair must deliver its sidecar intact: text=%q ancestry=%#v", got.text, got.ancestry)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("boot B's pair never reached the ancestry callback")
	}
}

// ReserveConfigGen hands the daemon a generation token under its
// active-publication lock so the queued frame carries the SNAPSHOT's
// generation even after a concurrent commit advances the counter. This pins
// both halves: the reservation is honored verbatim (not redrawn at queue
// time), and gen 0 — never a reservation — is refused without emitting.
func TestReservedConfigGenerationIsHonoredNotRedrawn10511(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	local, peer := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		peer.Close()
	})
	s.installConn(0, local)
	s.peerSnapshotProtocol.Store(1)
	s.peerCapabilityFlags.Store(uint32(capFlagConfigAncestry))
	g1 := s.ReserveConfigGen()
	g2 := s.ReserveConfigGen()
	if !(g1 < g2) {
		t.Fatalf("reservations must be strictly monotonic, got %d then %d", g1, g2)
	}
	want := []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}}
	queued := make(chan bool, 1)
	go func() {
		queued <- s.QueueConfigWithAncestryAtGeneration("reserved-text", want, g1)
	}()
	msgType, payload, _ := readOneFrame(t, peer)
	if msgType != syncMsgConfig || !<-queued {
		t.Fatal("reserved-generation queue did not emit a config frame")
	}
	gotText, gotGen, got := decodeConfigPayloadWithAncestry(payload)
	if gotText != "reserved-text" || gotGen != g1 || !reflect.DeepEqual(got, want) {
		t.Fatalf("reservation was not honored verbatim: text=%q gen=%d (want %d) ancestry=%#v", gotText, gotGen, g1, got)
	}
	if s.QueueConfigWithAncestryAtGeneration("zero-gen", want, 0) {
		t.Fatal("gen 0 is never a reservation and must be refused")
	}
	if _, _, ok := readOneFrame6778(peer, 100*time.Millisecond); ok {
		t.Fatal("refused zero-gen queue emitted a frame")
	}
}

// An old (pre-sidecar) peer decodes with the gen-magic tail check only: the
// last 16 bytes of a sidecar payload are JSON tail, not the gen magic, so it
// sees gen 0 and the whole framed blob as config text. That text must then
// fail LOUD at the old ingress (Store.SyncApply) instead of converging on
// garbage. The base hierarchical text SyncApplies cleanly on its own, so the
// rejection below proves the framing causes the failure rather than a bad
// fixture. The current decoder recovers the exact text, generation, and
// sidecar (see the RoundTrip cells).
func TestSidecarPayloadFailsSafeUnderLegacyDecode10511(t *testing.T) {
	const text = "system {\n    host-name sidecar;\n}\n"
	payload := encodeConfigPayloadWithAncestry(text, 92, []configstore.RenameDescriptor{{
		SourcePath:      []string{"security", "policies", "old"},
		DestinationPath: []string{"security", "policies", "new"},
	}})
	var legacyGen uint64
	legacyText := string(payload)
	if len(payload) >= 16 && bytes.Equal(payload[len(payload)-16:len(payload)-8], configGenMagic[:]) {
		legacyGen = binary.LittleEndian.Uint64(payload[len(payload)-8:])
		legacyText = string(payload[:len(payload)-16])
	}
	if legacyGen != 0 {
		t.Fatalf("old decoder extracted gen %d from a sidecar payload; a nonzero gen would arm ordering on garbage", legacyGen)
	}
	if legacyText == text {
		t.Fatal("old decoder silently recovered the original text from a sidecar payload")
	}
	if !bytes.Contains([]byte(legacyText), configAncestryMagic[:]) {
		t.Fatal("legacy-visible garbage lost the ancestry framing; an operator could not identify the payload shape from the parse error")
	}
	base, err := configstore.New(filepath.Join(t.TempDir(), "base"))
	if err != nil {
		t.Fatalf("fixture store: %v", err)
	}
	if _, err := base.SyncApply(text, nil); err != nil {
		t.Fatalf("fixture: the base hierarchical text must SyncApply cleanly alone: %v", err)
	}
	legacy, err := configstore.New(filepath.Join(t.TempDir(), "legacy"))
	if err != nil {
		t.Fatalf("fixture store: %v", err)
	}
	if _, err := legacy.SyncApply(legacyText, nil); err == nil {
		t.Fatal("legacy-decoded sidecar payload SyncApplied cleanly; an old peer would " +
			"converge on framed garbage instead of failing loud at ingress")
	}
}

// This build must actually advertise the config-ancestry bit, or no peer can
// ever gate the sidecar on it — and a fully-upgraded cluster would send
// legacy text-only frames forever, each node believing the other cannot decode
// ancestry. Binds the constant to the flag rather than assuming they agree
// (peer of TestThisBuildAdvertisesPeerDeleteOwnership9714).
func TestThisBuildAdvertisesConfigAncestry10511(t *testing.T) {
	t.Parallel()
	if localCapabilityFlags&capFlagConfigAncestry == 0 {
		t.Fatal("localCapabilityFlags does not set capFlagConfigAncestry, so this node tells its peer " +
			"it cannot decode a rename sidecar, and two upgraded nodes would take the legacy " +
			"teardown path for every rename permanently")
	}
	for _, tc := range []struct {
		name string
		bit  uint8
	}{
		{"capFlagFenceAck", capFlagFenceAck},
		{"capFlagPeerDeleteOwnership", capFlagPeerDeleteOwnership},
		{"capFlagPurgeRetirementForwardOnly", capFlagPurgeRetirementForwardOnly},
		{"capFlagInstallTableIdentity", capFlagInstallTableIdentity},
	} {
		if capFlagConfigAncestry == tc.bit {
			t.Fatalf("capFlagConfigAncestry collides with %s: one bit cannot carry two capabilities", tc.name)
		}
		if localCapabilityFlags&tc.bit == 0 {
			t.Fatalf("adding capFlagConfigAncestry dropped %s from localCapabilityFlags", tc.name)
		}
	}
}
func TestConfigPayloadAuthenticationProvenance10870(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	authenticated := make(chan bool, 2)
	s.OnConfigReceivedWithProvenance = func(_ string, _ []configstore.RenameDescriptor, peerAuthenticated bool) error {
		authenticated <- peerAuthenticated
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.handleMessage(&authConn{readKey: []byte("verified-read-key")},
		syncMsgConfig, encodeConfigPayload("authenticated", 1))
	s.handleMessage(&authConn{},
		syncMsgConfig, encodeConfigPayload("legacy-unkeyed", 2))

	for _, want := range []bool{true, false} {
		select {
		case got := <-authenticated:
			if got != want {
				t.Fatalf("config callback authentication=%v, want %v", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("config apply callback did not receive the queued payload")
		}
	}
}
