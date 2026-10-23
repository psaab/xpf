package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/psaab/xpf/pkg/config"
)

// relayConfigWithRate builds a single-interface relay config whose group sets
// the #5670 per-interface ingress rate limit (packets/second).
func relayConfigWithRate(rate int) *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {
				Name:              "g",
				Interfaces:        []string{"ge-0-0-0"},
				ActiveServerGroup: "sg",
				MaximumPacketRate: rate,
			},
		},
	}
}

// TestTokenBucket_BurstThenRefill is the deterministic unit proof of the #5670
// token-bucket semantics with an injected (frozen/advanceable) clock — no
// sleeping. It pins three properties: (1) a frozen clock admits exactly the
// burst capacity then denies; (2) advancing the clock one second refills
// exactly `rate` tokens; (3) a long idle refill is CAPPED at the burst
// capacity, not rate×elapsed (so an idle relay cannot bank unbounded credit and
// defeat the limiter on the next flood).
func TestTokenBucket_BurstThenRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	b := newTokenBucket(10, 20, clock) // rate 10/s, burst 20

	// (1) Full bucket, frozen clock: exactly `burst` (20) admitted, rest denied.
	allowed := 0
	for i := 0; i < 50; i++ {
		if b.allow() {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("initial burst: allowed %d, want 20 (burst capacity)", allowed)
	}
	if b.allow() {
		t.Fatal("empty bucket must deny with no time advance")
	}

	// (2) Advance 1s → +10 tokens (== rate), so 10 more admitted.
	now = now.Add(time.Second)
	allowed = 0
	for i := 0; i < 50; i++ {
		if b.allow() {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("after 1s refill: allowed %d, want 10 (sustained rate)", allowed)
	}

	// (3) Advance far → refill capped at burst (20), NOT rate×100.
	now = now.Add(100 * time.Second)
	allowed = 0
	for i := 0; i < 200; i++ {
		if b.allow() {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("long-idle refill: allowed %d, want 20 (capped at burst, not rate×elapsed)", allowed)
	}
}

// TestRunRelay_RateLimit_5670 is the end-to-end fail-on-revert proof for the
// #5670 per-interface DHCP relay ingress rate limit, as amended by #16087
// per-sender fairness. A burst of N valid BOOTREQUEST/DISCOVER datagrams
// from ONE sender is pushed through the live runRelay loop with the clock
// FROZEN, so the whole burst arrives "instantly": the aggregate bucket
// (burst 10) admits its burst, but the single sender's fairness sub-bucket
// (burst fairBurstFloor=8) binds first, so exactly 8 reach the server.
// Pre-#16087 this admitted the full aggregate burst of 10 — the aggregate
// starvation that let one MAC consume every token.
//
// GREEN: exactly fairBurstFloor datagrams reach the server and the excess
// (N-fairBurstFloor) is counted in RequestsDroppedRateLimit.
//
// RED-on-revert: neutralize either limiter (delete the aggregate or the
// fairness drop, or wire an effectively-infinite rate) and more than
// fairBurstFloor datagrams are relayed — the assertions below fail.
func TestRunRelay_RateLimit_5670(t *testing.T) {
	const rate = 5 // aggregate burst 10; fairness burst (8) binds first
	const n = 25

	// One valid client DISCOVER, replayed N times to model a flood from a single
	// untrusted client-facing segment.
	discover, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	discover.OpCode = dhcpv4.OpcodeBootRequest
	discover.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x05}
	discover.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	wire := discover.ToBytes()

	pending := make([][]byte, n)
	for i := range pending {
		pending[i] = append([]byte(nil), wire...)
	}

	client := newFakeConn()
	client.pending = pending
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	// Freeze the clock: the whole burst is admitted/denied at one instant, so the
	// bucket refills nothing mid-burst and the outcome is deterministic.
	frozen := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return frozen }

	m.Apply(context.Background(), relayConfigWithRate(rate))
	defer m.Stop()

	// Wait until the loop has read all N datagrams and blocked on the (N+1)th
	// read — at that point every pending packet has been fully processed (the
	// loop reads, acts, then loops back to ReadFrom).
	deadline := time.Now().Add(2 * time.Second)
	for client.readCalls.Load() < int64(n+1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := client.readCalls.Load(); got < int64(n+1) {
		t.Fatalf("relay did not consume all %d datagrams (readCalls=%d)", n, got)
	}

	// Exactly the per-sender fairness burst relayed to the one configured server.
	if got := server.writeCount(); got != fairBurstFloor {
		t.Errorf("relayed %d datagrams, want %d (per-sender fairness burst) — "+
			"fairness limiter not bounding the single-sender flood", got, fairBurstFloor)
	}

	var relayed, dropped uint64
	for _, s := range m.Stats() {
		relayed += s.RequestsRelayed
		dropped += s.RequestsDroppedRateLimit
	}
	if relayed != uint64(fairBurstFloor) {
		t.Errorf("RequestsRelayed = %d, want %d (fairness burst admitted)", relayed, fairBurstFloor)
	}
	if dropped != uint64(n-fairBurstFloor) {
		t.Errorf("RequestsDroppedRateLimit = %d, want %d (excess dropped) — "+
			"the flood was not throttled", dropped, n-fairBurstFloor)
	}
}

// TestRunRelay_RateLimit_DefaultBound proves an UNCONFIGURED relay still gets
// both bounds: with no `overrides maximum-packet-rate`, the resolver applies
// defaultMaxPacketRate (100 pps) so the aggregate burst is
// relayBurstFor(100)=200, and #16087 fairness caps this ONE sender at
// fairBurstFloor. A frozen-clock single-sender flood of 250 therefore admits
// exactly fairBurstFloor and drops the rest. RED-on-revert: if the default
// is not applied (bucket rate 0 / limiter opt-in only) or fairness is
// removed, an unconfigured relay would relay far more than fairBurstFloor.
func TestRunRelay_RateLimit_DefaultBound(t *testing.T) {
	const n = 250

	discover, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	discover.OpCode = dhcpv4.OpcodeBootRequest
	discover.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x06}
	discover.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	wire := discover.ToBytes()

	pending := make([][]byte, n)
	for i := range pending {
		pending[i] = append([]byte(nil), wire...)
	}

	client := newFakeConn()
	client.pending = pending
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	frozen := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return frozen }

	// singleInterfaceConfig sets NO maximum-packet-rate → resolver default.
	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for client.readCalls.Load() < int64(n+1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := client.readCalls.Load(); got < int64(n+1) {
		t.Fatalf("relay did not consume all %d datagrams (readCalls=%d)", n, got)
	}

	if got := server.writeCount(); got != fairBurstFloor {
		t.Errorf("relayed %d datagrams, want %d (per-sender fairness burst at default rate) — "+
			"unconfigured relay is unbounded", got, fairBurstFloor)
	}
	var dropped uint64
	for _, s := range m.Stats() {
		dropped += s.RequestsDroppedRateLimit
	}
	if dropped != uint64(n-fairBurstFloor) {
		t.Errorf("RequestsDroppedRateLimit = %d, want %d (default bound not applied?)",
			dropped, n-fairBurstFloor)
	}
}
