package dhcprelay

import (
	"context"
	"errors"
	"github.com/psaab/xpf/pkg/config"
	"net"
	"testing"
	"time"
)

// Regression for #13277 (D10-03): a spec-changing Apply replaced the
// interfaceRelay/dhcpV6Relay wholesale, zeroing monotonic counters and
// PendingEvicted even though #6562 already carried pending bindings across.
func TestApplyPreservesInterfaceRelayAndPendingEvictedCounters(t *testing.T) {
	// --- DHCPv4 ---
	factory, _ := recordingFactory()
	m := testManager(factory)
	defer m.Stop()
	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2000000000)

	m.mu.Lock()
	var old4 *interfaceRelay
	for _, ir := range m.relays {
		old4 = ir
	}
	m.mu.Unlock()
	if old4 == nil {
		t.Fatal("no v4 relay")
	}
	old4.requestsRelayed.Store(11)
	old4.repliesForwarded.Store(12)
	old4.requestsDroppedBackup.Store(13)
	old4.repliesDroppedUnknownServer.Store(14)
	old4.repliesDroppedNoRequest.Store(15)
	old4.repliesDroppedForceRenew.Store(16)
	old4.requestsDroppedMaxHops.Store(17)
	old4.requestsUntrustedGiaddrReset.Store(18)
	old4.requestsDroppedRateLimit.Store(19)
	old4.repliesL2Unicast.Store(20)
	old4.repliesUnicastCiaddr.Store(21)
	old4.repliesBroadcastFlag1.Store(22)
	old4.repliesBroadcastForced.Store(23)
	old4.repliesBroadcastNoTarget.Store(24)
	old4.repliesBroadcastL2Fallback.Store(25)
	old4.repliesBroadcastNak.Store(26)
	old4.repliesDroppedBadCiaddr.Store(27)
	// Seed PendingEvicted directly (plain uint64 under mu).
	old4.pending.mu.Lock()
	old4.pending.evicted = 7
	old4.pending.mu.Unlock()

	cfg := singleInterfaceConfig()
	cfg.Groups["g"].AlwaysBroadcast = true // spec change -> restart
	m.Apply(context.Background(), cfg)

	stats4 := m.Stats()
	var st4 *RelayStats
	for i := range stats4 {
		if stats4[i].Family == "" {
			st4 = &stats4[i]
			break
		}
	}
	if st4 == nil {
		t.Fatal("no v4 stats after re-Apply")
	}
	want4 := map[string]uint64{
		"RequestsRelayed": 11, "RepliesForwarded": 12, "RequestsDroppedBackup": 13,
		"RepliesDroppedUnknownServer": 14, "RepliesDroppedNoRequest": 15,
		"RepliesDroppedForceRenew": 16, "RequestsDroppedMaxHops": 17,
		"RequestsUntrustedGiaddrReset": 18, "RequestsDroppedRateLimit": 19,
		"RepliesL2Unicast": 20, "RepliesUnicastCiaddr": 21, "RepliesBroadcastFlag1": 22,
		"RepliesBroadcastForced": 23, "RepliesBroadcastNoTarget": 24,
		"RepliesBroadcastL2Fallback": 25, "RepliesBroadcastNak": 26, "PendingEvicted": 7,
		"RepliesDroppedBadCiaddr": 27,
	}
	got4 := map[string]uint64{
		"RequestsRelayed": st4.RequestsRelayed, "RepliesForwarded": st4.RepliesForwarded,
		"RequestsDroppedBackup":        st4.RequestsDroppedBackup,
		"RepliesDroppedUnknownServer":  st4.RepliesDroppedUnknownServer,
		"RepliesDroppedNoRequest":      st4.RepliesDroppedNoRequest,
		"RepliesDroppedForceRenew":     st4.RepliesDroppedForceRenew,
		"RequestsDroppedMaxHops":       st4.RequestsDroppedMaxHops,
		"RequestsUntrustedGiaddrReset": st4.RequestsUntrustedGiaddrReset,
		"RequestsDroppedRateLimit":     st4.RequestsDroppedRateLimit,
		"RepliesL2Unicast":             st4.RepliesL2Unicast,
		"RepliesUnicastCiaddr":         st4.RepliesUnicastCiaddr,
		"RepliesBroadcastFlag1":        st4.RepliesBroadcastFlag1,
		"RepliesBroadcastForced":       st4.RepliesBroadcastForced,
		"RepliesBroadcastNoTarget":     st4.RepliesBroadcastNoTarget,
		"RepliesBroadcastL2Fallback":   st4.RepliesBroadcastL2Fallback,
		"RepliesBroadcastNak":          st4.RepliesBroadcastNak,
		"RepliesDroppedBadCiaddr":      st4.RepliesDroppedBadCiaddr,
		"PendingEvicted":               st4.PendingEvicted,
	}
	for k, want := range want4 {
		if got4[k] != want {
			t.Errorf("v4 %s = %d after spec-changing Apply, want %d (counter reset)", k, got4[k], want)
		}
	}

}

func TestDHCPV6ApplyPreservesCounters(t *testing.T) {
	m := NewManager()
	defer m.Stop()
	m.v6.resolveLink = func(string) (net.IP, error) {
		return net.ParseIP("2001:db8::1"), nil
	}
	m.v6.newConn = func(context.Context, string, net.IP) (dhcpV6Sockets, error) {
		return dhcpV6Sockets{}, errors.New("test connection unavailable")
	}
	old := &dhcpV6Relay{ifaceName: "ge-0/0/0.0", done: make(chan struct{}),
		pending: newPendingTableOf[pending6Key, pending6Entry](8, time.Hour, time.Now),
		cancel:  func() {}}
	close(old.done)
	old.requestsRelayed.Store(31)
	old.repliesForwarded.Store(32)
	old.requestsDroppedBackup.Store(33)
	old.requestsDroppedRateLimit.Store(34)
	old.requestsDroppedNested.Store(35)
	old.requestsDroppedParse.Store(36)
	old.requestsDroppedPort.Store(37)
	old.requestsDroppedPeer.Store(38)
	old.requestsDroppedBuild.Store(39)
	old.repliesDroppedUnknownSrv.Store(40)
	old.repliesDroppedIID.Store(41)
	old.repliesDroppedParse.Store(42)
	old.repliesDroppedInvalid.Store(43)
	old.repliesDroppedNested.Store(44)
	old.repliesDroppedNoRequest.Store(45)
	old.pending.addEvictions(46)
	m.v6.relays[old.ifaceName] = old
	cfg := &config.DHCPRelayV6Config{
		ServerGroups: map[string]*config.DHCPRelayV6ServerGroup{
			"sg6": {Name: "sg6", Servers: []string{"2001:db8::5"}},
		},
		Groups: map[string]*config.DHCPRelayV6Group{
			"g6": {Name: "g6", Interfaces: []string{old.ifaceName}, ActiveServerGroup: "sg6"},
		},
	}
	m.v6.apply(context.Background(), cfg, func(name string) string { return name },
		func(string) bool { return true })
	stats := m.Stats()
	if len(stats) != 1 {
		t.Fatalf("stats rows = %d, want 1: %+v", len(stats), stats)
	}
	got := stats[0]
	v6Capacity, _ := pendingCapacityFor(defaultMaxPacketRate)
	want := RelayStats{Family: "inet6", Interface: old.ifaceName,
		KernelInterface: old.ifaceName, PendingCapacity: uint64(v6Capacity),
		RequestsRelayed: 31, RepliesForwarded: 32, RequestsDroppedBackup: 33,
		RequestsDroppedRateLimit: 34, RequestsDroppedNested: 35,
		RequestsDroppedParse: 36, RequestsDroppedPort: 37,
		RequestsDroppedPeer: 38, RequestsDroppedBuild: 39,
		RepliesDroppedUnknownServer: 40, RepliesDroppedIID: 41,
		RepliesDroppedParse: 42, RepliesDroppedInvalid: 43,
		RepliesDroppedNested: 44, RepliesDroppedNoRequest: 45, PendingEvicted: 46}
	if got != want {
		t.Errorf("DHCPv6 counters after spec-changing Apply = %+v, want %+v", got, want)
	}
}
