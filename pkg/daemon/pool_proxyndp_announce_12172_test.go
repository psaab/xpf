package daemon

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #12172: a new RG owner must ANNOUNCE the IPv6 pool addresses with an
// unsolicited NA, not merely stop the standby answering for them.
//
// #8405 landed the IPv4 half: announceProxyARPPoolAddresses sends one GARP per
// pool address, because removing a responder does not invalidate a binding
// already cached upstream. The v6 half was deliberately left ABSENT —
// announcing v6 through the v4 path would be silently wrong — but no v6 path
// was ever added. RETH MACs are per-node (RethVirtualMAC includes the node
// id), so an upstream neighbor entry for a pool address points at the OLD
// node until NUD expires: on failover the v4 binding is refreshed
// immediately while the v6 binding goes stale.
//
// The solicited path is not the defect: the userspace responder answers NUD
// probes, so NUD eventually bounds recovery. The defect is the missing
// failover INVALIDATION — same shape as #8405, same fix shape.

// upstreamNeigh12172 models an upstream neighbor cache with NUD expiry.
// Bindings initially point at the OLD owner's per-node RETH MAC; an
// advertisement rebinds its own address and restarts the aging lifetime.
// A cache entry that is neither refreshed nor advertised expires at the
// fixture lifetime, standing in for upstream NUD.
type upstreamNeighEntry12172 struct {
	mac       string
	expiresAt time.Duration
}

type upstreamNeigh12172 struct {
	now     time.Duration
	ageOut  time.Duration
	entries map[string]upstreamNeighEntry12172
}

func seededUpstreamNeigh12172(oldMAC string, ips ...string) *upstreamNeigh12172 {
	m := &upstreamNeigh12172{
		ageOut:  30 * time.Second,
		entries: make(map[string]upstreamNeighEntry12172, len(ips)),
	}
	for _, ip := range ips {
		m.entries[ip] = upstreamNeighEntry12172{mac: oldMAC, expiresAt: m.ageOut}
	}
	return m
}

func (m *upstreamNeigh12172) advance(elapsed time.Duration) {
	m.now += elapsed
}

func (m *upstreamNeigh12172) neighbor(ip string) (string, bool) {
	entry, ok := m.entries[ip]
	if !ok {
		return "", false
	}
	if m.now >= entry.expiresAt {
		delete(m.entries, ip)
		return "", false
	}
	return entry.mac, true
}

func (m *upstreamNeigh12172) rebind(ip, mac string) {
	if _, ok := m.entries[ip]; !ok {
		return
	}
	m.entries[ip] = upstreamNeighEntry12172{mac: mac, expiresAt: m.now + m.ageOut}
}

func (m *upstreamNeigh12172) applyGARP12172(calls []garpCall8405, newMAC string) {
	for _, c := range calls {
		m.rebind(c.ip, newMAC)
	}
}

func (m *upstreamNeigh12172) applyNA12172(calls []naCall12172, newMAC string) {
	for _, c := range calls {
		m.rebind(c.ip, newMAC)
	}
}

type naCall12172 struct {
	iface string
	ip    string
	count int
}

func captureNA12172(t *testing.T) *[]naCall12172 {
	t.Helper()
	var mu sync.Mutex
	calls := []naCall12172{}
	prev := directProxyNABurstFn
	directProxyNABurstFn = func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, naCall12172{iface: iface, ip: ip.String(), count: count})
		return nil
	}
	t.Cleanup(func() { directProxyNABurstFn = prev })
	return &calls
}

func TestNewOwnerRefreshesUpstreamV6PoolBinding12172(t *testing.T) {
	// THE DEFECT CELL. The upstream holds pool bindings for the old owner's
	// MAC in both families; after the new owner announces, both must point
	// at the new owner. The v4 entry is the control — it passes pre-fix.
	// The v6 entry FAILS pre-fix: no NA is sent, so the binding stays stale
	// until NUD re-resolves on its own schedule.
	const oldMAC, newMAC = "02:bf:72:16:01:01", "02:bf:72:16:01:02"
	const v4, v6 = "172.16.80.7", "2001:db8::7"

	// Positive aging control: without an announcement the old-owner entry
	// remains valid immediately before its NUD expiry, then ages out.
	agingControl := seededUpstreamNeigh12172(oldMAC, v6)
	agingControl.advance(29 * time.Second)
	if got, ok := agingControl.neighbor(v6); !ok || got != oldMAC {
		t.Fatalf("before NUD expiry, upstream neighbor = (%q, %v), want old MAC %s",
			got, ok, oldMAC)
	}
	agingControl.advance(time.Second)
	if got, ok := agingControl.neighbor(v6); ok {
		t.Fatalf("after NUD expiry, upstream still has binding %s for %s", got, v6)
	}

	// The actual failover path runs inside that final second of the old
	// binding's lifetime, so only an announcement should refresh it.
	upstream := seededUpstreamNeigh12172(oldMAC, v4, v6)
	upstream.advance(29 * time.Second)
	garps := captureGARP8405(t)
	nas := captureNA12172(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(
		cfgWithPoolProxyARP8405(1, v4+"/32", v6+"/128"), 1, nil)

	upstream.applyGARP12172(*garps, newMAC)
	upstream.applyNA12172(*nas, newMAC)
	if got, ok := upstream.neighbor(v4); !ok || got != newMAC {
		t.Errorf("CONTROL FAILED: v4 pool binding = (%s, %v); want new owner %s",
			got, ok, newMAC)
	}
	if got, ok := upstream.neighbor(v6); !ok || got != newMAC {
		t.Errorf("v6 pool binding = (%s, %v) after failover; want new owner %s. "+
			"RETH MACs are per-node, so upstream return traffic keeps going "+
			"to the standby until NUD expires — the #8405 fault in v6.",
			got, ok, newMAC)
	}

	// Reaching the old entry's expiry must not age out an address refreshed
	// by the failover announcement.
	upstream.advance(time.Second)
	if got, ok := upstream.neighbor(v4); !ok || got != newMAC {
		t.Errorf("the v4 control aged out at the old NUD deadline: (%s, %v)",
			got, ok)
	}
	if got, ok := upstream.neighbor(v6); !ok || got != newMAC {
		t.Errorf("the v6 neighbor was not refreshed before NUD expiry: (%s, %v)",
			got, ok)
	}
}

func TestPoolNAIsOnePerAddressNotABurst12172(t *testing.T) {
	// Breadth, not depth — same rationale as the v4 bound. Depth x breadth
	// is what turns this into a storm on a large pool.
	nas := captureNA12172(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(
		cfgWithPoolProxyARP8405(1, "2001:db8::7/128"), 1, nil)
	if len(*nas) != 1 {
		t.Fatalf("want 1 NA for the v6 pool address; got %d", len(*nas))
	}
	if (*nas)[0].count != 1 {
		t.Errorf("pool NA used a burst of %d; want 1 per address",
			(*nas)[0].count)
	}
	if got := (*nas)[0].ip; got != "2001:db8::7" {
		t.Errorf("announced %s, want the pool address 2001:db8::7", got)
	}
}

func TestPoolNARespectsOwnershipFence12172(t *testing.T) {
	// Same dangerous direction as the v4 control: announcing a v6 address
	// for an RG this node does not own tells the upstream to send us
	// traffic the PEER is primary for.
	nas := captureNA12172(t)
	d := &Daemon{}
	// The interface belongs to RG 2; we are announcing for RG 1.
	d.announceProxyARPPoolAddresses(
		cfgWithPoolProxyARP8405(2, "2001:db8::7/128"), 1, nil)
	if len(*nas) != 0 {
		t.Errorf("announced %d v6 addresses for an RG whose interface belongs "+
			"to a different RG; got %v", len(*nas), *nas)
	}
}

func TestPoolNAStopsWhenOwnershipMovesAgain12172(t *testing.T) {
	// stillValid is the ownership fence the VIP burst already honours. An
	// announce that kept going after ownership moved would be telling the
	// upstream to send us traffic we no longer own.
	nas := captureNA12172(t)
	d := &Daemon{}
	valid := true
	d.announceProxyARPPoolAddresses(
		cfgWithPoolProxyARP8405(1, "2001:db8::7/128", "2001:db8::8/128", "2001:db8::9/128"),
		1,
		func() bool { defer func() { valid = false }(); return valid },
	)
	if len(*nas) > 1 {
		t.Errorf("the v6 announce must stop as soon as stillValid goes false; sent %d",
			len(*nas))
	}
}

func TestPoolAnnounceBoundCoversBothFamilies12172(t *testing.T) {
	// The 64-address bound is per-FAILOVER fan-out, not per-family: v4 and
	// v6 share it, in deterministic configured order, so a mixed pool
	// cannot double the raw-socket fan-out the bound exists to prevent.
	var addrs []string
	for i := 0; i < proxyARPAnnounceMaxAddresses*3; i++ {
		if i%2 == 0 {
			addrs = append(addrs, fmt.Sprintf("172.16.80.%d/32", 100+(i/2)%100))
		} else {
			addrs = append(addrs, fmt.Sprintf("2001:db8::%x/128", i))
		}
	}
	garps := captureGARP8405(t)
	nas := captureNA12172(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(cfgWithPoolProxyARP8405(1, addrs...), 1, nil)

	if total := len(*garps) + len(*nas); total != proxyARPAnnounceMaxAddresses {
		t.Fatalf("announced %d addresses across both families; the bound is %d",
			total, proxyARPAnnounceMaxAddresses)
	}
	// Deterministic: the FIRST N in configured order. addrs[0] is v4, so the
	// first GARP must be it and no NA may jump the queue ahead of it.
	if len(*garps) == 0 {
		t.Fatal("the first configured IPv4 announce was not sent")
	}
	if (*garps)[0].ip != "172.16.80.100" {
		t.Errorf("truncation must keep the first N in configured order; got %s first",
			(*garps)[0].ip)
	}
	if len(*nas) == 0 || (*nas)[0].ip != "2001:db8::1" {
		t.Errorf("expected the first v6 address in configured order to be announced; got %v", *nas)
	}
}
func TestPoolAnnounceAttemptBoundCoversSendFailures12172(t *testing.T) {
	// A raw-socket failure still consumed one attempt. It must not let later
	// addresses expand the per-failover fan-out beyond the same shared bound.
	var garpAttempts, naAttempts int
	prevARP, prevNA := directGARPBurstFn, directProxyNABurstFn
	directGARPBurstFn = func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error {
		garpAttempts++
		return errors.New("synthetic send failure")
	}
	directProxyNABurstFn = func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error {
		naAttempts++
		return errors.New("synthetic send failure")
	}
	t.Cleanup(func() {
		directGARPBurstFn, directProxyNABurstFn = prevARP, prevNA
	})

	var addrs []string
	for i := 0; i < proxyARPAnnounceMaxAddresses*3; i++ {
		if i%2 == 0 {
			addrs = append(addrs, fmt.Sprintf("172.16.%d.%d/32", 80+i/256, i%256))
		} else {
			addrs = append(addrs, fmt.Sprintf("2001:db8::%x/128", i))
		}
	}
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(cfgWithPoolProxyARP8405(1, addrs...), 1, nil)

	if got := garpAttempts + naAttempts; got != proxyARPAnnounceMaxAddresses {
		t.Errorf("attempted %d sends across both families after send errors; want the shared bound %d",
			got, proxyARPAnnounceMaxAddresses)
	}
}
