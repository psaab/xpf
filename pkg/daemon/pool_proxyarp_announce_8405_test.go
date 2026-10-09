package daemon

import (
	"net"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #8405: a new RG owner must ANNOUNCE the pool addresses, not merely stop the
// standby answering for them.
//
// #8297 landed the ownership gate — the standby no longer answers proxy-ARP for
// a pool address on an RG it does not own. Necessary, not sufficient: removing
// a responder does not invalidate a binding already cached upstream.
//
// The measurement that makes this a defect rather than a theory: the seven
// misdelivered SYN-ACKs carried the STANDBY's MAC (02:bf:72:16:01:01) on a
// non-promiscuous NIC — so they were addressed to it, so the upstream had the
// pool address bound to the standby. A witness flow in the same cell recorded
// zero on the standby, which is what makes the seven mean something. That also
// rules out switch-port MAC learning: that mechanism delivers frames carrying
// the OWNER's MAC to the wrong port, and a non-promiscuous NIC drops those at
// the wire rather than counting them received.

type garpCall8405 struct {
	iface string
	ip    string
	count int
}

func captureGARP8405(t *testing.T) *[]garpCall8405 {
	t.Helper()
	var mu sync.Mutex
	calls := []garpCall8405{}
	prev := directGARPBurstFn
	directGARPBurstFn = func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, garpCall8405{iface: iface, ip: ip.String(), count: count})
		return nil
	}
	t.Cleanup(func() { directGARPBurstFn = prev })
	return &calls
}

func cfgWithPoolProxyARP8405(rg int, addrs ...string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: rg},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth0", Addresses: addrs},
	}
	return cfg
}

func TestANewOwnerAnnouncesItsPoolAddresses8405(t *testing.T) {
	calls := captureGARP8405(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(cfgWithPoolProxyARP8405(1, "172.16.80.7/32"), 1, nil)

	if len(*calls) != 1 {
		t.Fatalf("the new owner must announce the pool address; got %d GARPs.\n"+
			"Suppression alone leaves the upstream sending to the STANDBY's MAC "+
			"until its own entry ages out — which is the path the fix was meant "+
			"to repair.", len(*calls))
	}
	if got := (*calls)[0].ip; got != "172.16.80.7" {
		t.Errorf("announced %s, want the pool address 172.16.80.7", got)
	}
}

func TestThePoolAnnounceIsOnePerAddressNotABurst8405(t *testing.T) {
	// Breadth, not depth. The burst exists to survive loss when one VIP must be
	// re-bound; here the job is invalidating one upstream binding per address,
	// and depth x breadth is what turns this into a storm on a large pool.
	calls := captureGARP8405(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(cfgWithPoolProxyARP8405(1, "172.16.80.7/32"), 1, nil)
	if (*calls)[0].count != 1 {
		t.Errorf("pool announce used a burst of %d; want 1 per address",
			(*calls)[0].count)
	}
}

func TestAnRGThisNodeDoesNotOwnIsNotAnnounced8405(t *testing.T) {
	// THE CONTROL, and it is the dangerous direction. Announcing an address for
	// an RG this node does not own tells the upstream to send us traffic the
	// PEER is primary for — worse than the stale binding being fixed.
	calls := captureGARP8405(t)
	d := &Daemon{}
	// The interface belongs to RG 2; we are announcing for RG 1.
	d.announceProxyARPPoolAddresses(cfgWithPoolProxyARP8405(2, "172.16.80.7/32"), 1, nil)
	if len(*calls) != 0 {
		t.Errorf("announced %d addresses for an RG whose interface belongs to a "+
			"different RG; got %v", len(*calls), *calls)
	}
}

func TestThePoolAnnounceIsBounded8405(t *testing.T) {
	// A proxy-arp statement expands to up to 256 addresses and an interface may
	// carry several. Unbounded, this recreates the exact CPU/socket-exhaustion
	// vector GratuitousARPBurstClamp exists to prevent, through a different
	// door.
	var addrs []string
	for i := 0; i < proxyARPAnnounceMaxAddresses*3; i++ {
		addrs = append(addrs, net.IPv4(172, 16, 80, byte(i%250)).String()+"/32")
	}
	calls := captureGARP8405(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(cfgWithPoolProxyARP8405(1, addrs...), 1, nil)

	if len(*calls) != proxyARPAnnounceMaxAddresses {
		t.Fatalf("announced %d addresses; the bound is %d",
			len(*calls), proxyARPAnnounceMaxAddresses)
	}
	// Deterministic: the FIRST N in configured order, so the same addresses are
	// announced on every failover rather than an arbitrary subset that changes
	// between events.
	if (*calls)[0].ip != "172.16.80.0" {
		t.Errorf("truncation must keep the first N in configured order; got %s first",
			(*calls)[0].ip)
	}
}

func TestThePoolAnnounceStopsWhenOwnershipMovesAgain8405(t *testing.T) {
	// stillValid is the ownership fence the VIP burst already honours. An
	// announce that kept going after ownership moved would be telling the
	// upstream to send us traffic we no longer own — the same harm as the
	// wrong-RG case, arriving mid-loop.
	calls := captureGARP8405(t)
	d := &Daemon{}
	valid := true
	d.announceProxyARPPoolAddresses(
		cfgWithPoolProxyARP8405(1, "172.16.80.7/32", "172.16.80.8/32", "172.16.80.9/32"),
		1,
		func() bool { defer func() { valid = false }(); return valid },
	)
	if len(*calls) > 1 {
		t.Errorf("the announce must stop as soon as stillValid goes false; sent %d",
			len(*calls))
	}
}

func TestIPv6PoolAddressesAreNotAnnouncedThroughTheV4Path8405(t *testing.T) {
	// An unsolicited NA, not an ARP. Absent from the v4 burst is honest;
	// announcing a v6 address through the v4 burst would be silently wrong.
	calls := captureGARP8405(t)
	// #12172 added the v6 NA branch to this announcer; stub it so the
	// control stays hermetic (no real unsolicited NAs from unit tests).
	naCalls := captureNA12172(t)
	d := &Daemon{}
	d.announceProxyARPPoolAddresses(
		cfgWithPoolProxyARP8405(1, "2001:db8::7/128", "172.16.80.7/32"), 1, nil)
	if len(*calls) != 1 || (*calls)[0].ip != "172.16.80.7" {
		t.Errorf("only the v4 address may go out through the ARP path; got %v", *calls)
	}
	if len(*naCalls) != 1 || (*naCalls)[0].ip != "2001:db8::7" {
		t.Errorf("the v6 address must go out through the NA path; got %v", *naCalls)
	}
}
