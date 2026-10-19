package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func proxyARPCfg9237(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces ge-0/0/2 unit 80 family inet address 172.16.80.1/24",
		"set security nat source pool p1 address 172.16.80.7/32",
		"set security nat proxy-arp interface ge-0/0/2.80 address 172.16.80.7",
	} {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		tree.SetPath(p)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

// #9237: a responder whose goroutine exited (the socket open failed) must be
// EVICTED and restarted, not treated as running forever.
//
// The entry is published before the socket opens, so a failure leaves a member
// that owns nothing — and the running branch then swaps the address snapshot
// rather than restarting, on reasoning that is correct only for a responder
// that IS running. Neither the apply path nor the 30s reassert owner could
// recover it.
//
// Drives syncProxyARPResponders directly: it is the reconcile's worker and
// holds BOTH the sweep and the running-branch the sweep has to beat, while
// reconcileProxyARP itself resolves interface names through netlink, which a
// unit test cannot reach. The reconcile -> sync wiring is already bound by
// TestReconcileProxyARPStopsResponderOnRemoval's stop path.
//
// RED ON REVERT: remove the eviction sweep and the dead entry survives every
// reconcile, with the startup log still saying "started".
func TestDeadResponderIsEvictedAndRestarted9237(t *testing.T) {
	d := &Daemon{arpResponders: newProxyARPResponders()}
	cfg := proxyARPCfg9237(t)

	// A responder whose goroutine has already exited: `done` is closed, exactly
	// as runProxyARPResponder's `defer close(r.done)` leaves it after a failed
	// OpenARPSocket.
	_, cancel := context.WithCancel(context.Background())
	dead := &proxyARPResponder{
		cancel:   cancel,
		done:     make(chan struct{}),
		junosRef: "ge-0/0/2.80",
		addrs:    map[string]struct{}{"172.16.80.7": {}},
	}
	close(dead.done)
	d.arpResponders.running["ge-0-0-2.80"] = dead

	d.syncProxyARPResponders(cfg, map[string][]string{"ge-0-0-2.80": {"ge-0/0/2.80"}})

	cur, ok := d.arpResponders.running["ge-0-0-2.80"]
	if !ok {
		t.Fatal("#9237: the dead responder was evicted but NOT restarted — the interface " +
			"is still configured for proxy-arp, so nothing answers for the pool address")
	}
	if cur == dead {
		t.Error("#9237: the dead responder is still the map entry after a reconcile. It owns " +
			"no socket, answers nothing, and the running branch will keep swapping its " +
			"address snapshot forever — config removal or a daemon restart is the only exit.")
	}
	select {
	case <-cur.done:
		t.Error("#9237: the replacement is already dead")
	default:
	}
}

// A LIVE responder must NOT be evicted. Eviction that fired on healthy entries
// would restart the socket on every 30s reassert — dropping requests during
// each rebuild, which is exactly what the running-branch optimisation exists to
// avoid, and it would look like a fix while making things worse.
func TestLiveResponderIsNotEvicted9237(t *testing.T) {
	d := &Daemon{arpResponders: newProxyARPResponders()}
	_, cancel := context.WithCancel(context.Background())
	live := &proxyARPResponder{
		cancel:   cancel,
		done:     make(chan struct{}), // OPEN: still running
		junosRef: "ge-0/0/2.80",
		addrs:    map[string]struct{}{"172.16.80.7": {}},
	}
	d.arpResponders.running["ge-0-0-2.80"] = live

	d.syncProxyARPResponders(proxyARPCfg9237(t), map[string][]string{"ge-0-0-2.80": {"ge-0/0/2.80"}})

	if cur := d.arpResponders.running["ge-0-0-2.80"]; cur != live {
		t.Error("#9237: a LIVE responder was replaced. Restarting a healthy responder drops " +
			"requests during the socket rebuild on every reassert tick — the harm the " +
			"running-branch optimisation exists to prevent.")
	}
}

// The invariant after a sweep: whatever is in the map is not a corpse.
//
// THIS DOES NOT EXERCISE THE POINTER-IDENTITY COMPARISON, and says so rather
// than implying otherwise. The sweep re-reads the map it is iterating under the
// mutex it already holds, so the compared pointers cannot differ; a mutant that
// drops the comparison SURVIVES. That comparison is defensive against a future
// change moving eviction off this path, where a dead responder deleting a
// replacement becomes reachable — an intermittently missing responder, not a
// crash. An earlier version of this cell claimed to test it and was vacuous:
// it put only the replacement in the map, so the sweep never reached a dead
// entry at all.
func TestNoCorpseSurvivesASweep9237(t *testing.T) {
	d := &Daemon{arpResponders: newProxyARPResponders()}
	for _, name := range []string{"ge-0-0-2.80", "ge-0-0-3.90"} {
		_, cancel := context.WithCancel(context.Background())
		r := &proxyARPResponder{
			cancel: cancel, done: make(chan struct{}),
			junosRef: "ge-0/0/2.80",
			addrs:    map[string]struct{}{"172.16.80.7": {}},
		}
		close(r.done)
		d.arpResponders.running[name] = r
	}
	// Only the first is still wanted; the second must be stopped, not restarted.
	d.syncProxyARPResponders(proxyARPCfg9237(t), map[string][]string{"ge-0-0-2.80": {"ge-0/0/2.80"}})

	for name, r := range d.arpResponders.running {
		select {
		case <-r.done:
			t.Errorf("#9237: %s is still a corpse after a sweep — it owns no socket and "+
				"answers nothing, while every status channel reports healthy", name)
		default:
		}
	}
	if _, ok := d.arpResponders.running["ge-0-0-3.90"]; ok {
		t.Error("#9237: a responder the config no longer wants was restarted by the sweep. " +
			"A death must not re-arm retry debt for an interface that is gone.")
	}
}
