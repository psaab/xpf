package ddns

import (
	"net/http"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6754: the HTTP DDNS client cache keys on the RAW binding leaves, but the
// device a client is actually bound to is RESOLVED — bindDevice comes from
// config.ResolveKernelIfName, whose output is a function of the whole committed
// config (reth→physical member, the tunnel name map, the IRB→bridge map,
// SecureTunnelUnitNetdev, unit-vs-vlan-id).
//
// So the resolved device can change while all three key leaves stay
// byte-identical: move reth0's active member and `destination-interface
// reth0.50` keeps its key, keeps its cached client, and silently keeps
// SO_BINDTODEVICE on the OLD physical device. Nothing errors — the publish just
// egresses from the wrong interface.
//
// The cache key is deliberately NOT changed to the resolved value: the #2956
// reap keys on the binding leaves, and re-keying would decouple the two. The
// fix validates the resolution on a HIT instead, which is the check the raw key
// structurally cannot make.

// resolverReturning6754 is a committed-config interface resolver whose answer
// the test can change between calls, standing in for a commit that moves a
// reth's active member without touching any DDNS binding leaf.
func resolverReturning6754(dev *string) func(string) string {
	return func(string) string { return *dev }
}

// TestChangedResolutionRebuildsTheBoundClient6754 is the defect proper.
func TestChangedResolutionRebuildsTheBoundClient6754(t *testing.T) {
	c := newHTTPClientCache()
	dev := "eth0"
	p := &config.DDNSProvider{
		Name: "p", Backend: "generic",
		RFC2136Endpoint: config.RFC2136Endpoint{
			DestinationInterface: "reth0.50",
		},
	}

	first, err := c.clientFor(p, resolverReturning6754(&dev))
	if err != nil {
		t.Fatalf("clientFor (first): %v", err)
	}

	// Same provider, same leaves, same cache key — but the committed config now
	// resolves reth0.50 to a different physical member.
	if got := bindCacheKey(p); got != bindCacheKey(p) {
		t.Fatal("precondition: the cache key must be stable across the change")
	}
	dev = "eth1"

	second, err := c.clientFor(p, resolverReturning6754(&dev))
	if err != nil {
		t.Fatalf("clientFor (second): %v", err)
	}

	if second == first {
		t.Errorf("the cached client was reused after the RESOLVED bind device changed " +
			"eth0 -> eth1 with every raw binding leaf unchanged: the provider keeps " +
			"publishing with SO_BINDTODEVICE on the old device, and nothing reports it")
	}

	// And the rebuilt client must be the one now cached — a rebuild that does not
	// replace the entry would rebuild on EVERY call, throwing away the keep-alive
	// pool #2904 exists to preserve.
	third, err := c.clientFor(p, resolverReturning6754(&dev))
	if err != nil {
		t.Fatalf("clientFor (third): %v", err)
	}
	if third != second {
		t.Errorf("the rebuilt client was not cached: a stable resolution rebuilt again "+
			"(%p then %p), which discards the connection pool on every publish", second, third)
	}
	if c.size() != 1 {
		t.Errorf("cache size = %d, want 1 — the rebuild must REPLACE the entry under the "+
			"same key, not accumulate one per resolution", c.size())
	}
}

// TestStaleTransportIsReleasedOnRebuild6754 pins the leak half. The #2956 reap
// keys on the binding leaves, which have NOT changed here, so it would never
// collect the superseded transport — the rebuild has to release it.
func TestStaleTransportIsReleasedOnRebuild6754(t *testing.T) {
	var closed []*http.Client
	orig := closeIdleConns
	closeIdleConns = func(cl *http.Client) { closed = append(closed, cl); orig(cl) }
	defer func() { closeIdleConns = orig }()

	c := newHTTPClientCache()
	dev := "eth0"
	p := &config.DDNSProvider{Name: "p", Backend: "generic", RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "reth0.50"}}

	first, err := c.clientFor(p, resolverReturning6754(&dev))
	if err != nil {
		t.Fatalf("clientFor (first): %v", err)
	}
	dev = "eth1"
	if _, err := c.clientFor(p, resolverReturning6754(&dev)); err != nil {
		t.Fatalf("clientFor (second): %v", err)
	}

	found := false
	for _, cl := range closed {
		if cl == first {
			found = true
		}
	}
	if !found {
		t.Errorf("the superseded client's idle pool was not released on rebuild. Its cache " +
			"key is unchanged, so the #2956 reap will never collect it — the stale " +
			"*http.Transport lingers for the daemon lifetime")
	}
}

// TestUnchangedResolutionKeepsThePool6754 is the TIGHTENING control.
//
// A "fix" that rebuilt on every call would satisfy both tests above while
// destroying the #2904 keep-alive pool the cache exists for — the Surface A
// reconcile loop calls clientFor every pass. This pins the other side: a stable
// resolution must return the SAME client, and must not close anything.
func TestUnchangedResolutionKeepsThePool6754(t *testing.T) {
	var closed []*http.Client
	orig := closeIdleConns
	closeIdleConns = func(cl *http.Client) { closed = append(closed, cl); orig(cl) }
	defer func() { closeIdleConns = orig }()

	c := newHTTPClientCache()
	dev := "eth0"
	p := &config.DDNSProvider{Name: "p", Backend: "generic", RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "reth0.50"}}

	var prev *http.Client
	for i := 0; i < 5; i++ {
		cl, err := c.clientFor(p, resolverReturning6754(&dev))
		if err != nil {
			t.Fatalf("clientFor (pass %d): %v", i, err)
		}
		if prev != nil && cl != prev {
			t.Fatalf("pass %d rebuilt the client although the resolution never changed: the "+
				"Surface A reconcile calls this every pass, so this throws away the "+
				"keep-alive connection pool #2904 exists to preserve", i)
		}
		prev = cl
	}
	if len(closed) != 0 {
		t.Errorf("closed %d idle pools with no resolution change, want 0", len(closed))
	}
}

// TestUnboundProviderIsUnaffected6754 pins that the no-binding path — the common
// case, where there is nothing to resolve — still caches on the empty key.
func TestUnboundProviderIsUnaffected6754(t *testing.T) {
	c := newHTTPClientCache()
	p := &config.DDNSProvider{Name: "p", Backend: "generic"}

	a, err := c.clientFor(p)
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}
	b, err := c.clientFor(p)
	if err != nil {
		t.Fatalf("clientFor (2): %v", err)
	}
	if a != b {
		t.Error("an unbound provider rebuilt its client between calls; there is no resolution " +
			"to change, so the cache must be a straight hit")
	}
}
