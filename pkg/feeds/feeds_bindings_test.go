package feeds

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// installPrefixes seeds a feed's active snapshot directly so SnapshotForBindings
// has live prefixes to resolve, mirroring what a successful fetch would do.
func (m *Manager) installPrefixes(name string, prefixes []string) {
	fs := m.newFeed(name, "http://example.test/"+name, retainForever)
	m.mu.Lock()
	cp := make([]string, len(prefixes))
	copy(cp, prefixes)
	fs.prefixes = cp
	fs.hasSnapshot = true
	m.mu.Unlock()
}

func bindingCfg(bindings map[string][]string) *config.DynamicAddressConfig {
	ab := make(map[string]*config.AddressBinding, len(bindings))
	for name, feedNames := range bindings {
		ab[name] = &config.AddressBinding{Name: name, FeedNames: feedNames}
	}
	return &config.DynamicAddressConfig{AddressBindings: ab}
}

func TestSnapshotForBindingsResolvesSingleFeed(t *testing.T) {
	m := New(nil)
	m.installPrefixes("threat-feed", []string{"198.51.100.0/24", "203.0.113.0/24"})

	got := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"bad-actors": {"threat-feed"},
	}))
	want := map[string][]string{
		"bad-actors": {"198.51.100.0/24", "203.0.113.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SnapshotForBindings = %v, want %v", got, want)
	}
}

func TestSnapshotForBindingsUnionsAndDedupsMultipleFeeds(t *testing.T) {
	m := New(nil)
	m.installPrefixes("feed-a", []string{"198.51.100.0/24", "10.0.0.0/8"})
	m.installPrefixes("feed-b", []string{"203.0.113.0/24", "10.0.0.0/8"}) // 10/8 overlaps feed-a

	got := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"aggregate": {"feed-a", "feed-b"},
	}))
	want := []string{"10.0.0.0/8", "198.51.100.0/24", "203.0.113.0/24"}
	sort.Strings(want)
	if !reflect.DeepEqual(got["aggregate"], want) {
		t.Fatalf("aggregate = %v, want deduped union %v", got["aggregate"], want)
	}
}

func TestSnapshotForBindingsOmitsUnresolvedFeed(t *testing.T) {
	m := New(nil)
	// "missing-feed" was never started/fetched, so the binding resolves to no
	// enforceable prefixes. #5645: the binding name is OMITTED from the overlay
	// entirely (unresolved) rather than published as a present-but-empty
	// (match-none) slice — publishing match-none made a DENY policy referencing
	// the name fail OPEN before the first fetch. Omitting it leaves the name
	// unresolved so the policy lowering fails CLOSED (unrepresentable ->
	// __unsupported_address__ -> whole-snapshot reject). This also covers the
	// unknown/typo'd-feed case (an unknown name is treated like an unready feed).
	got := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"pending": {"missing-feed"},
	}))
	if _, ok := got["pending"]; ok {
		t.Fatalf("an unresolved feed-backed binding must be OMITTED from the overlay "+
			"(fail-closed), not published as match-none; got %v", got)
	}
}

func TestSnapshotForBindingsNilWithoutBindings(t *testing.T) {
	m := New(nil)
	if got := m.SnapshotForBindings(nil); got != nil {
		t.Fatalf("nil config must yield nil overlay, got %v", got)
	}
	if got := m.SnapshotForBindings(&config.DynamicAddressConfig{}); got != nil {
		t.Fatalf("no bindings must yield nil overlay, got %v", got)
	}
}

// TestSnapshotForBindingsDeepCopy proves the returned slices are independent of
// the manager's internal state — a caller mutation must not corrupt the feed.
func TestSnapshotForBindingsDeepCopy(t *testing.T) {
	m := New(nil)
	m.installPrefixes("feed", []string{"198.51.100.0/24"})
	got := m.SnapshotForBindings(bindingCfg(map[string][]string{"name": {"feed"}}))
	got["name"][0] = "0.0.0.0/0" // mutate the caller's copy

	again := m.SnapshotForBindings(bindingCfg(map[string][]string{"name": {"feed"}}))
	if again["name"][0] != "198.51.100.0/24" {
		t.Fatalf("manager state corrupted by caller mutation: %v", again["name"])
	}
}

// TestSnapshotForBindingsOmitsWholeSpaceUnion14392 is #14392 (DR7-H5): two
// feeds each serving one half of a family (0.0.0.0/1 + 128.0.0.0/1) pass the
// per-feed whole-space refusal in parseFeed (#10711), but their binding
// UNION covers the whole family. The enforcement unit is the union, so the
// binding must be omitted (fail-closed, #5645) instead of publishing
// permit-all / deny-all. A single feed serving both halves is already
// refused at parse (feed_union_10711_test.go); disjoint feeds must still
// union and enforce.
func TestSnapshotForBindingsOmitsWholeSpaceUnion14392(t *testing.T) {
	t.Run("ipv4 halves omitted", func(t *testing.T) {
		m := New(nil)
		m.installPrefixes("feed-a", []string{"0.0.0.0/1"})
		m.installPrefixes("feed-b", []string{"128.0.0.0/1"})
		got := m.SnapshotForBindings(bindingCfg(map[string][]string{
			"blocked": {"feed-a", "feed-b"},
		}))
		if _, ok := got["blocked"]; ok {
			t.Fatalf("whole-space union published as %v; binding must be omitted (#14392)", got["blocked"])
		}
	})
	t.Run("ipv6 halves omitted", func(t *testing.T) {
		m := New(nil)
		m.installPrefixes("feed-a", []string{"::/1"})
		m.installPrefixes("feed-b", []string{"8000::/1"})
		got := m.SnapshotForBindings(bindingCfg(map[string][]string{
			"blocked6": {"feed-a", "feed-b"},
		}))
		if _, ok := got["blocked6"]; ok {
			t.Fatalf("whole-space IPv6 union published as %v; binding must be omitted (#14392)", got["blocked6"])
		}
	})
	t.Run("disjoint feeds still union", func(t *testing.T) {
		m := New(nil)
		m.installPrefixes("feed-a", []string{"198.51.100.0/24"})
		m.installPrefixes("feed-b", []string{"203.0.113.0/24"})
		got := m.SnapshotForBindings(bindingCfg(map[string][]string{
			"blocked": {"feed-a", "feed-b"},
		}))
		want := []string{"198.51.100.0/24", "203.0.113.0/24"}
		if !reflect.DeepEqual(got["blocked"], want) {
			t.Fatalf("disjoint union = %v, want %v", got["blocked"], want)
		}
	})
	t.Run("partial halves still union", func(t *testing.T) {
		m := New(nil)
		m.installPrefixes("feed-a", []string{"0.0.0.0/1"})
		m.installPrefixes("feed-b", []string{"128.0.0.0/2"})
		got := m.SnapshotForBindings(bindingCfg(map[string][]string{
			"blocked": {"feed-a", "feed-b"},
		}))
		want := []string{"0.0.0.0/1", "128.0.0.0/2"}
		if !reflect.DeepEqual(got["blocked"], want) {
			t.Fatalf("partial union = %v, want %v", got["blocked"], want)
		}
	})
	t.Run("fail-mode drop empty row unaffected", func(t *testing.T) {
		// coversWholeAddressSpace([]) is false, so the #9689 drop+all-hold-
		// dropped present-but-empty row must survive the union check.
		m := New(nil)
		holdDrop9689(t, m, "partner-feed", []string{"198.51.100.0/24"})
		got, ok := m.SnapshotForBindings(failModeCfg9689("drop", "partner-feed"))["partners"]
		if !ok {
			t.Fatal("fail-mode drop omitted a hold-dropped binding; it must be published as an empty set")
		}
		if len(got) != 0 {
			t.Fatalf("fail-mode drop row = %v, want empty", got)
		}
	})
}
