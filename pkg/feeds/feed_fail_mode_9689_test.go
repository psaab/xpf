package feeds

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// holdDrop9689 installs prefixes on a feed with a one-minute hold interval,
// then fails it past the hold so recordFailure drops it to empty.
func holdDrop9689(t *testing.T, m *Manager, name string, prefixes []string) *feedState {
	t.Helper()
	fs := m.newFeed(name, "http://example.test/"+name, time.Minute)
	m.mu.Lock()
	fs.prefixes = append([]string(nil), prefixes...)
	fs.hasSnapshot = true
	m.mu.Unlock()
	base := time.Now()
	m.now = func() time.Time { return base }
	m.recordFailure(fs, errors.New("fetch failed"))
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	m.recordFailure(fs, errors.New("fetch failed"))
	if len(fs.prefixes) != 0 || !fs.holdDropped {
		t.Fatalf("fixture: feed %s was not dropped by its hold interval", name)
	}
	return fs
}

func failModeCfg9689(mode string, feedNames ...string) *config.DynamicAddressConfig {
	return &config.DynamicAddressConfig{AddressBindings: map[string]*config.AddressBinding{
		"partners": {Name: "partners", FeedNames: feedNames, FailMode: mode},
	}}
}

// TestRetainModeOmitsAHoldDroppedBinding9689: the default is unchanged. A
// binding whose feed was hold-dropped is omitted, so its policies fail closed
// (#5645).
func TestRetainModeOmitsAHoldDroppedBinding9689(t *testing.T) {
	for _, mode := range []string{"", "retain"} {
		m := New(nil)
		holdDrop9689(t, m, "partner-feed", []string{"198.51.100.0/24"})
		if got, ok := m.SnapshotForBindings(failModeCfg9689(mode, "partner-feed"))["partners"]; ok {
			t.Errorf("fail-mode %q published a hold-dropped binding (%v); it must stay omitted", mode, got)
		}
	}
}

// TestDropModePublishesAnEmptyRowAfterAHoldDrop9689: under drop the binding is
// PRESENT and empty, which lowers to match-none instead of the whole-snapshot
// reject.
func TestDropModePublishesAnEmptyRowAfterAHoldDrop9689(t *testing.T) {
	m := New(nil)
	holdDrop9689(t, m, "partner-feed", []string{"198.51.100.0/24"})
	got, ok := m.SnapshotForBindings(failModeCfg9689("drop", "partner-feed"))["partners"]
	if !ok {
		t.Fatal("fail-mode drop omitted a hold-dropped binding; it must be published as an empty set")
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("fail-mode drop published %#v, want a present empty slice", got)
	}
}

// TestDropModeStillOmitsAFeedThatNeverFetched9689: drop covers a feed that was
// dropped by its hold interval, never one with no first snapshot or an unknown
// name. Those keep the #5645 fail-closed omission.
func TestDropModeStillOmitsAFeedThatNeverFetched9689(t *testing.T) {
	m := New(nil)
	m.newFeed("not-yet", "http://example.test/not-yet", time.Minute)
	if _, ok := m.SnapshotForBindings(failModeCfg9689("drop", "not-yet"))["partners"]; ok {
		t.Error("fail-mode drop published a binding whose feed never fetched")
	}
	if _, ok := m.SnapshotForBindings(failModeCfg9689("drop", "no-such-feed"))["partners"]; ok {
		t.Error("fail-mode drop published a binding naming an unknown feed")
	}
	holdDrop9689(t, m, "dropped", []string{"203.0.113.0/24"})
	if _, ok := m.SnapshotForBindings(failModeCfg9689("drop", "dropped", "not-yet"))["partners"]; ok {
		t.Error("fail-mode drop published a binding with one hold-dropped and one never-fetched feed")
	}
}

// TestDropModePublishesTheFeedsThatRemain9689: a dropped feed contributes
// nothing, and the other feeds still contribute theirs.
func TestDropModePublishesTheFeedsThatRemain9689(t *testing.T) {
	m := New(nil)
	m.installPrefixes("live", []string{"192.0.2.0/24"})
	holdDrop9689(t, m, "dropped", []string{"203.0.113.0/24"})
	got := m.SnapshotForBindings(failModeCfg9689("drop", "live", "dropped"))["partners"]
	if !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("fail-mode drop published %v, want only the live feed's prefixes", got)
	}
	if _, ok := m.SnapshotForBindings(failModeCfg9689("retain", "live", "dropped"))["partners"]; ok {
		t.Fatal("fail-mode retain published a binding with a hold-dropped constituent")
	}
}

// TestASuccessfulFetchClearsTheHoldDrop9689: recovery returns the binding to
// normal, and the status surface stops reporting the drop.
func TestASuccessfulFetchClearsTheHoldDrop9689(t *testing.T) {
	m := New(func() error { return nil })
	fs := holdDrop9689(t, m, "partner-feed", []string{"198.51.100.0/24"})
	if !m.AllFeeds()["partner-feed"].HoldDropped {
		t.Fatal("AllFeeds does not report the hold drop")
	}
	m.installSnapshot(fs, fetchResult{prefixes: []string{"198.51.100.0/24"}})
	if fs.holdDropped || m.AllFeeds()["partner-feed"].HoldDropped {
		t.Fatal("a successful fetch did not clear the hold-drop marker")
	}
	got := m.SnapshotForBindings(failModeCfg9689("retain", "partner-feed"))["partners"]
	if !reflect.DeepEqual(got, []string{"198.51.100.0/24"}) {
		t.Fatalf("after recovery the binding resolves to %v", got)
	}
}
