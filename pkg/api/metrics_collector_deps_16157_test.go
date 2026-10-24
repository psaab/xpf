package api

import (
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/feeds"
)

// #16157: the collector must not reach the whole Server. These pins fail
// if the srv field (or any *Server-typed field) returns to xpfCollector,
// if collectorDeps drops a dependency the old c.srv reads used, or if
// newCollector stops bridging a wired Server hook into the seam — the
// last would silently omit a metric family on the production scrape.

func TestCollectorHasNoServerField16157(t *testing.T) {
	typ := reflect.TypeOf(xpfCollector{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Name == "srv" {
			t.Fatalf("xpfCollector regained an srv field (%s); the collector must depend on collectorDeps only", f.Type)
		}
		if f.Type == reflect.TypeOf(&Server{}) {
			t.Fatalf("xpfCollector field %s is *Server; the collector must depend on collectorDeps only", f.Name)
		}
	}
	depsField, ok := typ.FieldByName("deps")
	if !ok || depsField.Type != reflect.TypeOf(collectorDeps{}) {
		t.Fatalf("xpfCollector.deps = %v (present %v), want collectorDeps", depsField.Type, ok)
	}
}

func TestCollectorDepsFromNilServer16157(t *testing.T) {
	deps := collectorDepsFromServer(nil)
	if !reflect.DeepEqual(deps, collectorDeps{}) {
		t.Fatalf("collectorDepsFromServer(nil) = %+v, want zero collectorDeps", deps)
	}
	if cfg := deps.activeConfig(); cfg != nil {
		t.Fatalf("zero deps activeConfig = %v, want nil", cfg)
	}
	var bare collectorDeps
	if cfg := bare.activeConfig(); cfg != nil {
		t.Fatalf("bare collectorDeps activeConfig = %v, want nil (no store wired)", cfg)
	}
}

func TestNewCollectorBridgesServerDeps16157(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	now := time.Now()
	sentinel := 0
	srv := &Server{
		store:                   store,
		startTime:               now,
		configPersistDegradedFn: func() bool { sentinel++; return true },
		feedsFn:                 func() map[string]feeds.FeedInfo { return nil },
	}
	_ = sentinel
	c := newCollector(srv)
	if c.deps.store != store {
		t.Fatal("newCollector did not bridge Server.store into collectorDeps")
	}
	if !c.deps.startTime.Equal(now) {
		t.Fatalf("newCollector bridged startTime %v, want %v", c.deps.startTime, now)
	}
	if c.deps.configPersistDegradedFn == nil || !c.deps.configPersistDegradedFn() {
		t.Fatal("newCollector did not bridge Server.configPersistDegradedFn into collectorDeps")
	}
	if c.deps.feedsFn == nil {
		t.Fatal("newCollector did not bridge Server.feedsFn into collectorDeps")
	}
	if c.deps.restConnRefusals == nil || c.deps.restConnActive == nil {
		t.Fatal("newCollector did not bridge the REST conn-gate accessors into collectorDeps")
	}
	// A bare Server has no conn gate: the bridged accessors keep the old
	// nil-gate 0 rather than panicking.
	if got := c.deps.restConnRefusals(); got != 0 {
		t.Fatalf("bare-server restConnRefusals = %d, want 0", got)
	}
	if got := c.deps.restConnActive(); got != 0 {
		t.Fatalf("bare-server restConnActive = %d, want 0", got)
	}
	if cfg := c.deps.activeConfig(); cfg == nil {
		t.Fatal("bridged deps activeConfig = nil, want the store's active config")
	}
}
