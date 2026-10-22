package appid

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type fallbackCellApp struct {
	name, proto, dstPort string
}

func fallbackCellConfig(apps []fallbackCellApp, appID bool, refs []string) *config.Config {
	byName := make(map[string]*config.Application, len(apps))
	for _, app := range apps {
		byName[app.name] = &config.Application{
			Name: app.name, Protocol: app.proto, DestinationPort: app.dstPort,
		}
	}
	if len(refs) == 0 {
		refs = []string{"any"}
	}
	cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: byName}}
	cfg.Services.ApplicationIdentification = appID
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:  "fallback-index-test",
		Match: config.PolicyMatch{Applications: refs},
	}}
	return cfg
}

func fallbackCatalogWinner(cat Catalog, proto uint8, srcPort, dstPort uint16) string {
	var best CatalogEntry
	bestPortBased := false
	found := false
	inRange := func(port, lo, hi uint16) bool {
		return (lo == 0 && hi == 0) || (port >= lo && port <= hi)
	}
	for _, entry := range cat.Entries {
		if entry.Protocol != proto || !inRange(srcPort, entry.SrcPortLow, entry.SrcPortHigh) ||
			!inRange(dstPort, entry.DstPortLow, entry.DstPortHigh) {
			continue
		}
		portBased := entry.SrcPortLow != 0 || entry.SrcPortHigh != 0 || entry.DstPortLow != 0 || entry.DstPortHigh != 0
		if !found || (portBased && !bestPortBased) ||
			(portBased == bestPortBased && entry.AppID < best.AppID) {
			best = entry
			bestPortBased = portBased
			found = true
		}
	}
	if !found {
		return Unknown
	}
	return cat.AppNames[best.AppID]
}

func TestUnreferencedCollisionEdgeCells_12225(t *testing.T) {
	cases := []struct {
		name     string
		apps     []fallbackCellApp
		proto    uint8
		src, dst uint16
		want     string
		wantOnID config.AssignedAppID
	}{
		{
			name: "predefined-collider",
			apps: []fallbackCellApp{
				{name: "collider-1057", proto: "tcp", dstPort: "9100"},
				{name: "mmm-middle", proto: "tcp", dstPort: "9100"},
			},
			proto: 6, src: 40000, dst: 9100, want: "collider-1057", wantOnID: 1,
		},
		{
			name: "five-name-mixed",
			apps: []fallbackCellApp{
				{name: "svc-396", proto: "tcp", dstPort: "9000"},
				{name: "mmm-middle", proto: "tcp", dstPort: "9000"},
				{name: "nnn-x", proto: "tcp", dstPort: "9000"},
				{name: "ooo-y", proto: "tcp", dstPort: "9000"},
				{name: "svc-217", proto: "tcp", dstPort: "9999"},
			},
			proto: 6, src: 40000, dst: 9000, want: "svc-396", wantOnID: 1,
		},
		{
			name: "mixed-specificity-tier",
			apps: []fallbackCellApp{
				{name: "svc-217", proto: "tcp", dstPort: "8080"},
				{name: "svc-396", proto: "tcp", dstPort: "8080"},
				{name: "collider-1057", proto: "tcp"},
			},
			proto: 6, src: 40000, dst: 8080, want: "svc-396", wantOnID: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			onCfg := fallbackCellConfig(tc.apps, true, nil)
			onCat, err := BuildCatalog(onCfg)
			if err != nil {
				t.Fatalf("BuildCatalog (AppID on): %v", err)
			}
			offCfg := fallbackCellConfig(tc.apps, false, nil)
			offCat, err := BuildCatalog(offCfg)
			if err != nil {
				t.Fatalf("BuildCatalog (AppID off): %v", err)
			}
			if len(offCat.AppNames) != 0 {
				t.Fatalf("application any must leave the AppID-off catalog empty, got %v", offCat.AppNames)
			}
			if got := fallbackCatalogWinner(onCat, tc.proto, tc.src, tc.dst); got != tc.want {
				t.Fatalf("AppID-on catalog winner = %q, want %q", got, tc.want)
			}
			if got := idOfName(onCat, tc.want); got != tc.wantOnID {
				t.Fatalf("full-catalog assigned id for %q = %d, want %d", tc.want, got, tc.wantOnID)
			}
			index := NewFallbackIndex(offCfg)
			for range 100 {
				if got := ResolveSessionNameWithIndex(offCat.AppNames, offCfg, index, tc.proto, tc.src, tc.dst, 0); got != tc.want {
					t.Fatalf("AppID-off fallback = %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestReferencedCollidingTiesKeepOffStamp_12225(t *testing.T) {
	p := func(name, port string) fallbackCellApp {
		return fallbackCellApp{name: name, proto: "tcp", dstPort: port}
	}
	cases := []struct {
		name            string
		apps            []fallbackCellApp
		refs            []string
		dst             uint16
		wantOff, wantOn string
	}{
		{
			name: "S14 unreferenced-user-collider",
			apps: []fallbackCellApp{p("svc-396", "7000"), p("mmm-middle", "7000"), p("svc-217", "9999")},
			refs: []string{"svc-396", "mmm-middle"}, dst: 7000,
			wantOff: "mmm-middle", wantOn: "svc-396",
		},
		{
			name: "S15 referenced-user-collider",
			apps: []fallbackCellApp{p("svc-396", "7000"), p("mmm-middle", "7000"), p("svc-217", "9999")},
			refs: []string{"svc-396", "mmm-middle", "svc-217"}, dst: 7000,
			wantOff: "svc-396", wantOn: "svc-396",
		},
		{
			name: "S16 unreferenced-predefined-collider",
			apps: []fallbackCellApp{p("collider-1057", "9100"), p("mmm-middle", "9100")},
			refs: []string{"collider-1057", "mmm-middle"}, dst: 9100,
			wantOff: "mmm-middle", wantOn: "collider-1057",
		},
		{
			name: "S17 referenced-10722-collision",
			apps: []fallbackCellApp{p("svc-396", "8080"), p("svc-217", "8080"), p("mmm-middle", "8080")},
			refs: []string{"svc-396", "svc-217", "mmm-middle"}, dst: 8080,
			wantOff: "svc-396", wantOn: "svc-396",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			onCfg := fallbackCellConfig(tc.apps, true, tc.refs)
			onCat, err := BuildCatalog(onCfg)
			if err != nil {
				t.Fatalf("BuildCatalog (AppID on): %v", err)
			}
			offCfg := fallbackCellConfig(tc.apps, false, tc.refs)
			offCat, err := BuildCatalog(offCfg)
			if err != nil {
				t.Fatalf("BuildCatalog (AppID off): %v", err)
			}
			proto := uint8(6)
			offStamp := fallbackCatalogWinner(offCat, proto, 40000, tc.dst)
			onStamp := fallbackCatalogWinner(onCat, proto, 40000, tc.dst)
			if offStamp != tc.wantOff || onStamp != tc.wantOn {
				t.Fatalf("catalog stamp labels = off:%q on:%q, want off:%q on:%q", offStamp, onStamp, tc.wantOff, tc.wantOn)
			}
			got := ResolveSessionNameWithIndex(offCat.AppNames, offCfg, NewFallbackIndex(offCfg), proto, 40000, tc.dst, 0)
			if got != offStamp {
				t.Fatalf("unstamped AppID-off fallback = %q, want off-stamp label %q", got, offStamp)
			}
			if tc.name == "S15 referenced-user-collider" || tc.name == "S17 referenced-10722-collision" {
				if got != onStamp {
					t.Fatalf("fully referenced fallback = %q, want unchanged AppID-on/off label %q", got, onStamp)
				}
			}
		})
	}
}

type fallbackWarnRecorder struct {
	mu    sync.Mutex
	warns int
}

func (r *fallbackWarnRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *fallbackWarnRecorder) Handle(_ context.Context, record slog.Record) error {
	if record.Level >= slog.LevelWarn {
		r.mu.Lock()
		r.warns++
		r.mu.Unlock()
	}
	return nil
}
func (r *fallbackWarnRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *fallbackWarnRecorder) WithGroup(string) slog.Handler      { return r }

func TestFallbackIndexQuietOnRepeatedRender_12225(t *testing.T) {
	cfg := fallbackCellConfig([]fallbackCellApp{
		{name: "svc-217", proto: "tcp", dstPort: "8080"},
		{name: "svc-396", proto: "tcp", dstPort: "8080"},
	}, false, nil)
	index := NewFallbackIndex(cfg)
	recorder := &fallbackWarnRecorder{}
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(recorder))
	defer slog.SetDefault(oldLogger)
	for range 50 {
		if got := ResolveSessionNameWithIndex(nil, cfg, index, 6, 40000, 8080, 0); got != "svc-396" {
			t.Fatalf("colliding tie resolved to %q, want svc-396", got)
		}
	}
	recorder.mu.Lock()
	warns := recorder.warns
	recorder.mu.Unlock()
	if warns != 0 {
		t.Fatalf("fallback render emitted %d WARN records over 50 renders", warns)
	}
}

func TestFallbackIndexWarmedCollidingTieAllocations_12225(t *testing.T) {
	cfg := fallbackCellConfig([]fallbackCellApp{
		{name: "svc-217", proto: "tcp", dstPort: "8080"},
		{name: "svc-396", proto: "tcp", dstPort: "8080"},
	}, false, nil)
	index := NewFallbackIndex(cfg)
	if got := ResolveSessionNameWithIndex(nil, cfg, index, 6, 40000, 8080, 0); got != "svc-396" {
		t.Fatalf("warm-up fallback = %q, want svc-396", got)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		_ = ResolveSessionNameWithIndex(nil, cfg, index, 6, 40000, 8080, 0)
	})
	if allocs != 0 {
		t.Fatalf("warmed colliding-tie render allocated %v times per call, want 0", allocs)
	}
	allocs = testing.AllocsPerRun(1000, func() {
		_ = index.Collides("svc-217")
	})
	if allocs != 0 {
		t.Fatalf("FallbackIndex.Collides allocated %v times per call, want 0", allocs)
	}
	if !index.Collides("svc-217") {
		t.Fatal("known colliding name svc-217 was not reported as colliding")
	}
}
func fallbackBenchmarkConfig(b *testing.B, n int, mode string) (*config.Config, *FallbackIndex) {
	b.Helper()
	apps := make(map[string]*config.Application, n+2)
	for i := range n {
		name := fmt.Sprintf("filler-%05d", i)
		apps[name] = &config.Application{
			Name: name, Protocol: "tcp", DestinationPort: fmt.Sprint(20000 + i%20000),
		}
	}
	addCandidate := func(name string) {
		apps[name] = &config.Application{Name: name, Protocol: "tcp", DestinationPort: "8080"}
	}
	switch mode {
	case "single":
		addCandidate("cand-only")
	case "tie-collide":
		addCandidate("svc-217")
		addCandidate("svc-396")
	case "tie-nocollide":
		picked := 0
		for i := 0; picked < 2; i++ {
			name := fmt.Sprintf("cand-%d", i)
			if NewFallbackIndex(&config.Config{
				Applications: config.ApplicationsConfig{Applications: apps},
			}).Collides(name) {
				continue
			}
			addCandidate(name)
			if NewFallbackIndex(&config.Config{
				Applications: config.ApplicationsConfig{Applications: apps},
			}).Collides(name) {
				delete(apps, name)
				continue
			}
			picked++
		}
	}
	cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: apps}}
	index := NewFallbackIndex(cfg)
	return cfg, index
}

func BenchmarkFallbackIndex12225(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		for _, mode := range []string{"single", "tie-nocollide", "tie-collide"} {
			b.Run(fmt.Sprintf("N=%d/%s", n, mode), func(b *testing.B) {
				cfg, index := fallbackBenchmarkConfig(b, n, mode)
				if got := ResolveSessionNameWithIndex(nil, cfg, index, 6, 40000, 8080, 0); got == Unknown {
					b.Fatalf("%s fallback did not match", mode)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_ = ResolveSessionNameWithIndex(nil, cfg, index, 6, 40000, 8080, 0)
				}
			})
		}
	}
}
