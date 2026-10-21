package userspace

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1866: a config commit that removes the wgN stanza must produce a
// snapshot WITHOUT the WG tunnel endpoint — the prune signal the Rust
// coordinator's teardown keys on.
func TestBuildTunnelEndpointSnapshotsDropsRemovedWireguard(t *testing.T) {
	withWg := &config.Config{}
	withWg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Name: "wg0",
			Tunnel: &config.TunnelConfig{
				Name:              "wg0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: config.NewSecret("a01010101010101010101010101010101010101010101010101010101010101a"),
				WgPeers: []config.WgPeerConfig{{
					PublicKeyHex: "b02020202020202020202020202020202020202020202020202020202020202b",
					AllowedIPs:   []string{"10.77.0.0/24"},
				}},
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "wg0", LinuxName: "wg0", Ifindex: 42},
	}
	endpoints := buildTunnelEndpointSnapshots(withWg, interfaces)
	if len(endpoints) != 1 || endpoints[0].Mode != "wireguard" {
		t.Fatalf("pre-removal endpoints = %+v, want one wireguard endpoint", endpoints)
	}

	// The removal commit: wg0 gone from the compiled config. The
	// kernel TUN may still exist (documented S2a leak) — the snapshot
	// must NOT resurrect the endpoint from it.
	removed := &config.Config{}
	removed.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1"},
	}
	endpoints = buildTunnelEndpointSnapshots(removed, interfaces)
	if len(endpoints) != 0 {
		t.Fatalf("post-removal endpoints = %+v, want none", endpoints)
	}
}

// #2703: a tunnel TTL of 0 is the "use the default 64" sentinel. The
// AF_XDP snapshot emitter must apply that default (mirroring the netlink
// path in pkg/routing/tunnel.go) BEFORE the value reaches the Rust frame
// builders, which write the snapshot TTL straight into the outer IP
// header. Leaving it 0 emits outer TTL/hop-limit 0 → first-hop blackhole.
// An explicitly-configured non-zero TTL must be preserved unchanged.
func TestBuildTunnelEndpointSnapshotsTTLDefault(t *testing.T) {
	mkCfg := func(ttl int) *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name: "gr-0/0/0",
				Tunnel: &config.TunnelConfig{
					Name:        "gr-0/0/0",
					Mode:        "gre",
					Source:      "172.16.50.8",
					Destination: "172.16.50.9",
					TTL:         ttl,
				},
			},
		}
		return cfg
	}
	interfaces := []InterfaceSnapshot{
		{Name: "gr-0/0/0", LinuxName: "gr0", Ifindex: 50},
	}

	// TTL unset (0) → defaulted to 64. Fail-on-revert: raw passthrough
	// keeps 0 here, which the Rust builder writes as outer TTL 0 (blackhole).
	eps := buildTunnelEndpointSnapshots(mkCfg(0), interfaces)
	if len(eps) != 1 {
		t.Fatalf("TTL=0 endpoints = %+v, want exactly one", eps)
	}
	if eps[0].TTL != 64 {
		t.Fatalf("TTL=0 (sentinel) must default to 64, got %d", eps[0].TTL)
	}

	// Explicit non-zero TTL is preserved (the default must not override it).
	eps = buildTunnelEndpointSnapshots(mkCfg(32), interfaces)
	if len(eps) != 1 {
		t.Fatalf("TTL=32 endpoints = %+v, want exactly one", eps)
	}
	if eps[0].TTL != 32 {
		t.Fatalf("explicit TTL=32 must be preserved, got %d", eps[0].TTL)
	}
}

// #1910 r2 Codex High: an interface-level WireGuard tunnel with
// multiple units is ONE persistent TUN with ONE listen port. Now that
// TunnelNameMap resolves every unit ref of an interface-level wg to
// the base device (so every per-unit snapshot row carries the TUN's
// real positive ifindex), per-unit endpoint emission would produce
// two live endpoints with the same ifindex + listen port — the Rust
// populate pass would overwrite tunnel_endpoint_by_ifindex with the
// later id while the second WG control thread tombstones on the
// duplicate UDP bind. Exactly one endpoint (lowest unit ref) must be
// emitted.
func TestBuildTunnelEndpointSnapshotsInterfaceLevelWireguardMultiUnitSingleEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Name: "wg0",
			Tunnel: &config.TunnelConfig{
				Name:              "wg0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: config.NewSecret("a01010101010101010101010101010101010101010101010101010101010101a"),
				WgPeers: []config.WgPeerConfig{{
					PublicKeyHex: "b02020202020202020202020202020202020202020202020202020202020202b",
					AllowedIPs:   []string{"10.77.0.0/24"},
				}},
			},
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
				1: {Number: 1},
			},
		},
	}
	// Post-fix TunnelNameMap shape: BOTH unit rows resolve to the
	// shared persistent TUN device (same LinuxName, same ifindex).
	interfaces := []InterfaceSnapshot{
		{Name: "wg0", LinuxName: "wg0", Ifindex: 42},
		{Name: "wg0.0", LinuxName: "wg0", Ifindex: 42},
		{Name: "wg0.1", LinuxName: "wg0", Ifindex: 42},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, interfaces)
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want exactly one wireguard endpoint", endpoints)
	}
	ep := endpoints[0]
	if ep.Mode != "wireguard" || ep.Interface != "wg0.0" || ep.Ifindex != 42 {
		t.Fatalf("endpoint = %+v, want wireguard endpoint keyed by lowest unit ref wg0.0 with ifindex 42", ep)
	}
	if want := config.StableTunnelEndpointID("wg0.0"); ep.ID != want {
		t.Fatalf("endpoint id = %d, want stable id of lowest unit ref %d", ep.ID, want)
	}

	// The selected ref is a pure function of CONFIG (#1873): if the
	// lowest configured unit's snapshot row is absent the endpoint is
	// dropped — never re-keyed to another unit at runtime, which could
	// diverge the endpoint id across HA nodes. (In practice rows are
	// all-or-nothing: every unit of an interface-level wg shares one
	// LinuxName/ifindex.)
	withoutUnit0 := []InterfaceSnapshot{
		{Name: "wg0.1", LinuxName: "wg0", Ifindex: 42},
	}
	endpoints = buildTunnelEndpointSnapshots(cfg, withoutUnit0)
	if len(endpoints) != 0 {
		t.Fatalf("endpoints without the lowest-unit row = %+v, want none (config-deterministic ref, no runtime re-keying)", endpoints)
	}
}

// #1866 D3: the publish-boundary transition summary must change when
// the WG endpoint set changes and ignore non-WG endpoints.
func TestWgEndpointSetSummaryTransitions(t *testing.T) {
	empty := wgEndpointSetSummary(&ConfigSnapshot{})
	if empty != "" {
		t.Fatalf("empty snapshot summary = %q, want empty", empty)
	}
	if got := wgEndpointSetSummary(nil); got != "" {
		t.Fatalf("nil snapshot summary = %q, want empty", got)
	}
	withWg := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{ID: 2, Interface: "gr-0/0/0", Mode: "gre"},
			{ID: 1, Interface: "wg0", Mode: "wireguard", WgListenPort: 51820, Ifindex: 42},
		},
	}
	got := wgEndpointSetSummary(withWg)
	want := "1:wg0:51820@42"
	if got != want {
		t.Fatalf("summary = %q, want %q (GRE rows excluded)", got, want)
	}
	renamed := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{ID: 1, Interface: "wg1", Mode: "wireguard", WgListenPort: 51820, Ifindex: 43},
		},
	}
	if wgEndpointSetSummary(renamed) == got {
		t.Fatal("rename/ifindex change must change the summary")
	}

	m := &Manager{}
	m.logWgEndpointSetTransitionLocked(withWg, "test")
	if m.lastPublishedWgEndpoints != want {
		t.Fatalf("lastPublishedWgEndpoints = %q, want %q", m.lastPublishedWgEndpoints, want)
	}
	m.logWgEndpointSetTransitionLocked(withWg, "test")
	if m.lastPublishedWgEndpoints != want {
		t.Fatal("unchanged set must keep the recorded summary")
	}
	m.logWgEndpointSetTransitionLocked(&ConfigSnapshot{}, "test")
	if m.lastPublishedWgEndpoints != "" {
		t.Fatalf("removal must record the empty set, got %q", m.lastPublishedWgEndpoints)
	}
}

// #1873 helpers: build a config + interface snapshot set for N GRE
// tunnels by name. Each tunnel gets a unit-0 endpoint.
func tunnelTestConfig(names ...string) (*config.Config, []InterfaceSnapshot) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	interfaces := make([]InterfaceSnapshot, 0, len(names))
	for i, name := range names {
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			Tunnel: &config.TunnelConfig{
				Name:        name,
				Mode:        "gre",
				Source:      "10.0.0.1",
				Destination: fmt.Sprintf("10.0.1.%d", i+1),
			},
		}
		interfaces = append(interfaces, InterfaceSnapshot{
			Name:    name + ".0",
			Ifindex: 100 + i,
		})
	}
	return cfg, interfaces
}

func endpointIDsByInterface(endpoints []TunnelEndpointSnapshot) map[string]uint16 {
	out := make(map[string]uint16, len(endpoints))
	for _, ep := range endpoints {
		out[ep.Interface] = ep.ID
	}
	return out
}

// #1873 core pin: adding or removing one tunnel must not renumber any
// other tunnel. Under the retired positional allocator, removing
// gr-a renumbered gr-b and gr-c; under stable ids they are invariant.
func TestBuildTunnelEndpointSnapshotsStableAcrossAddRemove(t *testing.T) {
	cfgAll, ifAll := tunnelTestConfig("gr-a", "gr-b", "gr-c")
	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAll, ifAll))
	if len(idsAll) != 3 {
		t.Fatalf("baseline endpoints = %v, want 3", idsAll)
	}

	// Remove the FIRST-sorting tunnel — the positional scheme's worst
	// case (every later tunnel shifted).
	cfgRm, ifRm := tunnelTestConfig("gr-b", "gr-c")
	idsRm := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgRm, ifRm))
	for _, name := range []string{"gr-b.0", "gr-c.0"} {
		if idsRm[name] != idsAll[name] {
			t.Fatalf("%s id changed on unrelated removal: %d -> %d", name, idsAll[name], idsRm[name])
		}
	}

	// Add a new tunnel — existing ids invariant again.
	cfgAdd, ifAdd := tunnelTestConfig("gr-a", "gr-b", "gr-c", "gr-d")
	idsAdd := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAdd, ifAdd))
	for name, id := range idsAll {
		if idsAdd[name] != id {
			t.Fatalf("%s id changed on unrelated add: %d -> %d", name, id, idsAdd[name])
		}
	}
	// And ids are the pure hash of the name (HA agreement by
	// construction — no history input).
	for name, id := range idsAdd {
		if want := config.StableTunnelEndpointID(name); id != want {
			t.Fatalf("%s id = %d, want pure hash %d", name, id, want)
		}
	}
}

// #1873 eligibility-flap pin (Codex plan r1 M2 / AGY plan r1): an
// interface absent from the runtime snapshot must remove ONLY its own
// row — every other tunnel's id is identical in both builds.
func TestBuildTunnelEndpointSnapshotsEligibilityFlapDoesNotShiftIDs(t *testing.T) {
	cfg, ifAll := tunnelTestConfig("gr-a", "gr-b", "gr-c")
	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifAll))

	// gr-a's netdev is transiently absent (link flap at build time).
	ifFlap := make([]InterfaceSnapshot, 0, 2)
	for _, snap := range ifAll {
		if snap.Name == "gr-a.0" {
			continue
		}
		ifFlap = append(ifFlap, snap)
	}
	idsFlap := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifFlap))
	if _, present := idsFlap["gr-a.0"]; present {
		t.Fatalf("flapped tunnel still has a row: %v", idsFlap)
	}
	for _, name := range []string{"gr-b.0", "gr-c.0"} {
		if idsFlap[name] != idsAll[name] {
			t.Fatalf("%s id shifted on gr-a flap: %d -> %d", name, idsAll[name], idsFlap[name])
		}
	}
}

// #1873 R-B belt-and-braces: if a colliding pair somehow reaches the
// snapshot builder (commit gate bypassed — e.g. pre-existing lenient
// config), the later-sorting collider is dropped, never double-keyed.
func TestBuildTunnelEndpointSnapshotsDropsLaterSortingCollider(t *testing.T) {
	// wg1408.0 / wg78.0 both fold to 824 (frozen pin in pkg/config).
	cfg, ifAll := tunnelTestConfig("wg1408", "wg78")
	endpoints := buildTunnelEndpointSnapshots(cfg, ifAll)
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want exactly one (collider dropped)", endpoints)
	}
	// Sorted iteration: "wg1408" sorts before "wg78", so wg1408.0 wins.
	if endpoints[0].Interface != "wg1408.0" {
		t.Fatalf("kept %q, want earlier-sorting wg1408.0", endpoints[0].Interface)
	}
	if endpoints[0].ID != config.StableTunnelEndpointID("wg1408.0") {
		t.Fatalf("kept id %d, want %d", endpoints[0].ID, config.StableTunnelEndpointID("wg1408.0"))
	}
}

// #1914 SSOT parity: the builder's configured-name set MUST equal the
// emitter's Name set (before runtime-iface intersect + usedIDs). This pins
// buildTunnelEndpointSnapshots to config.EmitTunnelEndpointNames so the
// commit-time collision gate (which drives Views 2/3 through the emitter)
// and the dataplane builder can never drift (the #1910 r2-r6 drift class).
//
// Methodology: for each corpus config, take the emitter's Name set, build a
// runtime InterfaceSnapshot for every emitted ref (distinct ifindex, no
// fold collision among the corpus names) so the builder's runtime intersect
// is a no-op and no usedIDs drop fires, then assert the builder's emitted
// Interface set equals the emitter's Name set exactly.
func TestEmitTunnelEndpointNamesMatchesBuilder(t *testing.T) {
	mkIface := func(name string, tun *config.TunnelConfig, units map[int]*config.InterfaceUnit) *config.InterfaceConfig {
		return &config.InterfaceConfig{Name: name, Tunnel: tun, Units: units}
	}
	wg := func() *config.TunnelConfig { return &config.TunnelConfig{Mode: "wireguard", WgListenPort: 51820} }
	greComplete := func() *config.TunnelConfig {
		return &config.TunnelConfig{Mode: "gre", Source: "10.0.0.1", Destination: "10.0.0.2"}
	}
	greIncomplete := func() *config.TunnelConfig { return &config.TunnelConfig{Mode: "gre"} }

	corpus := []struct {
		name  string
		cfg   *config.Config
		wantN int // sanity: expected emitted count
	}{
		{
			name: "interface-level-wg-multi-unit-lowest-only",
			cfg: cfgWith(map[string]*config.InterfaceConfig{
				"wg0": mkIface("wg0", wg(), map[int]*config.InterfaceUnit{
					0: {Number: 0}, 1: {Number: 1}, 2: {Number: 2},
				}),
			}),
			wantN: 1, // only wg0.0
		},
		{
			name: "interface-level-wg-no-units-bare",
			cfg: cfgWith(map[string]*config.InterfaceConfig{
				"wg5": mkIface("wg5", wg(), nil),
			}),
			wantN: 1, // bare "wg5"
		},
		{
			name: "non-wg-multi-unit-complete-per-unit",
			cfg: cfgWith(map[string]*config.InterfaceConfig{
				"gr-0/0/0": mkIface("gr-0/0/0", greComplete(), map[int]*config.InterfaceUnit{
					0: {Number: 0}, 3: {Number: 3},
				}),
			}),
			wantN: 2, // gr-0/0/0.0, gr-0/0/0.3
		},
		{
			name: "non-wg-incomplete-dropped",
			cfg: cfgWith(map[string]*config.InterfaceConfig{
				"gr-1/0/0": mkIface("gr-1/0/0", greIncomplete(), nil),
			}),
			wantN: 0, // dropped by src/dest gate
		},
		{
			name: "per-unit-tunnels-mixed",
			cfg: cfgWith(map[string]*config.InterfaceConfig{
				"gr-2/0/0": mkIface("gr-2/0/0", nil, map[int]*config.InterfaceUnit{
					0: {Number: 0, Tunnel: greComplete()},
					1: {Number: 1},                          // no tunnel — not emitted
					2: {Number: 2, Tunnel: greIncomplete()}, // dropped
				}),
			}),
			wantN: 1, // only gr-2/0/0.0
		},
		{
			name: "no-tunnels",
			cfg: cfgWith(map[string]*config.InterfaceConfig{
				"ge-0/0/0": mkIface("ge-0/0/0", nil, map[int]*config.InterfaceUnit{0: {Number: 0}}),
			}),
			wantN: 0,
		},
	}

	for _, tc := range corpus {
		t.Run(tc.name, func(t *testing.T) {
			emitted := config.EmitTunnelEndpointNames(tc.cfg)
			emitNames := make(map[string]struct{}, len(emitted))
			ifaces := make([]InterfaceSnapshot, 0, len(emitted))
			idx := 100
			for _, ep := range emitted {
				emitNames[ep.Name] = struct{}{}
				ifaces = append(ifaces, InterfaceSnapshot{
					Name:      ep.Name,
					LinuxName: ep.Name,
					Ifindex:   idx,
				})
				idx++
			}
			if len(emitNames) != tc.wantN {
				t.Fatalf("emitter produced %d names %v, want %d", len(emitNames), emitNames, tc.wantN)
			}
			snaps := buildTunnelEndpointSnapshots(tc.cfg, ifaces)
			builderNames := make(map[string]struct{}, len(snaps))
			for _, s := range snaps {
				builderNames[s.Interface] = struct{}{}
			}
			if len(builderNames) != len(emitNames) {
				t.Fatalf("builder names %v != emitter names %v", builderNames, emitNames)
			}
			for n := range emitNames {
				if _, ok := builderNames[n]; !ok {
					t.Fatalf("emitter ref %q missing from builder set %v", n, builderNames)
				}
			}
		})
	}
}

func cfgWith(ifaces map[string]*config.InterfaceConfig) *config.Config {
	c := &config.Config{}
	c.Interfaces.Interfaces = ifaces
	return c
}

// #1434 multi-peer: a two-peer WG tunnel produces a snapshot whose
// WgPeers carries BOTH peers, sorted by pubkey hex, and two builds of
// the SAME config produce byte-identical JSON (HA compile determinism —
// both nodes ship the config TEXT and recompile; the snapshot must be
// stable regardless of authored peer order).
func TestBuildTunnelEndpointSnapshotsMultiPeerSortedDeterministic(t *testing.T) {
	const (
		keyA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
		keyB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
		keyC = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	)
	build := func() []TunnelEndpointSnapshot {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"wg0": {Name: "wg0", Tunnel: &config.TunnelConfig{
				Name:         "wg0",
				Mode:         "wireguard",
				WgListenPort: 51820,
				// Authored OUT of pubkey-sort order (C before B) — the
				// builder must sort so the snapshot is stable.
				WgPeers: []config.WgPeerConfig{
					{PublicKeyHex: keyC, AllowedIPs: []string{"10.3.0.0/16"}, Endpoint: "198.51.100.7:51820"},
					{PublicKeyHex: keyB, AllowedIPs: []string{"10.2.0.0/16"}, Endpoint: "203.0.113.1:51820"},
				},
			}},
		}
		return buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
			{Name: "wg0", LinuxName: "wg0", Ifindex: 42, Zone: "vpn"},
		})
	}
	eps := build()
	if len(eps) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(eps))
	}
	peers := eps[0].WgPeers
	if len(peers) != 2 {
		t.Fatalf("WgPeers = %d, want 2", len(peers))
	}
	// Sorted by pubkey: B (b2..) before C (c3..) despite authored order.
	if peers[0].WgPeerPubkeyHex != keyB || peers[1].WgPeerPubkeyHex != keyC {
		t.Fatalf("peers not sorted by pubkey: %q then %q", peers[0].WgPeerPubkeyHex, peers[1].WgPeerPubkeyHex)
	}
	// Per-peer AllowedIPs stay with their peer.
	if peers[0].WgAllowedIPs[0] != "10.2.0.0/16" || peers[1].WgAllowedIPs[0] != "10.3.0.0/16" {
		t.Fatalf("AllowedIPs crossed: %v / %v", peers[0].WgAllowedIPs, peers[1].WgAllowedIPs)
	}
	// HA determinism: two builds of the same config marshal identically.
	j1, err := json.Marshal(build())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	j2, err := json.Marshal(build())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(j1) != string(j2) {
		t.Fatalf("snapshot JSON not deterministic:\n%s\n%s", j1, j2)
	}
}
