package config

import (
	"reflect"
	"testing"
)

// #17239: the `system ntp` arm enumerated its children two ways. `peer`
// walked the #15709 run-normalised list
// (hoistAndSplitRun8939(packedBodyChildren(...))), while `server`,
// `trusted-key` and `threshold` walked raw FindChildren/FindChild, which see
// only DIRECT children. A chain headed by `boot-server` —
// `set system ntp boot-server X server Y`, AST `[ntp] > [boot-server X] >
// [server Y]` — therefore compiled NO server/trusted-key/threshold, silently
// and strict-clean (the only diagnostic blamed the inert boot-server knob),
// while a `peer` in the same chain compiled. The fix extracts
// compileSystemNTP, which computes the normalised list ONCE and dispatches
// all four readers through a single `switch s.Name()`; no raw
// `child.FindChild*` walk remains in the extracted function.
//
// The table below is the issue's acceptance shape: {server, peer,
// trusted-key, threshold} x {braced, compact, chained after boot-server,
// flat-set chain}, each cell asserting the FULL compiled tuple
// (NTPServers/NTPPeers/NTPTrustedKeyIDs/NTPThreshold + action), not a length.

// ntpTuple17239 is the compiled NTP projection the table compares.
type ntpTuple17239 struct {
	servers   []string
	peers     []string
	trusted   []int
	threshold int
	thAction  string
}

func tuple17239(cfg *Config) ntpTuple17239 {
	return ntpTuple17239{
		servers:   cfg.System.NTPServers,
		peers:     cfg.System.NTPPeers,
		trusted:   cfg.System.NTPTrustedKeyIDs,
		threshold: cfg.System.NTPThreshold,
		thAction:  cfg.System.NTPThresholdAction,
	}
}

func TestNTPChainParity17239(t *testing.T) {
	// want for a cell carrying server 1.1.1.1, peer 2.2.2.2, trusted-key 7
	// and threshold 400 (no action unless the cell names one).
	full := ntpTuple17239{
		servers: []string{"1.1.1.1"}, peers: []string{"2.2.2.2"},
		trusted: []int{7}, threshold: 400,
	}

	cells := []struct {
		name string
		cfg  *Config
		want ntpTuple17239
	}{
		// Braced control: every statement a direct child of `ntp`.
		{"braced", compileHierStrict(t,
			`system { ntp { server 1.1.1.1; peer 2.2.2.2; trusted-key 7; threshold 400; } }`), full},
		// Braced with threshold action (hierarchical action child).
		{"braced-threshold-action", compileHierStrict(t,
			`system { ntp { server 1.1.1.1; peer 2.2.2.2; trusted-key 7; threshold 400 { action accept; } } }`),
			ntpTuple17239{servers: []string{"1.1.1.1"}, peers: []string{"2.2.2.2"}, trusted: []int{7}, threshold: 400, thAction: "accept"}},
		// Braced run headed by boot-server: statements nested under it.
		{"braced-run-boot-server-head", compileHierStrict(t,
			`system { ntp { boot-server 3.3.3.3 server 1.1.1.1; } }`),
			ntpTuple17239{servers: []string{"1.1.1.1"}}},
		// Compact spelling: the whole body packed onto the `ntp` Keys. The
		// `server` statement is `multi`, so its packed followers stay packed
		// onto it (a bracket list reads identically) and project as extra
		// "servers" exactly as the pre-fix raw reader projected them; the
		// unambiguous compact form is the boot-server-headed cell below.
		{"compact", compileHierStrict(t,
			`system { ntp server 1.1.1.1 peer 2.2.2.2 trusted-key 7 threshold 400; }`),
			ntpTuple17239{servers: []string{"1.1.1.1", "peer", "2.2.2.2", "trusted-key", "7", "threshold", "400"}}},
		// Compact headed by boot-server (packed tail of `ntp`): every
		// follower is a sibling statement and compiles.
		{"compact-boot-server-head", compileHierStrict(t,
			`system { ntp boot-server 3.3.3.3 server 1.1.1.1 trusted-key 7 threshold 400; }`),
			ntpTuple17239{servers: []string{"1.1.1.1"}, trusted: []int{7}, threshold: 400}},
		// Flat-set chain headed by boot-server: the issue's exact trigger.
		// Pre-fix: servers=[] trusted=[] th=0 (peer alone compiled).
		{"flat-boot-server-server", compileSetStrict(t,
			"set system ntp boot-server 3.3.3.3 server 1.1.1.1"),
			ntpTuple17239{servers: []string{"1.1.1.1"}}},
		{"flat-boot-server-peer", compileSetStrict(t,
			"set system ntp boot-server 3.3.3.3 peer 2.2.2.2"),
			ntpTuple17239{peers: []string{"2.2.2.2"}}},
		{"flat-boot-server-trusted", compileSetStrict(t,
			"set system ntp boot-server 3.3.3.3 trusted-key 7"),
			ntpTuple17239{trusted: []int{7}}},
		{"flat-boot-server-threshold", compileSetStrict(t,
			"set system ntp boot-server 3.3.3.3 threshold 400"),
			ntpTuple17239{threshold: 400}},
		// One flat command chaining server, then trusted-key/threshold
		// packed onto the server's Keys under the boot-server head: the
		// `multi` server keeps its packed tail (a bracket list reads
		// identically), so the tail projects as server values exactly as
		// the pre-fix raw reader projected it.
		{"flat-boot-server-full-chain", compileSetStrict(t,
			"set system ntp boot-server 3.3.3.3 server 1.1.1.1 trusted-key 9 threshold 400"),
			ntpTuple17239{servers: []string{"1.1.1.1", "trusted-key", "9", "threshold", "400"}}},
		// Flat-set chain headed by `server` itself: the followers nest as
		// CHILDREN under `server`, so every reader compiles (the
		// chain-peer-server shape measured on master).
		{"flat-server-head-chain", compileSetStrict(t,
			"set system ntp server 1.1.1.1 peer 2.2.2.2 trusted-key 7 threshold 400"),
			ntpTuple17239{servers: []string{"1.1.1.1"}, peers: []string{"2.2.2.2"}, trusted: []int{7}, threshold: 400}},
		// Threshold with inline action in a chain.
		{"flat-threshold-action", compileSetStrict(t,
			"set system ntp threshold 400 action accept"),
			ntpTuple17239{threshold: 400, thAction: "accept"}},
		// Chained server carrying a compact modifier must keep the modifier
		// (prefer) and must not gain a phantom server.
		{"flat-boot-server-server-prefer", compileSetStrict(t,
			"set system ntp boot-server 3.3.3.3 server 1.1.1.1 prefer"),
			ntpTuple17239{servers: []string{"1.1.1.1"}}},
	}
	for _, c := range cells {
		got := tuple17239(c.cfg)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: tuple = %+v, want %+v (#17239: reader diverged from the normalised enumeration)", c.name, got, c.want)
		}
	}

	// A repeated address inside ONE bracket statement must keep its
	// options: `server [ 1.1.1.1 1.1.1.1 ] prefer;` collapses to one
	// server, but the duplicate must not clear its own first-occurrence
	// flag and drop prefer/key/version (the fold blocker). Assert the
	// full option + stripped key ids, not just the address.
	repeatServerCfg := compileHierStrict(t,
		`system { ntp { server [ 1.1.1.1 1.1.1.1 ] prefer; } }`)
	if got := repeatServerCfg.System.NTPServers; len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("repeat-server: NTPServers = %v, want [1.1.1.1]", got)
	}
	if opt := repeatServerCfg.System.NTPServerOptions["1.1.1.1"]; !opt.Prefer {
		t.Errorf("repeat-server: NTPServerOptions[1.1.1.1] = %+v, want Prefer=true", opt)
	}
	repeatServerKeyCfg := compileHierStrict(t,
		`system { ntp { server [ 1.1.1.1 1.1.1.1 ] key 5 version 4; } }`)
	if opt := repeatServerKeyCfg.System.NTPServerOptions["1.1.1.1"]; opt.Version != 4 || opt.Key != 0 {
		t.Errorf("repeat-server-key: NTPServerOptions[1.1.1.1] = %+v, want Version=4 Key=0 (stripped)", opt)
	}
	if got := repeatServerKeyCfg.System.NTPServerKeyIDs; len(got) != 1 || got[0] != 5 {
		t.Errorf("repeat-server-key: NTPServerKeyIDs = %v, want [5]", got)
	}
	// Same for peer: repeated address in one bracket statement.
	repeatPeerCfg := compileHierStrict(t,
		`system { ntp { peer [ 2.2.2.2 2.2.2.2 ] prefer; } }`)
	if got := repeatPeerCfg.System.NTPPeers; len(got) != 1 || got[0] != "2.2.2.2" {
		t.Errorf("repeat-peer: NTPPeers = %v, want [2.2.2.2]", got)
	}
	if opt := repeatPeerCfg.System.NTPPeerOptions["2.2.2.2"]; !opt.Prefer {
		t.Errorf("repeat-peer: NTPPeerOptions[2.2.2.2] = %+v, want Prefer=true", opt)
	}
	repeatPeerKeyCfg := compileHierStrict(t,
		`system { ntp { peer [ 2.2.2.2 2.2.2.2 ] key 7 version 3; } }`)
	if opt := repeatPeerKeyCfg.System.NTPPeerOptions["2.2.2.2"]; opt.Version != 3 || opt.Key != 0 {
		t.Errorf("repeat-peer-key: NTPPeerOptions[2.2.2.2] = %+v, want Version=3 Key=0 (stripped)", opt)
	}
	if got := repeatPeerKeyCfg.System.NTPServerKeyIDs; len(got) != 1 || got[0] != 7 {
		t.Errorf("repeat-peer-key: NTPServerKeyIDs = %v, want [7]", got)
	}

	// The prefer cell must also keep its OPTION, not just its address.
	preferCfg := compileSetStrict(t, "set system ntp boot-server 3.3.3.3 server 1.1.1.1 prefer")
	if opt := preferCfg.System.NTPServerOptions["1.1.1.1"]; !opt.Prefer {
		t.Errorf("flat-boot-server-server-prefer: NTPServerOptions[1.1.1.1] = %+v, want Prefer=true", opt)
	}
}

// TestNTPChainSeparateSetLinesUnaffected17239 pins the control the fix must
// not disturb: separate `set` lines (each its own SetPath) already compiled
// every reader pre-fix and must compile identically after.
func TestNTPChainSeparateSetLinesUnaffected17239(t *testing.T) {
	cfg := compileSetStrict(t,
		"set system ntp server 1.1.1.1",
		"set system ntp peer 2.2.2.2",
		"set system ntp trusted-key 7",
		"set system ntp threshold 400",
	)
	want := ntpTuple17239{
		servers: []string{"1.1.1.1"}, peers: []string{"2.2.2.2"},
		trusted: []int{7}, threshold: 400,
	}
	if got := tuple17239(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("separate set lines: tuple = %+v, want %+v", got, want)
	}
}
