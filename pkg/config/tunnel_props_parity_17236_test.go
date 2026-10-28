// #17236 (R4-Q23-04): the tunnel property reader existed twice inside
// compileInterfaces — an interface-level switch and a unit-level switch
// over the same 10 leaves. #13215 fixed one copy and the unit twin
// shipped the inherited-peer / plaintext-GRE bug until #14440, which
// extracted the braced pre-pass but left the main switch duplicated.
// applyTunnelProps17236 is now the single reader; both call sites
// decide only whether a numeric quarantine skips the interface or
// the unit.
//
// This file pins the two acceptance guards:
//  1. an AST source guard: exactly one tunnel-property dispatch site
//     exists over ALL non-test pkg/config .go files (switch cases plus
//     if/else comparisons against the 10 tunnel leaf literals;
//     const-case via map lookup is also caught — see
//     tunnelDispatchSites17236), compiler_interfaces.go holds no
//     dispatch, and both compileInterfaces tunnel sites call the
//     shared helper (so a future edit cannot re-fork the reader
//     silently, in any file or spelling);
//  2. a parity table: every tunnel leaf compiles identically at
//     interface and unit level in braced, packed and flat-set
//     spellings, including the strict/lenient numeric outcomes.
package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// tunnelLeafNames17236 is the closed set of 10 tunnel property leaves
// the single reader dispatches over (#17236).
var tunnelLeafNames17236 = []string{
	"source", "destination", "mode", "key", "ttl",
	"keepalive", "keepalive-retry", "routing-instance",
	"wireguard", "clear-dont-fragment-bit",
}

func tunnelLeafSet17236() map[string]bool {
	m := make(map[string]bool, len(tunnelLeafNames17236))
	for _, leaf := range tunnelLeafNames17236 {
		m[leaf] = true
	}
	return m
}

// tunnelDispatchSite17236 is one dispatch site: a switch, an if/else
// chain, or a map index whose leaves include >=2 tunnel leaves.
type tunnelDispatchSite17236 struct {
	file   string
	line   int
	kind   string // "switch", "if-chain" or "map-index"
	leaves []string
}

func stringLit17236(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// tunnelCondLeaves17236 collects tunnel-leaf literals compared with
// == or != anywhere inside an if condition.
func tunnelCondLeaves17236(cond ast.Expr, leaves map[string]bool, out map[string]bool) {
	ast.Inspect(cond, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || (be.Op != token.EQL && be.Op != token.NEQ) {
			return true
		}
		for _, side := range []ast.Expr{be.X, be.Y} {
			if s, ok := stringLit17236(side); ok && leaves[s] {
				out[s] = true
			}
		}
		return true
	})
}

func sortedLeafKeys17236(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for leaf := range m {
		out = append(out, leaf)
	}
	sort.Strings(out)
	return out
}

// tunnelDispatchSites17236 is an AST census over ALL non-test
// pkg/config .go files counting dispatch over the 10 tunnel leaf
// names. A dispatch site is:
//
//   - a switch whose case clauses name >=2 tunnel leaves,
//   - an if/else chain (else-if continuations folded into the head)
//     whose conditions compare against >=2 distinct tunnel leaves, or
//   - a handler map literal (map[string]func... keyed by >=2 tunnel
//     leaves — the const-case spelling; schema/lookup maps whose
//     values are not funcs cannot dispatch and are excluded).
//
// Package-wide unrelated same-name switches exist (e.g. a system
// switch over "key"/"routing-instance" in a non-tunnel scope); they
// are DISCOVERED by this census and must be allow-listed explicitly
// below with their scope, so any NEW multi-leaf dispatch — in any
// file, spelled as switch, if/else chain or map lookup — fails
// instead of evading a substring count. A single-leaf helper (e.g.
// reading only "mode" to detect WireGuard) is not a property
// dispatch: it cannot re-implement the 10-leaf reader.
func tunnelDispatchSites17236(t *testing.T) []tunnelDispatchSite17236 {
	t.Helper()
	leaves := tunnelLeafSet17236()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.): %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	if len(files) < 100 {
		t.Fatalf("census: only %d non-test .go files in pkg/config; the package-wide walk is not reaching the package and a green would measure nothing", len(files))
	}
	fset := token.NewFileSet()
	var sites []tunnelDispatchSite17236
	parsed := 0
	for _, name := range files {
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		parsed++
		lineOf := func(p token.Pos) int { return fset.Position(p).Line }
		// else-if continuations are folded into their chain head.
		elseIf := map[*ast.IfStmt]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if ifs, ok := n.(*ast.IfStmt); ok {
				if ei, ok := ifs.Else.(*ast.IfStmt); ok {
					elseIf[ei] = true
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SwitchStmt:
				found := map[string]bool{}
				for _, stmt := range node.Body.List {
					cc, ok := stmt.(*ast.CaseClause)
					if !ok {
						continue
					}
					for _, e := range cc.List {
						if s, ok := stringLit17236(e); ok && leaves[s] {
							found[s] = true
						}
					}
				}
				if len(found) >= 2 {
					sites = append(sites, tunnelDispatchSite17236{name, lineOf(node.Pos()), "switch", sortedLeafKeys17236(found)})
				}
			case *ast.TypeSwitchStmt:
				found := map[string]bool{}
				if node.Body != nil {
					for _, stmt := range node.Body.List {
						cc, ok := stmt.(*ast.CaseClause)
						if !ok {
							continue
						}
						for _, e := range cc.List {
							if s, ok := stringLit17236(e); ok && leaves[s] {
								found[s] = true
							}
						}
					}
				}
				if len(found) >= 2 {
					sites = append(sites, tunnelDispatchSite17236{name, lineOf(node.Pos()), "switch", sortedLeafKeys17236(found)})
				}
			case *ast.IfStmt:
				if elseIf[node] {
					return true
				}
				found := map[string]bool{}
				for cur := node; cur != nil; {
					tunnelCondLeaves17236(cur.Cond, leaves, found)
					ei, ok := cur.Else.(*ast.IfStmt)
					if !ok {
						break
					}
					cur = ei
				}
				if len(found) >= 2 {
					sites = append(sites, tunnelDispatchSite17236{name, lineOf(node.Pos()), "if-chain", sortedLeafKeys17236(found)})
				}
			}
			return true
		})
		// Map-literal dispatch tables (const-case spelling): a map
		// literal keyed by any tunnel leaf, whether indexed inline or
		// bound to a var and indexed later.
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			mt, isMap := cl.Type.(*ast.MapType)
			if !isMap {
				return true
			}
			// Only a handler map can dispatch: its values are funcs.
			// Schema/lookup maps in this package are keyed by leaf
			// names by design (schema_*.go, natScopeKinds, ...) and
			// never hold code, so they are not const-case readers.
			if _, isFunc := mt.Value.(*ast.FuncType); !isFunc {
				return true
			}
			found := map[string]bool{}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if s, ok := stringLit17236(kv.Key); ok && leaves[s] {
					found[s] = true
				}
			}
			if len(found) >= 2 {
				sites = append(sites, tunnelDispatchSite17236{name, lineOf(cl.Pos()), "map-index", sortedLeafKeys17236(found)})
			}
			return true
		})
	}
	if parsed < 100 {
		t.Fatalf("census: parsed only %d production files; not reaching pkg/config", parsed)
	}
	return sites
}

// TestTunnelPropertySwitchIsSingle17236 is the AST source guard for
// #17236: exactly ONE tunnel-property dispatch site exists over all
// non-test pkg/config .go files — applyTunnelProps17236's switch in
// tunnel_flat_run_9156.go — and both compileInterfaces tunnel sites
// call it. A second reader in a new file, or spelled as if/else or
// map lookup, is a new dispatch site and fails. Also pins the
// historical acceptance: no `case "keepalive-retry"` substring in
// compiler_interfaces.go.
func TestTunnelPropertySwitchIsSingle17236(t *testing.T) {
	ci, err := os.ReadFile("compiler_interfaces.go")
	if err != nil {
		t.Fatalf("read compiler_interfaces.go: %v", err)
	}
	if n := strings.Count(string(ci), `case "keepalive-retry"`); n != 0 {
		t.Errorf("compiler_interfaces.go has %d `case \"keepalive-retry\"`, want 0 (tunnel switch must live only in applyTunnelProps17236)", n)
	}
	// AST-count helper callsites: the two compileInterfaces tunnel
	// sites, not every textual mention (docs/comments included).
	helperCalls := 0
	{
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, "compiler_interfaces.go", nil, 0)
		if perr != nil {
			t.Fatalf("parse compiler_interfaces.go: %v", perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "applyTunnelProps17236" {
				helperCalls++
			}
			return true
		})
	}
	if helperCalls != 2 {
		t.Errorf("compiler_interfaces.go calls applyTunnelProps17236 %d times, want 2 (interface + unit sites)", helperCalls)
	}

	sites := tunnelDispatchSites17236(t)
	// Known non-tunnel multi-leaf dispatches discovered by the
	// census. Each entry scopes WHY the site is not a tunnel
	// property reader; any site not listed here (and not the single
	// allowed helper switch) fails.
	allowed := []tunnelDispatchSite17236{
		// compiler_system.go: system login/authentication switch over
		// node names in a system scope (keys like "key" collide by
		// name only; it never reads tunnel nodes / TunnelConfig).
		{file: "compiler_system.go", kind: "switch"},
		// tunnel_flat_run_9156.go braced-scalar pre-pass: handles only
		// source/destination/mode/keepalive/keepalive-retry, NOT a
		// property switch (no key/ttl/routing-instance/wireguard/
		// clear-dont-fragment-bit); called only from the helper.
		{file: "tunnel_flat_run_9156.go", kind: "switch"},
		// tunnelid.go:171: astTunnelModeWireguard compares a node's
		// Name() to "mode" and its VALUE to "wireguard" (a value, not
		// a leaf name) to answer one boolean; it reads no other leaf
		// and writes no TunnelConfig field.
		{file: "tunnelid.go", kind: "if-chain"},
	}
	var tunnelSites []tunnelDispatchSite17236
	for _, s := range sites {
		isAllowed := false
		for _, a := range allowed {
			if s.file == a.file && s.kind == a.kind {
				// The helper file carries exactly two switches; the
				// system file carries exactly one. Counted below.
				isAllowed = true
			}
		}
		if s.file == "tunnel_flat_run_9156.go" && s.kind == "switch" {
			tunnelSites = append(tunnelSites, s)
			continue
		}
		if isAllowed {
			continue
		}
		t.Errorf("unexpected tunnel-property dispatch site %s:%d (%s over %v): a second tunnel reader must not exist in any file or spelling; fold it into applyTunnelProps17236", s.file, s.line, s.kind, s.leaves)
	}
	// Exactly two switches in the helper file: the single property
	// switch (all 10 leaves) plus the braced pre-pass (5 leaves).
	if len(tunnelSites) != 2 {
		t.Fatalf("tunnel_flat_run_9156.go has %d dispatch switches, want 2 (property switch + braced pre-pass): %+v", len(tunnelSites), tunnelSites)
	}
	var propSwitch *tunnelDispatchSite17236
	for i := range tunnelSites {
		if len(tunnelSites[i].leaves) == len(tunnelLeafNames17236) {
			propSwitch = &tunnelSites[i]
		}
	}
	if propSwitch == nil {
		t.Fatalf("no switch in tunnel_flat_run_9156.go covers all 10 tunnel leaves: %+v", tunnelSites)
	}
	for _, leaf := range tunnelLeafNames17236 {
		found := false
		for _, l := range propSwitch.leaves {
			if l == leaf {
				found = true
			}
		}
		if !found {
			t.Errorf("single tunnel property switch misses leaf %q (leaves=%v)", leaf, propSwitch.leaves)
		}
	}

	// The allowed non-helper switches must stay exactly one each; a
	// second one in an allow-listed file is a new dispatch.
	for _, want := range []struct {
		file, kind string
	}{
		{"compiler_system.go", "switch"},
		{"tunnelid.go", "if-chain"},
	} {
		n := 0
		for _, s := range sites {
			if s.file == want.file && s.kind == want.kind {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s has %d %s dispatch sites, want exactly the 1 allow-listed non-tunnel site", want.file, n, want.kind)
		}
	}
}

// tunnelLeaf17236 is one row of the parity table: a leaf spelling in
// each of the three AST shapes, plus whether the strict channel must
// reject it and the lenient channel must warn-and-quarantine.
type tunnelLeaf17236 struct {
	name string
	// braced is the hierarchical spelling inside `tunnel { ... }`.
	braced string
	// flat is the `set interfaces gr-0/0/0 [unit 0] tunnel ...` tail.
	flat string
	// numeric marks key/ttl rows where strict rejects and lenient
	// quarantines; wantKey/wantTTL carry the expected bad raw token.
	badRaw string
	// check asserts the leaf landed on tc (called for good rows).
	check func(t *testing.T, tc *TunnelConfig)
}

func tunnelLeaves17236() []tunnelLeaf17236 {
	return []tunnelLeaf17236{
		{
			name:   "source",
			braced: "source 10.9.0.1;",
			flat:   "source 10.9.0.1",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Source != "10.9.0.1" {
					t.Errorf("Source = %q, want 10.9.0.1", tc.Source)
				}
			},
		},
		{
			name:   "destination",
			braced: "destination 10.9.0.2;",
			flat:   "destination 10.9.0.2",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Destination != "10.9.0.2" {
					t.Errorf("Destination = %q, want 10.9.0.2", tc.Destination)
				}
			},
		},
		{
			name:   "mode",
			braced: "mode ipip;",
			flat:   "mode ipip",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Mode != TunnelModeIPIP {
					t.Errorf("Mode = %q, want ipip", tc.Mode)
				}
			},
		},
		{
			name:   "key good",
			braced: "key 4242;",
			flat:   "key 4242",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Key != 4242 {
					t.Errorf("Key = %d, want 4242", tc.Key)
				}
			},
		},
		{
			name:   "key bad strict+lenient",
			braced: "key 4294967296;",
			flat:   "key 4294967296",
			badRaw: "key",
		},
		{
			name:   "ttl good",
			braced: "ttl 99;",
			flat:   "ttl 99",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.TTL != 99 {
					t.Errorf("TTL = %d, want 99", tc.TTL)
				}
			},
		},
		{
			name:   "ttl bad strict+lenient",
			braced: "ttl 0;",
			flat:   "ttl 0",
			badRaw: "ttl",
		},
		{
			name:   "keepalive",
			braced: "keepalive 17;",
			flat:   "keepalive 17",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Keepalive != 17 {
					t.Errorf("Keepalive = %d, want 17", tc.Keepalive)
				}
			},
		},
		{
			name:   "keepalive-retry",
			braced: "keepalive-retry 4;",
			flat:   "keepalive-retry 4",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.KeepaliveRetry != 4 {
					t.Errorf("KeepaliveRetry = %d, want 4", tc.KeepaliveRetry)
				}
			},
		},
		{
			name:   "routing-instance",
			braced: "routing-instance { destination VR1; }",
			flat:   "routing-instance destination VR1",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.RoutingInstance != "VR1" {
					t.Errorf("RoutingInstance = %q, want VR1", tc.RoutingInstance)
				}
			},
		},
		{
			name:   "clear-dont-fragment-bit",
			braced: "clear-dont-fragment-bit;",
			flat:   "clear-dont-fragment-bit",
			check: func(t *testing.T, tc *TunnelConfig) {
				if !tc.ClearDontFragmentBit {
					t.Errorf("ClearDontFragmentBit = false, want true")
				}
			},
		},
		{
			name:   "wireguard",
			braced: "mode wireguard; wireguard { listen-port 51820; private-key " + wgKeyA + "; peer " + wgKeyB + " { allowed-ips 10.9.0.0/24; } }",
			flat:   "mode wireguard",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Mode != TunnelModeWireGuard {
					t.Errorf("Mode = %q, want wireguard", tc.Mode)
				}
			},
		},
	}
}

// ifaceTunnel17236 returns the interface-level tunnel of gr-0/0/0.
// The unit tunnel inherits via cloneForUnit, so parity is compared
// after stripping the caller-owned fields (Name, Addresses).
func ifaceTunnel17236(t *testing.T, cfg *Config) *TunnelConfig {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatalf("gr-0/0/0 missing: %v", cfg.Interfaces.Interfaces)
	}
	return ifc.Tunnel
}

func unitTunnel17236(t *testing.T, cfg *Config) *TunnelConfig {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatalf("gr-0/0/0 missing: %v", cfg.Interfaces.Interfaces)
	}
	u := ifc.Units[0]
	if u == nil {
		return nil
	}
	return u.Tunnel
}

// stripCallerOwned17236 removes the fields the two call sites own
// differently (device name; addresses appended later) so the
// property-read result can be DeepEqual-compared across levels.
func stripCallerOwned17236(tc *TunnelConfig) *TunnelConfig {
	if tc == nil {
		return nil
	}
	c := *tc
	c.Name = ""
	c.Addresses = nil
	if len(c.WgPeers) == 0 {
		c.WgPeers = nil
	}
	return &c
}

func compileBraced17236(t *testing.T, unit bool, leaf string) *Config {
	t.Helper()
	var body string
	if unit {
		body = "interfaces { gr-0/0/0 { unit 0 { tunnel { " + leaf + " } } } } routing-instances { VR1 { instance-type virtual-router; } }"
	} else {
		body = "interfaces { gr-0/0/0 { tunnel { " + leaf + " } } } routing-instances { VR1 { instance-type virtual-router; } }"
	}
	cfg, err := CompileConfig(parseHierText(t, body))
	if err != nil {
		t.Fatalf("braced unit=%v leaf %q: %v", unit, leaf, err)
	}
	return cfg
}

func compileFlat17236(t *testing.T, unit bool, leaf string) *Config {
	t.Helper()
	prefix := "set interfaces gr-0/0/0 tunnel "
	if unit {
		prefix = "set interfaces gr-0/0/0 unit 0 tunnel "
	}
	cfg, err := CompileConfig(parseSetCommands(t,
		prefix+leaf,
		"set routing-instances VR1 instance-type virtual-router",
	))
	if err != nil {
		t.Fatalf("flat unit=%v leaf %q: %v", unit, leaf, err)
	}
	return cfg
}

// compilePacked17236 builds the packed spelling: the whole tunnel
// stanza on one hierarchical line (`tunnel { <leaf> ... };` inside a
// one-line interface body), which packedBody expands.
func compilePacked17236(t *testing.T, unit bool, leaf string) *Config {
	t.Helper()
	// Packed = several leaves packed into one tunnel block on a
	// single line; the leaf under test rides with a source so the
	// tunnel is well-formed.
	var body string
	if unit {
		body = "interfaces { gr-0/0/0 { unit 0 { tunnel { source 10.9.0.1; " + leaf + " } } } } routing-instances { VR1 { instance-type virtual-router; } }"
	} else {
		body = "interfaces { gr-0/0/0 { tunnel { source 10.9.0.1; " + leaf + " } } } routing-instances { VR1 { instance-type virtual-router; } }"
	}
	cfg, err := CompileConfig(parseHierText(t, body))
	if err != nil {
		t.Fatalf("packed unit=%v leaf %q: %v", unit, leaf, err)
	}
	return cfg
}

func TestTunnelPropsParity17236(t *testing.T) {
	for _, leaf := range tunnelLeaves17236() {
		t.Run(leaf.name, func(t *testing.T) {
			if leaf.badRaw != "" {
				// Strict must reject at BOTH levels naming the leaf;
				// lenient must warn and quarantine (interface: no
				// tunnel survives / unit: unit skipped).
				for _, unit := range []bool{false, true} {
					func() {
						prefix := "set interfaces gr-0/0/0 tunnel "
						if unit {
							prefix = "set interfaces gr-0/0/0 unit 0 tunnel "
						}
						tree := parseSetCommands(t, prefix+leaf.flat)
						if _, err := CompileConfig(tree); err == nil {
							t.Errorf("strict unit=%v %q accepted, want rejection", unit, leaf.flat)
						} else if !strings.Contains(err.Error(), leaf.badRaw) {
							t.Errorf("strict unit=%v error %q must name %q", unit, err, leaf.badRaw)
						}
						ltree := parseSetCommands(t, prefix+leaf.flat)
						cfg, err := CompileConfigLenient(ltree)
						if err != nil {
							t.Fatalf("lenient unit=%v %q: %v", unit, leaf.flat, err)
						}
						joined := strings.Join(cfg.Warnings, "\n")
						if !strings.Contains(joined, leaf.badRaw) {
							t.Errorf("lenient unit=%v warnings %q must name %q", unit, joined, leaf.badRaw)
						}
						if unit {
							// Unit may be absent (quarantined) — do
							// not fatal on the missing interface.
							if cfg.Interfaces.Interfaces["gr-0/0/0"] != nil {
								if u := unitTunnel17236(t, cfg); u != nil {
									t.Errorf("lenient unit tunnel survived quarantine: %+v", u)
								}
							}
							if !strings.Contains(joined, "skipping unit 0") {
								t.Errorf("lenient unit warnings %q must say skipping unit 0", joined)
							}
						} else {
							if cfg.Interfaces.Interfaces["gr-0/0/0"] != nil {
								if tc := ifaceTunnel17236(t, cfg); tc != nil {
									t.Errorf("lenient iface tunnel survived quarantine: %+v", tc)
								}
							}
							if !strings.Contains(joined, "quarantining interface") {
								t.Errorf("lenient iface warnings %q must say quarantining interface", joined)
							}
						}
					}()
				}
				return
			}

			// Good leaf: braced, packed and flat-set must agree at
			// each level, and interface vs unit must agree after
			// stripping caller-owned fields. The unit fixture has
			// no interface tunnel, so nothing is inherited.
			if leaf.name == "wireguard" {
				// Braced, packed and flat spellings are all run
				// through their real compilers: braced via
				// compileBraced17236, packed via compilePacked17236
				// (source rider, so Source is forced to 10.9.0.1 as
				// for every other leaf), and flat via separate
				// wireguard set lines (mode/listen-port/private-key/
				// peer — a lone `mode wireguard` flat line would be
				// rejected by the WireGuard validator for missing
				// key material). All three must DeepEqual the braced
				// result after stripping caller-owned fields, except
				// the flat peer's AllowedIPs, which the flat fixture
				// authors as 10.77.0.0/16 (wgTunnel5618) vs the
				// braced 10.9.0.0/24.
				ib := stripCallerOwned17236(ifaceTunnel17236(t, compileBraced17236(t, false, leaf.braced)))
				ub := stripCallerOwned17236(unitTunnel17236(t, compileBraced17236(t, true, leaf.braced)))
				if ib == nil || ub == nil {
					t.Fatalf("wireguard braced tunnels: iface=%+v unit=%+v", ib, ub)
				}
				leaf.check(t, ib)
				leaf.check(t, ub)
				if ib.WgListenPort != 51820 || len(ib.WgPeers) != 1 {
					t.Errorf("wireguard braced iface: port=%d peers=%+v, want 51820 + 1 peer", ib.WgListenPort, ib.WgPeers)
				}
				if !reflect.DeepEqual(ib, ub) {
					t.Errorf("wireguard braced parity: iface %+v != unit %+v", ib, ub)
				}
				ip := stripCallerOwned17236(ifaceTunnel17236(t, compilePacked17236(t, false, leaf.braced)))
				up := stripCallerOwned17236(unitTunnel17236(t, compilePacked17236(t, true, leaf.braced)))
				if ip == nil || up == nil {
					t.Fatalf("wireguard packed tunnels: iface=%+v unit=%+v", ip, up)
				}
				wantPI, wantPU := *ib, *ub
				wantPI.Source, wantPU.Source = "10.9.0.1", "10.9.0.1"
				if !reflect.DeepEqual(&wantPI, ip) {
					t.Errorf("wireguard packed vs braced iface: %+v != %+v", ip, &wantPI)
				}
				if !reflect.DeepEqual(&wantPU, up) {
					t.Errorf("wireguard packed vs braced unit: %+v != %+v", up, &wantPU)
				}
				for _, unit := range []bool{false, true} {
					var lines []string
					if unit {
						lines = wgTunnel5618("gr-0/0/0", 0, 51820, wgKeyA, wgKeyB)
					} else {
						lines = wgTunnel5618("gr-0/0/0", -1, 51820, wgKeyA, wgKeyB)
					}
					cfg, err := CompileConfig(parseSetCommands(t, lines...))
					if err != nil {
						t.Fatalf("wireguard flat unit=%v: %v", unit, err)
					}
					var got *TunnelConfig
					if unit {
						got = stripCallerOwned17236(unitTunnel17236(t, cfg))
					} else {
						got = stripCallerOwned17236(ifaceTunnel17236(t, cfg))
					}
					if got == nil {
						t.Fatalf("wireguard flat unit=%v: tunnel nil", unit)
					}
					want := *ib
					if unit {
						want = *ub
					}
					if len(want.WgPeers) == 1 && len(got.WgPeers) == 1 {
						want.WgPeers = append([]WgPeerConfig(nil), want.WgPeers...)
						want.WgPeers[0].AllowedIPs = append([]string(nil), got.WgPeers[0].AllowedIPs...)
					}
					if !reflect.DeepEqual(&want, got) {
						t.Errorf("wireguard flat vs braced unit=%v: %+v != %+v", unit, got, &want)
					}
				}
				return
			}

			ib := stripCallerOwned17236(ifaceTunnel17236(t, compileBraced17236(t, false, leaf.braced)))
			ub := stripCallerOwned17236(unitTunnel17236(t, compileBraced17236(t, true, leaf.braced)))
			if ib == nil {
				t.Fatalf("iface braced %q: tunnel nil", leaf.braced)
			}
			if ub == nil {
				t.Fatalf("unit braced %q: tunnel nil", leaf.braced)
			}
			leaf.check(t, ib)
			leaf.check(t, ub)
			if !reflect.DeepEqual(ib, ub) {
				t.Errorf("braced parity %s: iface %+v != unit %+v", leaf.name, ib, ub)
			}

			ip := stripCallerOwned17236(ifaceTunnel17236(t, compilePacked17236(t, false, leaf.braced)))
			up := stripCallerOwned17236(unitTunnel17236(t, compilePacked17236(t, true, leaf.braced)))
			if ip == nil || up == nil {
				t.Fatalf("packed %s: iface=%+v unit=%+v", leaf.name, ip, up)
			}
			// Packed rides with a `source 10.9.0.1` sibling (see
			// compilePacked17236); expect it on top of the braced
			// result unless the leaf itself is source.
			wantPI, wantPU := *ib, *ub
			if leaf.name != "source" {
				wantPI.Source = "10.9.0.1"
				wantPU.Source = "10.9.0.1"
			}
			if !reflect.DeepEqual(&wantPI, ip) {
				t.Errorf("packed vs braced iface %s: %+v != %+v", leaf.name, ip, &wantPI)
			}
			if !reflect.DeepEqual(&wantPU, up) {
				t.Errorf("packed vs braced unit %s: %+v != %+v", leaf.name, up, &wantPU)
			}

			ifl := stripCallerOwned17236(ifaceTunnel17236(t, compileFlat17236(t, false, leaf.flat)))
			ufl := stripCallerOwned17236(unitTunnel17236(t, compileFlat17236(t, true, leaf.flat)))
			if ifl == nil || ufl == nil {
				t.Fatalf("flat %s: iface=%+v unit=%+v", leaf.name, ifl, ufl)
			}
			// Flat-set carries no source sibling, so the packed/
			// braced `source 10.9.0.1` rider is absent; compare
			// against the braced result with Source cleared when
			// the leaf itself is not source.
			wantI, wantU := ib, ub
			if leaf.name != "source" {
				wi, wu := *ib, *ub
				wi.Source, wu.Source = "", ""
				wantI, wantU = &wi, &wu
			}
			if !reflect.DeepEqual(wantI, ifl) {
				t.Errorf("flat vs braced iface %s: %+v != %+v", leaf.name, ifl, wantI)
			}
			if !reflect.DeepEqual(wantU, ufl) {
				t.Errorf("flat vs braced unit %s: %+v != %+v", leaf.name, ufl, wantU)
			}
		})
	}
}
