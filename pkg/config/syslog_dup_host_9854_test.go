package config

import "testing"

// Tests for #9854: two `system syslog host <addr>` statements naming one
// address compiled as TWO destinations. Strict commit accepted each row.
//
// Flat-set `set` usually merges the same lines into one node (SetPath), so
// the hierarchical spelling diverged from it — the #8436
// duplicate-named-block class, disposition "append both". The #8436 census
// lists `system syslog host` in dupConservationSkipped8436 (its fixture
// cannot express this site), so the rows below were measured by hand at
// master ad2ba883a:
//
//	system { syslog { host 10.0.0.1; host 10.0.0.1; } }
//	system { syslog { host 10.0.0.1; host 10.0.0.1 any any; } }
//	groups { G { system { syslog { host 10.0.0.1 any any; } } } }
//	apply-groups G; system { syslog { host 10.0.0.1 { } } }
//
// all compiled two SyslogHostConfig entries for 10.0.0.1. The runtime builds
// one SyslogClient per entry (daemon_system.go applySystemSyslog), so a
// message matching both was sent to the same address once per statement.
//
// compileSystem now find-or-creates on the host address (Junos merge
// semantics), mirroring the zone merge (#4818) and the BGP neighbor merge
// (#9192): facilities union in first-seen order with exact-pair duplicates
// dropped, scalar modifiers follow apply-groups precedence (inline explicit
// beats inherited; last inline wins; first group wins), allow-duplicates is
// OR, and first-seen host order is preserved.
//
// SHAPE NOTE: a duplicate host block is most directly expressible via the
// hierarchical / NewParser path — parseHierarchical is the primary
// reproducer here. Flat-set is NOT fully immune: identical facility paths
// merge into one node, but a BARE `set ... host X` leaf and a later
// `set ... host X <body>` container are SEPARATE nodes (SetPath's leaf
// branch never matches the container find-or-create, ast_edit.go:508-553
// vs :720-738), so that flat shape also coalesces here and has its own
// control below. One group shape has NO control by design: a packed GROUP
// host leaf beside an inline PACKED host leaf is dropped whole at expansion
// (leafListPeer matches any same-keyword leaf, even a different address),
// so the coalescing never sees it — pre-existing, master-identical,
// out of scope for this lane.

func compileSyslogHosts9854(t *testing.T, text string) []*SyslogHostConfig {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	if cfg.System.Syslog == nil {
		t.Fatalf("System.Syslog is nil, want hosts to compile (#9854)")
	}
	return cfg.System.Syslog.Hosts
}

// compileSyslogHostsLenient9854 compiles WITHOUT the strict commit gate, for
// shapes strict rejects but the tolerant path must still coalesce (the
// valueless `source-address;` guard cell: strict says "missing value").
func compileSyslogHostsLenient9854(t *testing.T, text string) []*SyslogHostConfig {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.Syslog == nil {
		t.Fatalf("System.Syslog is nil, want hosts to compile (#9854)")
	}
	return cfg.System.Syslog.Hosts
}

func facilities9854(hosts []*SyslogHostConfig) []SyslogFacility {
	if len(hosts) != 1 {
		return nil
	}
	return hosts[0].Facilities
}

// TestSyslogDupHost9854IssueRows is the primary RED-on-revert guard: the
// issue's three measured rows must each compile ONE destination.
func TestSyslogDupHost9854IssueRows(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []SyslogFacility
	}{
		{
			"two bare statements",
			`system { syslog { host 10.0.0.1; host 10.0.0.1; } }`,
			nil,
		},
		{
			"bare plus facility statement",
			`system { syslog { host 10.0.0.1; host 10.0.0.1 any any; } }`,
			[]SyslogFacility{{Facility: "any", Severity: "any"}},
		},
		{
			"group statement beside inline braced host",
			`groups { G { system { syslog { host 10.0.0.1 any any; } } } } apply-groups G; system { syslog { host 10.0.0.1 { } } }`,
			[]SyslogFacility{{Facility: "any", Severity: "any"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts := compileSyslogHosts9854(t, tc.text)
			if len(hosts) != 1 {
				t.Fatalf("compiled %d hosts for one address, want 1 (#9854)", len(hosts))
			}
			if hosts[0].Address != "10.0.0.1" {
				t.Fatalf("host address = %q, want 10.0.0.1 (#9854)", hosts[0].Address)
			}
			got := facilities9854(hosts)
			if len(got) != len(tc.want) {
				t.Fatalf("facilities = %+v, want %+v (#9854)", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("facilities = %+v, want %+v (#9854)", got, tc.want)
				}
			}
		})
	}
}

// TestSyslogDupHost9854FacilitiesMergeInOrder covers the merge the issue asks
// for: facilities from BOTH instances survive, in config order, across the
// braced/braced and packed/braced spelling pairs.
func TestSyslogDupHost9854FacilitiesMergeInOrder(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			"braced plus braced",
			`system { syslog { host 10.0.0.1 { any warning; } host 10.0.0.1 { daemon info; } } }`,
		},
		{
			"packed plus braced",
			`system { syslog { host 10.0.0.1 any warning; host 10.0.0.1 { daemon info; } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts := compileSyslogHosts9854(t, tc.text)
			if len(hosts) != 1 {
				t.Fatalf("compiled %d hosts, want 1 merged host (#9854)", len(hosts))
			}
			want := []SyslogFacility{{Facility: "any", Severity: "warning"}, {Facility: "daemon", Severity: "info"}}
			got := hosts[0].Facilities
			if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("facilities = %+v, want %+v in config order (#9854)", got, want)
			}
		})
	}
}

// TestSyslogDupHost9854ScalarsLastWins pins the INLINE scalar merge: a
// modifier present in both instances takes the LAST value (matching
// flat-set, where the second `set` overwrites the first), while a modifier
// present in only the first instance survives — absence does not wipe.
func TestSyslogDupHost9854ScalarsLastWins(t *testing.T) {
	hosts := compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { source-address 10.9.9.9; port 5514; }
		host 10.0.0.1 { source-address 10.9.9.10; }
	} }`)
	if len(hosts) != 1 {
		t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
	}
	h := hosts[0]
	if h.SourceAddress != "10.9.9.10" {
		t.Fatalf("source-address = %q, want 10.9.9.10 (last wins, #9854)", h.SourceAddress)
	}
	if h.Port != 5514 {
		t.Fatalf("port = %d, want 5514 (absent in the second instance must not wipe, #9854)", h.Port)
	}

	hosts = compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { port 5514; }
		host 10.0.0.1 { port 5515; }
	} }`)
	if len(hosts) != 1 {
		t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
	}
	if hosts[0].Port != 5515 {
		t.Fatalf("port = %d, want 5515 (last wins, #9854)", hosts[0].Port)
	}
}

// TestSyslogDupHost9854GroupInlineScalarPrecedence pins apply-groups
// precedence across the coalescing: expansion appends adopted group nodes
// AFTER inline nodes, so a position-based last-wins would let the group's
// scalar beat the inline block's explicit value — the opposite of Junos and
// of the repo's typed-merge rule (ast_groups.go:385-386, "inline OVERRIDES
// the group value"). Measured pre-fix: group port 999 + inline port 514
// merged to 999.
//
// Each scalar is covered in BOTH value directions (swapped values prove the
// outcome is precedence, not the value). The group statements use the PACKED
// spelling (`host X port 999;`), which expansion adopts as a sibling
// (leafListPeer only matches len(Keys)==1 peers, so the inline braced host
// is not its peer) — the shape that inverted. The braced-group cell pins
// the container path, which merges at expansion with inline already
// winning.
func TestSyslogDupHost9854GroupInlineScalarPrecedence(t *testing.T) {
	cases := []struct {
		name          string
		group, inline string
		check         func(t *testing.T, h *SyslogHostConfig)
	}{
		{
			"port, group 999 vs inline 514",
			`host 10.0.0.1 port 999;`, `host 10.0.0.1 { port 514; }`,
			func(t *testing.T, h *SyslogHostConfig) {
				if h.Port != 514 {
					t.Fatalf("port = %d, want 514 (inline explicit beats inherited, #9854)", h.Port)
				}
			},
		},
		{
			"port, group 514 vs inline 999",
			`host 10.0.0.1 port 514;`, `host 10.0.0.1 { port 999; }`,
			func(t *testing.T, h *SyslogHostConfig) {
				if h.Port != 999 {
					t.Fatalf("port = %d, want 999 (inline explicit beats inherited, #9854)", h.Port)
				}
			},
		},
		{
			"source-address, group .1 vs inline .2",
			`host 10.0.0.1 source-address 10.9.9.1;`, `host 10.0.0.1 { source-address 10.9.9.2; }`,
			func(t *testing.T, h *SyslogHostConfig) {
				if h.SourceAddress != "10.9.9.2" {
					t.Fatalf("source-address = %q, want 10.9.9.2 (inline explicit beats inherited, #9854)", h.SourceAddress)
				}
			},
		},
		{
			"source-address, group .2 vs inline .1",
			`host 10.0.0.1 source-address 10.9.9.2;`, `host 10.0.0.1 { source-address 10.9.9.1; }`,
			func(t *testing.T, h *SyslogHostConfig) {
				if h.SourceAddress != "10.9.9.1" {
					t.Fatalf("source-address = %q, want 10.9.9.1 (inline explicit beats inherited, #9854)", h.SourceAddress)
				}
			},
		},
		{
			"port, braced group vs braced inline (expansion-merge control)",
			`host 10.0.0.1 { port 999; }`, `host 10.0.0.1 { port 514; }`,
			func(t *testing.T, h *SyslogHostConfig) {
				if h.Port != 514 {
					t.Fatalf("port = %d, want 514 (inline wins on the container path too, #9854)", h.Port)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `groups { G { system { syslog { ` + tc.group + ` } } } } apply-groups G; system { syslog { ` + tc.inline + ` } }`
			hosts := compileSyslogHosts9854(t, text)
			if len(hosts) != 1 {
				t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
			}
			tc.check(t, hosts[0])
		})
	}
}

// TestSyslogDupHost9854GroupScalarAppliesWhenInlineLacks is the counter-case
// that keeps the precedence fix honest: inline-beats-inherited must not
// become inline-ignores-inherited. A group scalar with no inline rival
// still lands on the merged destination.
func TestSyslogDupHost9854GroupScalarAppliesWhenInlineLacks(t *testing.T) {
	hosts := compileSyslogHosts9854(t, `groups { G { system { syslog { host 10.0.0.1 port 999; } } } } apply-groups G; system { syslog { host 10.0.0.1 { any warning; } } }`)
	if len(hosts) != 1 {
		t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
	}
	if hosts[0].Port != 999 {
		t.Fatalf("port = %d, want 999 (unrivalled group value must apply, #9854)", hosts[0].Port)
	}
	if len(hosts[0].Facilities) != 1 {
		t.Fatalf("facilities = %+v, want the inline pair beside the inherited port (#9854)", hosts[0].Facilities)
	}

	hosts = compileSyslogHosts9854(t, `groups { G { system { syslog { host 10.0.0.1 source-address 10.9.9.1; } } } } apply-groups G; system { syslog { host 10.0.0.1 { any warning; } } }`)
	if len(hosts) != 1 {
		t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
	}
	if hosts[0].SourceAddress != "10.9.9.1" {
		t.Fatalf("source-address = %q, want 10.9.9.1 (unrivalled group value must apply, #9854)", hosts[0].SourceAddress)
	}
}

// TestSyslogDupHost9854FirstGroupWins pins group-vs-group precedence: with
// no inline rival, the FIRST applied group's scalar wins.
//
// The both-packed cell resolves at EXPANSION (the later packed leaf finds
// the adopted earlier one as its peer and is skipped), so it also passes
// pre-fix — it characterizes the outcome, not the compile rule. The mixed
// cell (G1 braced merged into the inline container, G2 packed adopted as a
// sibling) reaches the coalescing as two nodes and is RED without the
// inherited-first rule.
//
// The mirror (G1 packed + G2 braced) is the documented positional residual
// (see the #9854 note in compiler_system.go) and is deliberately unpinned:
// no test enshrines a position-dependent outcome.
func TestSyslogDupHost9854FirstGroupWins(t *testing.T) {
	cases := []struct{ name, g1, g2 string }{
		{"both packed", `host 10.0.0.1 port 111;`, `host 10.0.0.1 port 222;`},
		{"G1 braced, G2 packed", `host 10.0.0.1 { port 111; }`, `host 10.0.0.1 port 222;`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `groups { G1 { system { syslog { ` + tc.g1 + ` } } } G2 { system { syslog { ` + tc.g2 + ` } } } } apply-groups [ G1 G2 ]; system { syslog { host 10.0.0.1 { any warning; } } }`
			hosts := compileSyslogHosts9854(t, text)
			if len(hosts) != 1 {
				t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
			}
			if hosts[0].Port != 111 {
				t.Fatalf("port = %d, want 111 (first applied group wins, %s, #9854)", hosts[0].Port, tc.name)
			}
		})
	}
}

// TestSyslogDupHost9854FlatBarePlusBody covers the flat-set shape that is
// NOT immune: a bare `set ... host X` leaf plus a `set ... host X <body>`
// container are separate nodes (ast_edit.go:508-553 vs :720-738), so the
// coalescing folds them in both orders. The node count is the
// anti-vacuity pin: without two nodes the merge below would prove nothing.
func TestSyslogDupHost9854FlatBarePlusBody(t *testing.T) {
	orders := [][]string{
		{"set system syslog host 10.0.0.1", "set system syslog host 10.0.0.1 any any"},
		{"set system syslog host 10.0.0.1 any any", "set system syslog host 10.0.0.1"},
	}
	for i, cmds := range orders {
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("order %d: ParseSetCommand(%q): %v", i, cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("order %d: SetPath(%q): %v", i, cmd, err)
			}
		}
		nodes := 0
		for _, sys := range tree.FindChildren("system") {
			for _, sl := range sys.FindChildren("syslog") {
				nodes += len(sl.FindChildren("host"))
			}
		}
		if nodes != 2 {
			t.Fatalf("order %d: %d host nodes, want 2 (the bare leaf and the body container must stay separate pre-merge, #9854)", i, nodes)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("order %d: CompileConfig: %v", i, err)
		}
		hosts := cfg.System.Syslog.Hosts
		if len(hosts) != 1 {
			t.Fatalf("order %d: compiled %d hosts, want 1 (#9854)", i, len(hosts))
		}
		if len(hosts[0].Facilities) != 1 || hosts[0].Facilities[0] != (SyslogFacility{Facility: "any", Severity: "any"}) {
			t.Fatalf("order %d: facilities = %+v, want [any any] (#9854)", i, hosts[0].Facilities)
		}
	}
}

// TestSyslogDupHost9854SourceGuardValuelessRepeat pins the source-address
// guard: a valueless `source-address;` repeat in a later instance must not
// wipe the address an earlier instance recorded. Strict rejects the shape
// ("source-address: missing value"), so this compiles without the commit
// gate — the tolerant path must still coalesce.
func TestSyslogDupHost9854SourceGuardValuelessRepeat(t *testing.T) {
	hosts := compileSyslogHostsLenient9854(t, `system { syslog {
		host 10.0.0.1 { source-address 10.9.9.9; }
		host 10.0.0.1 { source-address; }
	} }`)
	if len(hosts) != 1 {
		t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
	}
	if hosts[0].SourceAddress != "10.9.9.9" {
		t.Fatalf("source-address = %q, want 10.9.9.9 (the valueless repeat wiped it, #9854)", hosts[0].SourceAddress)
	}
}

// TestSyslogDupHost9854AllowDuplicatesOr pins the flag merge in BOTH
// directions: set in either instance, observed on the merged destination,
// with the other instance's facilities surviving.
func TestSyslogDupHost9854AllowDuplicatesOr(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			"flag first",
			`system { syslog { host 10.0.0.1 { allow-duplicates; } host 10.0.0.1 { any any; } } }`,
		},
		{
			"flag second",
			`system { syslog { host 10.0.0.1 { any any; } host 10.0.0.1 { allow-duplicates; } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts := compileSyslogHosts9854(t, tc.text)
			if len(hosts) != 1 {
				t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
			}
			if !hosts[0].AllowDuplicates {
				t.Fatalf("allow-duplicates = false, want true (%s, #9854)", tc.name)
			}
			if len(hosts[0].Facilities) != 1 {
				t.Fatalf("facilities = %+v, want the other instance's pair to survive (%s, #9854)", hosts[0].Facilities, tc.name)
			}
		})
	}
}

// TestSyslogDupHost9854ExactPairDedupe pins the hier/flat parity for
// repeated identical pairs: flat-set skips an exact duplicate leaf, so
// `set ... any any` twice is one pair, and both hierarchical shapes — one
// instance carrying the pair twice, two instances carrying it once each —
// must be one pair too. Same-facility DIFFERENT-severity pairs are not
// deduped (covered by FacilitiesMergeInOrder).
func TestSyslogDupHost9854ExactPairDedupe(t *testing.T) {
	hosts := compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { any any; }
		host 10.0.0.1 { any any; }
	} }`)
	if len(hosts) != 1 || len(hosts[0].Facilities) != 1 {
		t.Fatalf("two-instance facilities = %+v, want exactly one [any any] (#9854)", facilities9854(hosts))
	}

	hosts = compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { any any; any any; }
	} }`)
	if len(hosts) != 1 || len(hosts[0].Facilities) != 1 {
		t.Fatalf("single-instance facilities = %+v, want exactly one [any any] (#9854)", facilities9854(hosts))
	}

	flat := &ConfigTree{}
	for _, cmd := range []string{
		"set system syslog host 10.0.0.1 any any",
		"set system syslog host 10.0.0.1 any any",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := flat.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	flatCfg, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("CompileConfig(flat): %v", err)
	}
	if flatCfg.System.Syslog == nil || len(flatCfg.System.Syslog.Hosts) != 1 ||
		len(flatCfg.System.Syslog.Hosts[0].Facilities) != 1 {
		t.Fatalf("flat-set facilities = %+v, want exactly one [any any] (the parity target, #9854)", flatCfg.System.Syslog)
	}
}

// TestSyslogDupHost9854DistinctAddressesDoNotFold is the control the merge
// must not break: two genuinely distinct addresses stay two destinations, in
// first-seen order, each carrying only its own statements.
func TestSyslogDupHost9854DistinctAddressesDoNotFold(t *testing.T) {
	hosts := compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { any warning; }
		host 10.0.0.2 { daemon info; }
	} }`)
	if len(hosts) != 2 {
		t.Fatalf("compiled %d hosts, want 2 distinct destinations (#9854)", len(hosts))
	}
	if hosts[0].Address != "10.0.0.1" || hosts[1].Address != "10.0.0.2" {
		t.Fatalf("addresses = [%q %q], want [10.0.0.1 10.0.0.2] in order (#9854)", hosts[0].Address, hosts[1].Address)
	}
	if len(hosts[0].Facilities) != 1 || hosts[0].Facilities[0] != (SyslogFacility{Facility: "any", Severity: "warning"}) {
		t.Fatalf("host 10.0.0.1 facilities = %+v, want only its own pair (#9854)", hosts[0].Facilities)
	}
	if len(hosts[1].Facilities) != 1 || hosts[1].Facilities[0] != (SyslogFacility{Facility: "daemon", Severity: "info"}) {
		t.Fatalf("host 10.0.0.2 facilities = %+v, want only its own pair (#9854)", hosts[1].Facilities)
	}
}

// TestSyslogDupHost9854SingleHostUnchanged is the byte-identical negative
// control: one host statement compiles exactly as before the find-or-create
// change (no dedup of DISTINCT pairs, no reordering, scalars intact).
func TestSyslogDupHost9854SingleHostUnchanged(t *testing.T) {
	hosts := compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { source-address 10.9.9.9; port 5514; allow-duplicates; any warning; daemon info; }
	} }`)
	if len(hosts) != 1 {
		t.Fatalf("compiled %d hosts, want 1 (#9854)", len(hosts))
	}
	h := hosts[0]
	if h.SourceAddress != "10.9.9.9" || h.Port != 5514 || !h.AllowDuplicates {
		t.Fatalf("scalars = src %q port %d allowDup %v, want 10.9.9.9/5514/true (#9854)", h.SourceAddress, h.Port, h.AllowDuplicates)
	}
	want := []SyslogFacility{{Facility: "any", Severity: "warning"}, {Facility: "daemon", Severity: "info"}}
	if len(h.Facilities) != 2 || h.Facilities[0] != want[0] || h.Facilities[1] != want[1] {
		t.Fatalf("facilities = %+v, want %+v (#9854)", h.Facilities, want)
	}
}

// TestSyslogDupHost9854MatchesFlatSet pins the conservation claim: the
// hierarchical duplicate now compiles what the flat-set spelling always did.
func TestSyslogDupHost9854MatchesFlatSet(t *testing.T) {
	hier := compileSyslogHosts9854(t, `system { syslog {
		host 10.0.0.1 { any warning; }
		host 10.0.0.1 { daemon info; }
	} }`)

	flat := &ConfigTree{}
	for _, cmd := range []string{
		"set system syslog host 10.0.0.1 any warning",
		"set system syslog host 10.0.0.1 daemon info",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := flat.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	flatCfg, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("CompileConfig(flat): %v", err)
	}
	if flatCfg.System.Syslog == nil || len(flatCfg.System.Syslog.Hosts) != 1 {
		t.Fatalf("flat-set compiled %+v, want 1 host (the spelling that already worked, #9854)", flatCfg.System.Syslog)
	}
	if len(hier) != 1 {
		t.Fatalf("hierarchical compiled %d hosts, want 1 like flat-set (#9854)", len(hier))
	}
	hf, ff := hier[0].Facilities, flatCfg.System.Syslog.Hosts[0].Facilities
	if len(hf) != len(ff) {
		t.Fatalf("hier facilities = %+v, flat = %+v (#9854)", hf, ff)
	}
	for i := range hf {
		if hf[i] != ff[i] {
			t.Fatalf("hier facilities = %+v, flat = %+v (#9854)", hf, ff)
		}
	}
}
