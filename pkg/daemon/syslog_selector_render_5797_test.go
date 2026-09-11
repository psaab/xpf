package daemon

// #5797 render-site binding.
//
// syslog_selector_token_5797_test.go proves the PREDICATES
// (syslogSelectorFacilitySafe / syslogSelectorSeveritySafe) classify tokens
// correctly, per position. That is scaffolding:
// it stays green if both belt call sites are deleted, because nothing in it
// reaches production. This file binds the CONSUMER — it drives
// syslogDropinContents, the function that actually renders the rsyslog
// drop-ins, and asserts on the rendered bytes. Removing either
// `if !syslogSelector...Safe(...)` guard turns these RED.
//
// Four properties, one per failure the belt exists to prevent:
//
//  1. a safe destination still renders (the belt is not a blanket refusal),
//  2. an unsafe file/user token is OMITTED from the rendered set,
//  3. a drop-in a previous apply wrote for a now-unsafe destination is
//     REMOVED from disk, not merely left un-rewritten,
//  4. the skip is reported to the operator.
//
// Plus the reachability chain, which is why this matters at all: an unsafe
// FACILITY is not a tolerant-load curiosity, it passes SchemaValidate.

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// renderPrefix mirrors applySyslogFiles' drop-in filename prefix.
const renderPrefix = "10-xpf-"

// syslogCfg builds a *config.Config carrying the given file and user
// destinations, the shape applySyslogFiles consumes.
func syslogCfg(files []*config.SyslogFileConfig, users []*config.SyslogUserConfig) *config.Config {
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{Files: files, Users: users}
	return cfg
}

// renderedFor returns the drop-in body syslogDropinContents produced for the
// named file destination, and whether it rendered at all.
func renderedFor(cfg *config.Config, confFile string) (string, bool) {
	got := syslogDropinContents(cfg, renderPrefix)
	body, ok := got[confFile]
	return body, ok
}

// TestSyslogRenderOmitsUnsafeFileToken_5797 is the fail-on-revert guard for the
// FILE belt. Each case pairs an unsafe destination with a safe sibling: the
// unsafe one must be absent from the rendered set and the safe one present, so
// a "reject everything" implementation fails just as loudly as a "reject
// nothing" one.
//
// Reverting `if !syslogSelectorFacilitySafe(f.Facility) || ...` in
// syslogDropinContents renders `10-xpf-evil.conf` and this fails, printing the
// rsyslog directive that would have been written.
func TestSyslogRenderOmitsUnsafeFileToken_5797(t *testing.T) {
	for _, tc := range []struct {
		name     string
		facility string
		severity string
	}{
		// Commit-reachable: the facility is the schema's unvalidated wildcard key.
		{"facility statement separator", "daemon;*.* /tmp/pwn", "info"},
		{"facility pushes an action field", "* @@collector.example:514", "info"},
		{"facility selector dot", "daemon.info", "info"},
		// #6829: ISOLATED metacharacters, one unsafe byte per row. The rows
		// above each carry several, so a mutation admitting exactly one of them
		// leaves the whole table green — measured: adding `case c == ';'` to
		// syslogSelectorAtomSafe reddened only the `both unsafe` row below,
		// because every other `;` row is also rejected for its `*`, `.` or
		// space. These rows make each byte bind on its own.
		{"facility statement separator alone", "daemon;x", "info"},
		{"facility space alone", "daemon local7", "info"},
		{"facility slash alone", "var/log/pwn", "info"},
		{"severity statement separator alone", "daemon", "info;y"},
		{"severity space alone", "daemon", "info warning"},
		// Tolerant-load / peer-sync only: the severity is enum-gated at commit.
		{"severity pushes an action field", "daemon", "* @@collector.example:514"},
		{"severity statement separator", "daemon", "info;*.*"},
		// #6829 NIT: a literal newline is reachable on NEITHER path — strict
		// rejects control characters and the tolerant path sanitizes them to a
		// space, so this row is a defence-in-depth characterization of the
		// predicate, not a reachable input. It sits under the tolerant-load
		// heading for grouping only; the belt's own comment already says this,
		// and mislabelling the row re-taught the misconception that comment
		// exists to correct.
		{"severity newline (predicate only, reachable on no path)", "daemon", "info\n*.* /tmp/pwn"},
		// Both halves unsafe.
		{"both unsafe", "daemon;x", "info;y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg([]*config.SyslogFileConfig{
				{Name: "evil", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
				{Name: "audit", Selectors: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
			}, nil)

			if body, ok := renderedFor(cfg, renderPrefix+"evil.conf"); ok {
				t.Errorf("file destination with facility=%q severity=%q RENDERED an rsyslog "+
					"drop-in; the selector belt at the render site is not consulted (#5797).\n"+
					"written content:\n%s", tc.facility, tc.severity, body)
			}
			if _, ok := renderedFor(cfg, renderPrefix+"audit.conf"); !ok {
				t.Errorf("the safe sibling destination was dropped too — an unsafe token must " +
					"skip ONLY its own destination")
			}
		})
	}
}

// TestSyslogRenderOmitsUnsafeUserToken_5797 is the same guard for the USER
// belt, which is a separate call site: reverting only the file belt leaves this
// green, and reverting only the user belt leaves the file test green. Both are
// needed to pin both lines.
func TestSyslogRenderOmitsUnsafeUserToken_5797(t *testing.T) {
	for _, tc := range []struct {
		name     string
		facility string
		severity string
	}{
		{"facility statement separator", "daemon;*.*", "info"},
		{"facility pushes an action field", "* @@collector.example:514", "info"},
		{"severity pushes an action field", "daemon", "* @@collector.example:514"},
		{"severity control byte", "daemon", "info\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg(nil, []*config.SyslogUserConfig{
				{User: "root", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
				{User: "operator", Selectors: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
			})

			if body, ok := renderedFor(cfg, renderPrefix+"user-root.conf"); ok {
				t.Errorf("user destination with facility=%q severity=%q RENDERED an rsyslog "+
					"drop-in; the selector belt at the render site is not consulted (#5797).\n"+
					"written content:\n%s", tc.facility, tc.severity, body)
			}
			if _, ok := renderedFor(cfg, renderPrefix+"user-operator.conf"); !ok {
				t.Errorf("the safe sibling user destination was dropped too — an unsafe token " +
					"must skip ONLY its own destination")
			}
		})
	}
}

// TestSyslogRenderSafeTokensReachOutput_5797 is the positive control the two
// omission tests lean on. It asserts the exact rendered bytes for the ordinary
// vocabulary, including the `any`/empty wildcard folding and the change-log ->
// local6 remap, so a belt that quietly narrowed to a hardcoded facility list
// (dropping `authorization` and friends) fails here rather than silently
// deleting operator destinations.
func TestSyslogRenderSafeTokensReachOutput_5797(t *testing.T) {
	for _, tc := range []struct {
		name     string
		facility string
		severity string
		want     string
	}{
		{"mapped facility", "daemon", "info", "daemon.info\t/var/log/d\n"},
		{"empty folds to wildcard", "", "", "*.*\t/var/log/d\n"},
		{"any folds to wildcard", "any", "any", "*.*\t/var/log/d\n"},
		{"change-log remaps to local6", "change-log", "warning", "local6.warning\t/var/log/d\n"},
		// Junos spellings the runtime cannot map to a numeric facility. They
		// are still valid rsyslog-side configuration and must render.
		{"unmapped Junos facility", "authorization", "critical", "authorization.critical\t/var/log/d\n"},
		{"hyphenated Junos facility", "interactive-commands", "notice", "interactive-commands.notice\t/var/log/d\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg([]*config.SyslogFileConfig{
				{Name: "d", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
			}, nil)

			body, ok := renderedFor(cfg, renderPrefix+"d.conf")
			if !ok {
				t.Fatalf("safe destination facility=%q severity=%q did not render; the belt is "+
					"scoped wider than the injection surface it guards", tc.facility, tc.severity)
			}
			if want := "# Managed by xpf — do not edit\n" + tc.want; body != want {
				t.Errorf("rendered drop-in = %q, want %q", body, want)
			}
		})
	}
}

// TestSyslogRenderNativeSelectorSyntaxReachesOutput_6829 is the regression
// guard for the belt's own scope. It asserts the EMITTED SELECTOR TEXT for the
// two rsyslog spellings an earlier revision of this belt rejected, because "no
// warning fired" is not the property that matters — the property is that the
// operator's destination still routes the records they asked for.
//
// Both spellings are strict-commit-clean: `auth,authpriv` and `*` pass
// SchemaValidate (measured — the facility is the schema's unvalidated wildcard
// KEY, see TestSyslogRenderUnsafeFacilityIsLoadReachable_5797 for the same
// chain driven end to end) and compile verbatim. Before any belt existed both
// rendered a working drop-in. A belt that dropped them therefore did not
// harden the render path, it deleted a working destination on upgrade — the
// drop-in is not merely left unwritten, reconcileSyslogDropins REMOVES the one
// a previous apply wrote.
//
// RED-on-revert: narrow either position predicate back to a single
// `[A-Za-z0-9-]` allowlist and every row here fails with the rendered-vs-want
// diff, naming the selector that no longer reaches disk.
func TestSyslogRenderNativeSelectorSyntaxReachesOutput_6829(t *testing.T) {
	for _, tc := range []struct {
		name     string
		facility string
		severity string
		want     string
	}{
		// The facility comma list: rsyslog's native multiple-facility operator.
		{"comma facility list", "auth,authpriv", "info", "auth,authpriv.info"},
		{"three-member facility list", "auth,authpriv,daemon", "warning", "auth,authpriv,daemon.warning"},
		// The bare `*`. Distinct from the `any` -> `*` fold already covered by
		// TestSyslogRenderSafeTokensReachOutput_5797: this is the operator
		// AUTHORING `*`, which commits clean and must survive the belt on its
		// own rather than by being rewritten.
		{"bare wildcard facility", "*", "info", "*.info"},
		// The priority position's own syntax.
		{"wildcard severity", "daemon", "*", "daemon.*"},
		{"exact-priority modifier", "daemon", "=info", "daemon.=info"},
		{"exclude-priority modifier", "daemon", "!info", "daemon.!info"},
		{"exclude-exact modifier", "daemon", "!=info", "daemon.!=info"},
		// Both positions at once.
		{"list facility and modified severity", "auth,authpriv", "!=debug", "auth,authpriv.!=debug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg([]*config.SyslogFileConfig{
				{Name: "d", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
			}, []*config.SyslogUserConfig{
				{User: "root", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
			})

			// The FILE call site.
			body, ok := renderedFor(cfg, renderPrefix+"d.conf")
			if !ok {
				t.Fatalf("facility=%q severity=%q rendered NO file drop-in. This spelling is "+
					"native rsyslog syntax and commits clean, so dropping it deletes a working "+
					"destination on upgrade rather than hardening anything (#5797/#6829)",
					tc.facility, tc.severity)
			}
			if want := "# Managed by xpf — do not edit\n" + tc.want + "\t/var/log/d\n"; body != want {
				t.Errorf("rendered file drop-in = %q, want %q", body, want)
			}

			// The USER call site is a separate `if !syslogSelector...` pair;
			// widening only one leaves the other deleting destinations.
			ubody, uok := renderedFor(cfg, renderPrefix+"user-root.conf")
			if !uok {
				t.Fatalf("facility=%q severity=%q rendered NO user drop-in — the user call site "+
					"did not get the same position-aware predicates as the file site",
					tc.facility, tc.severity)
			}
			if want := "# Managed by xpf — do not edit\n" + tc.want + "\t:omusrmsg:root\n"; ubody != want {
				t.Errorf("rendered user drop-in = %q, want %q", ubody, want)
			}
		})
	}
}

// TestSyslogRenderOmitsMalformedFacilityList_6829 is the over-reach guard for
// the comma admission above. Accepting `auth,authpriv` must not degrade into
// "a comma makes the token safe": the list is admitted PER MEMBER, so an empty
// member (a malformed list) and a member carrying a payload are both still
// dropped at the render site.
//
// Each row pairs the rejected destination with a safe sibling, so a belt that
// regressed to rejecting everything fails just as loudly as one that regressed
// to accepting everything.
func TestSyslogRenderOmitsMalformedFacilityList_6829(t *testing.T) {
	for _, tc := range []struct {
		name     string
		facility string
	}{
		{"trailing empty member", "auth,"},
		{"leading empty member", ",auth"},
		{"interior empty member", "auth,,authpriv"},
		{"comma only", ","},
		// The load-bearing pair: the comma must not carry an injection in.
		{"member carries a statement separator", "auth,authpriv;*.* /tmp/pwn"},
		{"member carries a space", "auth,authpriv @@collector.example:514"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg([]*config.SyslogFileConfig{
				{Name: "evil", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: "info"}}},
				{Name: "audit", Selectors: []config.SyslogFacility{{Facility: "auth,authpriv", Severity: "info"}}},
			}, nil)

			if body, ok := renderedFor(cfg, renderPrefix+"evil.conf"); ok {
				t.Errorf("facility %q RENDERED an rsyslog drop-in. The comma operator is "+
					"admitted per MEMBER, not as a blanket pass on any token containing a "+
					"comma (#6829).\nwritten content:\n%s", tc.facility, body)
			}
			if _, ok := renderedFor(cfg, renderPrefix+"audit.conf"); !ok {
				t.Errorf("the well-formed sibling list `auth,authpriv` was dropped too — a " +
					"malformed list must skip ONLY its own destination")
			}
		})
	}
}

// TestSyslogRenderRemovesStaleDropinOnUnsafeToken_5797 is the end-to-end
// property, and the one that separates "declines to write" from "fails closed".
// A destination that rendered safely on a previous apply already has a drop-in
// on disk. When a later config makes its token unsafe, omitting it from the
// desired set is only half the job — the reconcile must DELETE the file, and
// `changed` must flip so rsyslog is restarted and stops honouring the old rule.
//
// This runs the production pair (syslogDropinContents -> reconcileSyslogDropins)
// against a temp dir, which is exactly what applySyslogFiles does with
// /etc/rsyslog.d. Reverting the file belt makes the drop-in be REWRITTEN with
// the injected selector instead of removed.
func TestSyslogRenderRemovesStaleDropinOnUnsafeToken_5797(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, renderPrefix+"audit.conf")
	if err := os.WriteFile(stale, []byte("# Managed by xpf — do not edit\ndaemon.info\t/var/log/audit\n"), 0644); err != nil {
		t.Fatalf("seed previously-rendered drop-in: %v", err)
	}
	keep := filepath.Join(dir, renderPrefix+"ops.conf")
	if err := os.WriteFile(keep, []byte("# Managed by xpf — do not edit\ndaemon.info\t/var/log/ops\n"), 0644); err != nil {
		t.Fatalf("seed sibling drop-in: %v", err)
	}

	// The operator (or a peer sync) changes `audit`'s facility to an injecting
	// value. `ops` is untouched.
	cfg := syslogCfg([]*config.SyslogFileConfig{
		{Name: "audit", Selectors: []config.SyslogFacility{{Facility: "daemon;*.* @@collector.example:514", Severity: "info"}}},
		{Name: "ops", Selectors: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
	}, nil)

	changed := reconcileSyslogDropins(dir, renderPrefix, syslogDropinContents(cfg, renderPrefix))

	if body, err := os.ReadFile(stale); err == nil {
		t.Errorf("the drop-in for the now-unsafe destination survived on disk; rsyslog keeps "+
			"honouring it until the next restart (#5797). content:\n%s", body)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat stale drop-in: %v", err)
	}
	if !changed {
		t.Errorf("removing the unsafe destination's drop-in must set changed=true so rsyslog " +
			"is restarted and unloads the stale rule")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("the safe sibling's drop-in must survive: %v", err)
	}
}

// TestSyslogRenderWarnsOnSkippedDestination_5797 pins property 4. A silent skip
// is its own defect: the operator's destination stops receiving logs with no
// signal, which reads as a logging outage rather than a rejected config. Both
// call sites must name the destination they dropped.
func TestSyslogRenderWarnsOnSkippedDestination_5797(t *testing.T) {
	t.Run("file skip warns", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		syslogDropinContents(syslogCfg([]*config.SyslogFileConfig{
			{Name: "audit", Selectors: []config.SyslogFacility{{Facility: "daemon;*.*", Severity: "info"}}},
		}, nil), renderPrefix)

		got := buf.String()
		if !strings.Contains(got, "unsafe selector token") {
			t.Errorf("skipping a file destination emitted no warning; the operator sees a "+
				"silent logging outage (#5797). captured:\n%s", got)
		}
		if !strings.Contains(got, "audit") {
			t.Errorf("the warning must name the dropped destination. captured:\n%s", got)
		}
	})

	t.Run("user skip warns", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		syslogDropinContents(syslogCfg(nil, []*config.SyslogUserConfig{
			{User: "root", Selectors: []config.SyslogFacility{{Facility: "daemon", Severity: "info;*.*"}}},
		}), renderPrefix)

		got := buf.String()
		if !strings.Contains(got, "unsafe selector token") {
			t.Errorf("skipping a user destination emitted no warning (#5797). captured:\n%s", got)
		}
		if !strings.Contains(got, "root") {
			t.Errorf("the warning must name the dropped user. captured:\n%s", got)
		}
	})

	// Negative control: a clean config must stay quiet, or the warning trains
	// operators to ignore it.
	t.Run("safe config is quiet", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		syslogDropinContents(syslogCfg(
			[]*config.SyslogFileConfig{{Name: "audit", Selectors: []config.SyslogFacility{{Facility: "authorization", Severity: "info"}}}},
			[]*config.SyslogUserConfig{{User: "*", Selectors: []config.SyslogFacility{{Facility: "any", Severity: "emergency"}}}},
		), renderPrefix)

		if got := buf.String(); strings.Contains(got, "unsafe selector token") {
			t.Errorf("a config with only legitimate tokens must not warn. captured:\n%s", got)
		}
	})
}

// TestSyslogRenderUnsafeFacilityIsLoadReachable_5797 is the reachability chain,
// and the reason the file/user belts are load-bearing rather than
// defence-in-depth.
//
// # Why this test changed name and premise (#6844)
//
// It used to assert that SchemaValidate ACCEPTS an injecting facility, as a
// deliberate tripwire: "if a future change adds a key validator to the
// `<facility> <severity>` wildcard, this test fails -- that is the intent. It
// forces whoever adds that gate to re-derive whether the render belt is still
// needed instead of deleting it on the assumption that the schema already
// covers this."
//
// #6844 added that gate, the tripwire fired, and here is the re-derivation.
//
// The belt is STILL the only line of defence, because the new gate is not
// unconditional. SchemaValidate is strict only on the operator-driven commit /
// commit-check path; Store.compileTreeLenient downgrades a violation to a
// WARNING on the tolerant Load / SyncApply ingress, deliberately, so a persisted
// config written by an older binary does not blackout-boot the node and an
// un-upgraded cluster primary does not alarm-loop HA config sync (#1319/#1960).
// An injecting facility written before the gate existed therefore still LOADS,
// still compiles, and still arrives at the render function -- which is exactly
// the path this test drives.
//
// So the chain is unchanged in substance and narrower in premise: what the
// commit path now rejects, the tolerant path still admits.
//
// WHAT THIS TEST DOES AND DOES NOT PROVE. It calls config.CompileConfig, not
// Store.compileTreeLenient, so it does not itself demonstrate the tolerant
// ingress — an earlier revision claimed otherwise in its name and comment, and
// a regression routing Load through STRICT compilation would have left it
// green. What it proves is the half it actually drives: the value compiles, it
// reaches the render function, and the belt drops it. The tolerant-ingress half
// is proved where it happens, by
// pkg/configstore's TestLoadToleratesAnInjectableSyslogFacility_6844, which
// drives the real Store.Load and asserts the node still boots with an active
// config.
func TestSyslogRenderUnsafeFacilityIsLoadReachable_5797(t *testing.T) {
	const injecting = "daemon;*.* /tmp/pwn"

	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand(`set system syslog file audit "` + injecting + `" info`)
	if err != nil {
		t.Fatalf("parse set command: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	// The COMMIT path rejects it (#6844). Pinned here rather than merely
	// assumed: if that gate is ever removed, this fails and says so, and the
	// tripwire the original test installed keeps working in the other
	// direction.
	if err := config.SchemaValidate(tree, nil); err == nil {
		t.Fatalf("SchemaValidate ACCEPTED %q. The #6844 facility key gate is gone, so an "+
			"ORDINARY commit can once again land an injecting selector -- the render belt "+
			"below is then the only thing standing between it and a written drop-in.",
			injecting)
	}

	// The TOLERANT path still admits it: the compiler is unchanged, and
	// Store.compileTreeLenient downgrades the schema violation to a warning.
	// This is the reachability premise the belt exists for.
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v\nThe rejection has migrated out of SchemaValidate and "+
			"into the compiler, which makes it unconditional and blackout-boots a node "+
			"carrying a config an older binary accepted (#1960).", err)
	}
	if len(cfg.System.Syslog.Files) != 1 || len(cfg.System.Syslog.Files[0].Selectors) != 1 ||
		cfg.System.Syslog.Files[0].Selectors[0].Facility != injecting {
		t.Fatalf("compiled facility = %+v, want the verbatim %q — the reachability premise of "+
			"this test no longer holds", cfg.System.Syslog.Files, injecting)
	}

	if body, ok := renderedFor(cfg, renderPrefix+"audit.conf"); ok {
		t.Errorf("a config reaching render via the tolerant load path wrote an rsyslog "+
			"drop-in built from %q (#5797):\n%s", injecting, body)
	}
}

// TestApplySystemSyslogWarnsOnUnmappedFacility_5797 binds the OTHER half of the
// PR: ParseFacilityChecked's extra bit is only worth having if the daemon acts
// on it. Reverting ParseFacilityChecked to `return ParseFacility(name), true`,
// or dropping the `if !known` warn in applySystemSyslog, makes this fail.
//
// Hermeticity (#6829): applySystemSyslog DOES dial — NewSyslogClientWithSource
// resolves and connects, and on UDP a failure returns a nil client. An earlier
// comment here claimed UDP "resolves without a connect", which was simply
// false: under a restricted runner the socket call was refused and this test
// died at client construction, never reaching ParseFacilityChecked, so it
// asserted nothing and failed for an unrelated reason. The classification and
// its warning now run BEFORE the dial (daemon_system.go), so the assertions
// below hold whether or not the sandbox permits a socket. The
// documentation-range literal (RFC 5737) is still used so no real host is
// contacted when sockets ARE permitted.
func TestApplySystemSyslogWarnsOnUnmappedFacility_5797(t *testing.T) {
	apply := func(t *testing.T, facility string) string {
		t.Helper()
		buf := captureRenderedWarnings(t)

		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })

		cfg := &config.Config{}
		cfg.System.Syslog = &config.SystemSyslogConfig{
			Hosts: []*config.SyslogHostConfig{{
				Address:    "192.0.2.10",
				Facilities: []config.SyslogFacility{{Facility: facility, Severity: "info"}},
			}},
		}
		d.applySystemSyslog(cfg)
		return buf.String()
	}

	// A facility name the runtime cannot map: the substitution to local0 must be
	// reported.
	//
	// #6830 SPLIT THE MESSAGE, NOT THE PROPERTY. This used to pin the literal
	// "unmapped facility name" for every case. The warning now discriminates a
	// real Junos facility this box misfiles from a name in neither vocabulary,
	// because those need different operator actions — so the assertion moves
	// from one literal to "warned, named the facility, and CLASSIFIED it
	// correctly", which is strictly stronger than what it replaced.
	for _, tc := range []struct {
		facility string
	}{
		// #6830 wired the documented Junos table into the emit path, so
		// `authorization` / `kernel` / `interactive-commands` are now MAPPED and
		// no longer warn -- that is the fix, not a regression. What still
		// reaches this warning is a name in NEITHER vocabulary, plus the Junos
		// names that have no documented wire facility at all.
		{"security"},
		{"external"},
		{"typo"},
	} {
		facility := tc.facility
		t.Run("unmapped/"+facility, func(t *testing.T) {
			got := apply(t, facility)
			if !strings.Contains(got, "unrecognized facility name") {
				t.Errorf("host facility %q silently became local0 with no warning; records leave "+
					"under a facility the configuration never names (#5797). captured:\n%s",
					facility, got)
			}
			if !strings.Contains(got, facility) {
				t.Errorf("the warning must name the unmapped facility %q. captured:\n%s", facility, got)
			}
			// #6830 collapsed this classification, and the collapse is the fix.
			//
			// The MISFILED arm described a name IN the documented Junos
			// vocabulary that this box emitted under a different code.
			// ParseFacility now consults that table first, so the two agree by
			// construction and the arm has no reachable input. Every name that
			// still reaches this warning is in neither vocabulary, or is Junos
			// with no documented wire facility -- a probable typo either way,
			// which is the one arm that remains.
			//
			// The property the MISFILED arm protected did not disappear, it
			// moved to where it can actually be asserted: pkg/logging's
			// TestNothingInTheTableIsMisfiled6830 quantifies over the whole
			// table, so a row added without wiring reds there.
			if !strings.Contains(got, "unrecognized facility name") {
				t.Errorf("%q must be reported as a probable typo (#6830). captured:\n%s",
					facility, got)
			}
		})
	}

	// Negative control: a mapped name must not warn.
	// #6830 added the nine documented Junos names to this control: they are now
	// mapped, so a correct config using them must stay quiet. Without them the
	// control would not cover the names the flip actually moved.
	for _, facility := range []string{
		"daemon", "local0", "change-log", "auth",
		"authorization", "kernel", "interactive-commands", "conflict-log",
		"dfc", "firewall", "ftp", "ntp", "pfe",
	} {
		t.Run("mapped/"+facility, func(t *testing.T) {
			if got := apply(t, facility); strings.Contains(got, "unmapped facility name") {
				t.Errorf("host facility %q is mapped by ParseFacility but warned as unmapped; a "+
					"correct config must stay quiet. captured:\n%s", facility, got)
			}
		})
	}
}

// TestApplySystemSyslogWarnsWhenClientDialFails_6829 binds the ordering fix:
// the unmapped-facility classification must run BEFORE the client is
// constructed, because construction DIALS.
//
// This is not only a test-hermeticity concern. NewSyslogClientWithSource
// resolves and dials, and on UDP a failure returns a NIL client, so
// applySystemSyslog's `continue` skipped everything after it. An operator whose
// collector address is unreachable — or whose source-address binding is wrong —
// therefore never learned that their facility name was ALSO unmappable, which
// is precisely the diagnosis that does not depend on the network working. With
// the classification below the dial, the warning is lost exactly when the
// operator has the most to debug.
//
// The failure is forced without touching the network: binding the source to a
// documentation address (RFC 5737) that is on no local interface fails
// immediately, with no DNS lookup and no packet sent.
//
// #6829: the errno is ENVIRONMENT-DEPENDENT and an earlier version of this
// comment over-specified it. On a host that may create sockets the bind fails
// with EADDRNOTAVAIL (measured: errors.Is(err, syscall.EADDRNOTAVAIL) true,
// EPERM false). In a sandbox that denies socket CREATION the call fails earlier
// with EPERM, never reaching the bind. This test does not depend on which: its
// premise asserts only that client construction FAILED — the "failed to create
// system syslog client" warning — which holds under either. So the hermeticity
// holds, but for a weaker reason than "no sandbox dependency" claimed.
//
// RED-on-revert: move the ParseFacilityChecked block back below the
// NewSyslogClientWithSource call in applySystemSyslog and this goes silent,
// because the `continue` fires first.
func TestApplySystemSyslogWarnsWhenClientDialFails_6829(t *testing.T) {
	buf := captureRenderedWarnings(t)

	d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })

	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{
		Hosts: []*config.SyslogHostConfig{{
			Address: "192.0.2.10",
			// On no local interface, so the bind fails and the client is nil.
			SourceAddress: "192.0.2.1",
			Facilities:    []config.SyslogFacility{{Facility: "security", Severity: "info"}},
		}},
	}
	d.applySystemSyslog(cfg)
	got := buf.String()

	// Precondition: the dial really did fail, or this test proves nothing about
	// ordering — it would just be the ordinary warning path again.
	if !strings.Contains(got, "failed to create system syslog client") {
		t.Fatalf("premise broken: the client was expected to FAIL construction so the "+
			"ordering matters; captured:\n%s", got)
	}
	// #6830: `security` is in the Junos vocabulary but has no documented wire
	// facility, so it takes the unrecognized arm. The property under test is
	// unchanged -- the classification must not sit behind the dial.
	if !strings.Contains(got, "unrecognized facility name") {
		t.Errorf("the unmapped-facility warning was lost because the client could not be "+
			"constructed — classification must not sit behind the dial (#6829). The "+
			"operator with an unreachable collector is the one who most needs to be "+
			"told their facility name is wrong. captured:\n%s", got)
	}
	if !strings.Contains(got, "security") {
		t.Errorf("the warning must still name the unmapped facility. captured:\n%s", got)
	}

	// #6829 A4 — scope control. The assertions above are the only cell with a
	// SourceAddress, and it also carries an unmapped facility, so they cannot
	// tell "classification runs before the dial" from "classification runs for
	// unmapped names". This cell holds the dial failure fixed and makes the
	// facility MAPPED: the dial-failure warning must still appear (the premise
	// is unchanged) and the unmapped warning must NOT, which is the half the
	// combined fixture could not distinguish.
	t.Run("mapped facility with a failing dial warns only about the dial", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })
		cfg := &config.Config{}
		cfg.System.Syslog = &config.SystemSyslogConfig{
			Hosts: []*config.SyslogHostConfig{{
				Address:       "192.0.2.10",
				SourceAddress: "192.0.2.1",
				Facilities:    []config.SyslogFacility{{Facility: "auth", Severity: "info"}},
			}},
		}
		d.applySystemSyslog(cfg)
		got := buf.String()
		if !strings.Contains(got, "failed to create system syslog client") {
			t.Fatalf("premise broken: the dial was expected to fail; captured:\n%s", got)
		}
		if strings.Contains(got, "unmapped facility name") {
			t.Errorf("`auth` is mapped, so a failing dial must not produce an unmapped-facility "+
				"warning. captured:\n%s", got)
		}
	})
}

// loopbackSyslogSink9359 opens a UDP sink on loopback and returns its port, for a
// cell that needs an INSTALLED client. A UDP client dials at construction
// (pkg/logging/syslog.go) and a failed dial installs nothing, so a collector off
// the box made these cells depend on this host's routing. Measured (#9359): in
// one network namespace, removing the route to 192.0.2.10 turned red exactly the
// two cells that asserted an installed client, and nothing else in pkg/daemon.
// The sink is the test's own, so no other host is contacted and nothing else is
// listening on it.
func loopbackSyslogSink9359(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open a loopback syslog sink: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestApplySystemSyslogFacilityReachesClient_6829 binds the facility VALUE that
// reaches the installed client (A5).
//
// applySystemSyslog computes the facility on one side of the dial and assigns
// it on the other — the split this PR introduced to fix the ordering, and
// exactly the refactor shape that drops a value. Before this test, deleting
// EITHER `facility = f` or `c.Facility = facility` left the whole suite green:
// the warning still fired, so every existing assertion was satisfied while the
// records went out under the wrong facility.
func TestApplySystemSyslogFacilityReachesClient_6829(t *testing.T) {
	apply := func(t *testing.T, facility string) *logging.SyslogClient {
		t.Helper()
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })
		cfg := &config.Config{}
		cfg.System.Syslog = &config.SystemSyslogConfig{
			Hosts: []*config.SyslogHostConfig{{
				Address:    "127.0.0.1",
				Port:       loopbackSyslogSink9359(t),
				Facilities: []config.SyslogFacility{{Facility: facility, Severity: "info"}},
			}},
		}
		d.applySystemSyslog(cfg)
		cs := d.slogHandler.Clients()
		if len(cs) != 1 {
			t.Fatalf("want exactly one installed client, got %d; captured:\n%s", len(cs), buf.String())
		}
		return cs[0]
	}

	t.Run("mapped facility reaches the client", func(t *testing.T) {
		if got := apply(t, "auth").Facility; got != logging.FacilityAuth {
			t.Errorf("installed client Facility = %d, want FacilityAuth (%d) — the authored "+
				"facility must survive the compute/assign split across the dial",
				got, logging.FacilityAuth)
		}
	})

	t.Run("unmapped facility lands on the documented substitution", func(t *testing.T) {
		if got := apply(t, "security").Facility; got != logging.FacilityLocal0 {
			t.Errorf("installed client Facility = %d, want FacilityLocal0 (%d) — the warning "+
				"promises records leave under local0, so that must be what is installed",
				got, logging.FacilityLocal0)
		}
	})

	// The third element of the compute/assign shape: the DEFAULT INITIALIZER.
	//
	// The two subtests above bind `facility = f` and `c.Facility = facility`.
	// Neither reaches `facility := logging.FacilityDaemon`, because both supply
	// a Facilities entry and so take the branch that overwrites it. Replacing
	// the initializer with `var facility int` left pkg/logging, pkg/cli,
	// pkg/daemon and pkg/config all green — the same free-initializer gap the
	// haveFacility guards close on the other two syslog paths, one site over.
	//
	// A host with no `<facility> <severity>` child at all is ordinary config:
	// `set system syslog host 10.0.0.1` alone commits clean. It must keep the
	// daemon default rather than the zero value, which is kern — the bucket
	// receivers reserve for the kernel.
	t.Run("host naming no facility at all keeps the daemon default", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })
		cfg := &config.Config{}
		cfg.System.Syslog = &config.SystemSyslogConfig{
			Hosts: []*config.SyslogHostConfig{{Address: "127.0.0.1", Port: loopbackSyslogSink9359(t)}},
		}
		d.applySystemSyslog(cfg)
		cs := d.slogHandler.Clients()
		if len(cs) != 1 {
			t.Fatalf("want exactly one installed client, got %d; captured:\n%s", len(cs), buf.String())
		}
		got := cs[0].Facility
		if got == logging.FacilityKern {
			t.Fatalf("installed client Facility = %d (FacilityKern) — the default initializer "+
				"was dropped, so a host naming no facility got the zero value of the "+
				"`facility` local instead of FacilityDaemon (%d). Every record from that "+
				"host would be misfiled into the kernel bucket",
				got, logging.FacilityDaemon)
		}
		if got != logging.FacilityDaemon {
			t.Errorf("installed client Facility = %d, want FacilityDaemon (%d)",
				got, logging.FacilityDaemon)
		}
	})
}

// TestApplySystemSyslogWildcardFacilityDoesNotWarn_6829 pins A3: `any` is the
// CANONICAL Junos form (`set system syslog host <ip> any <sev>` is this repo's
// own fixture) and names no facility deliberately. Warning "records will carry
// a facility the configuration does not name" is literally false for it, and a
// warning on a correct config is what trains operators to ignore warnings.
//
// The mapped/unmapped negative controls live in
// TestApplySystemSyslogWarnsOnUnmappedFacility_5797; this pins only the
// wildcard, which is neither.
func TestApplySystemSyslogWildcardFacilityDoesNotWarn_6829(t *testing.T) {
	buf := captureRenderedWarnings(t)
	d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{
		Hosts: []*config.SyslogHostConfig{{
			Address:    "192.0.2.10",
			Facilities: []config.SyslogFacility{{Facility: "any", Severity: "info"}},
		}},
	}
	d.applySystemSyslog(cfg)
	if got := buf.String(); strings.Contains(got, "unmapped facility name") {
		t.Errorf("the canonical `host <ip> any <sev>` form warned about an unmapped "+
			"facility. `any` names no facility on purpose, so the warning's own text "+
			"is false for it. captured:\n%s", got)
	}
}

// TestApplySyslogConfigSecurityStreamWarnsOnUnmappedFacility_6829 binds the A2
// conversion of the SECURITY/AUDIT stream wiring in applySyslogConfig.
//
// That site was left on the unchecked ParseFacility for four rounds on the
// argument that the schema enum gates it. That is true on the STRICT path only:
// configstore.Store downgrades the gate to a warning on Load (boot) and
// SyncApply (HA peer sync) — the same reachability class the severity belt is
// built for. Untold, every audit record on this stream leaves under local0
// while `show system syslog` still reports the authored name, which is the
// worst stream in the daemon to misroute silently.
//
// RED-on-revert: put the site back on logging.ParseFacility, or drop the
// !known warn, and this goes silent.
func TestApplySyslogConfigSecurityStreamWarnsOnUnmappedFacility_6829(t *testing.T) {
	apply := func(t *testing.T, facility string) (string, *logging.EventReader) {
		t.Helper()
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })

		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"audit": {
				Name: "audit", Host: "127.0.0.1", Port: loopbackSyslogSink9359(t),
				Facility: facility, Severity: "info",
			},
		}
		er := logging.NewEventReader(nil, nil)
		d.applySyslogConfig(er, cfg)
		return buf.String(), er
	}

	t.Run("unmapped facility warns", func(t *testing.T) {
		got, er := apply(t, "security")
		// #6829 F2: bind the VALUE on the audit stream — the site this file
		// calls the worst in the daemon to misroute silently. It has the same
		// compute/assign split as the host path, so a log-only assertion cannot
		// see either half being dropped.
		// #6829 round 8: the count is asserted with Fatalf, not folded into the
		// value check. `len(cs) == 1 && ...` evaporates when nothing is
		// installed, so a regression to ZERO clients passed silently — the
		// vacuity is per dimension, and {} == {} is free.
		//
		// The VALUE here is deliberately NOT treated as discriminating:
		// FacilityLocal0 is the constructor default (pkg/logging/syslog.go),
		// so on an unmapped facility "the substitution ran" and "nothing ran"
		// produce the same number and this assertion cannot tell them apart.
		// It is kept as a consistency check on the warning's promise. The
		// discriminating coverage is the mapped subtest and the two-stream
		// subtest below, both of which red when the assign half is dropped.
		cs := er.SyslogClients()
		if len(cs) != 1 {
			t.Fatalf("want exactly one installed audit-stream client, got %d — forwarding "+
				"is deliberately NOT withheld for an unmappable facility, so a regression "+
				"to zero clients is a behaviour change this subtest must catch; captured:\n%s", len(cs), got)
		}
		if cs[0].Facility != logging.FacilityLocal0 {
			t.Errorf("installed audit-stream Facility = %d, want FacilityLocal0 (%d) — the "+
				"warning promises records leave under local0", cs[0].Facility, logging.FacilityLocal0)
		}
		if !strings.Contains(got, "unmapped facility name") {
			t.Errorf("the security/audit stream silently mapped an unmappable facility to "+
				"local0 with no warning — this is the audit path (#5797/#6829). captured:\n%s", got)
		}
		if !strings.Contains(got, "security") {
			t.Errorf("the warning must name the unmapped facility. captured:\n%s", got)
		}
	})

	// #6829 round 8: the ordering property. Construction DIALS; an unmappable
	// facility is the one diagnosis that does not depend on the network being
	// up. Before the compute/assign split the classify block sat BELOW the
	// `client == nil` continue, so a stream whose host does not resolve was
	// skipped and the operator was never told the facility was also unmappable.
	//
	// Measured: a loopback sink constructs fine (1 client); an unresolvable
	// name returns nil,err from the UDP arm (pkg/logging/syslog.go) and installs
	// ZERO. RED-on-revert: move the classify block back below the continue and
	// this subtest goes silent while every other cell stays green.
	t.Run("warns even when client construction fails", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })

		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"audit": {
				Name: "audit", Host: "no-such-host.invalid.", Port: 514,
				Facility: "security", Severity: "info",
			},
		}
		er := logging.NewEventReader(nil, nil)
		d.applySyslogConfig(er, cfg)

		if n := er.SyslogClientCount(); n != 0 {
			t.Fatalf("premise broken: this fixture must FAIL construction so the ordering "+
				"is what is under test; got %d installed clients", n)
		}
		got := buf.String()
		if !strings.Contains(got, "unmapped facility name") {
			t.Errorf("construction failed and the stream was skipped, so the operator was "+
				"never told the facility is ALSO unmappable — the one diagnosis that does "+
				"not need the network up (#6829). captured:\n%s", got)
		}
		if !strings.Contains(got, "security") {
			t.Errorf("the warning must name the unmapped facility. captured:\n%s", got)
		}
	})

	// The value assertion that CAN fail. Two streams in one apply: one
	// unmappable (substitutes to local0) and one mapped to a non-default
	// facility. Dropping the assign half leaves BOTH on the constructor
	// default, so asserting they DIFFER is what the single-stream unmapped cell
	// cannot do.
	t.Run("unmapped and mapped streams get different facilities", func(t *testing.T) {
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })

		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"unmappable": {Name: "unmappable", Host: "127.0.0.1", Port: loopbackSyslogSink9359(t),
				Facility: "security", Severity: "info"},
			"mapped": {Name: "mapped", Host: "127.0.0.1", Port: loopbackSyslogSink9359(t),
				Facility: "auth", Severity: "info"},
		}
		er := logging.NewEventReader(nil, nil)
		d.applySyslogConfig(er, cfg)

		cs := er.SyslogClients()
		if len(cs) != 2 {
			t.Fatalf("want two installed clients, got %d; captured:\n%s", len(cs), buf.String())
		}
		seen := map[int]bool{}
		for _, c := range cs {
			seen[c.Facility] = true
		}
		if !seen[logging.FacilityLocal0] || !seen[logging.FacilityAuth] {
			t.Errorf("installed facilities = %v, want both FacilityLocal0 (%d, the "+
				"substitution) and FacilityAuth (%d, the authored value). Both landing on "+
				"local0 means the assign half was dropped — which the single-stream "+
				"unmapped cell cannot distinguish, because local0 is also the constructor "+
				"default", seen, logging.FacilityLocal0, logging.FacilityAuth)
		}
	})

	t.Run("mapped facility stays quiet", func(t *testing.T) {
		got, er := apply(t, "auth")
		if strings.Contains(got, "unmapped facility name") {
			t.Errorf("`auth` is mapped; a correct config must not warn. captured:\n%s", got)
		}
		cs := er.SyslogClients()
		if len(cs) != 1 {
			t.Fatalf("want one installed audit-stream client, got %d; captured:\n%s", len(cs), got)
		}
		if cs[0].Facility != logging.FacilityAuth {
			t.Errorf("installed audit-stream Facility = %d, want FacilityAuth (%d) — the "+
				"authored facility must survive the compute/assign split", cs[0].Facility, logging.FacilityAuth)
		}
	})

	// #6829 B2: `any` must WARN on a security stream, and this subtest asserted
	// the opposite. The suppression it pinned was borrowed from the system-syslog
	// host/file/user surface, whose facility key is an open-ended schema wildcard
	// and where `host <ip> any <sev>` really is the canonical Junos form. A
	// security stream is a different surface: its facility is
	// ValidateEnum(syslogFacilities) — auth/change-log/daemon/kern/local0-7/
	// syslog/user — with no `any`, and the stream carries a NUMERIC facility, so
	// there is no wildcard for `any` to denote.
	//
	// Because the enum forbids it, `any` cannot arrive by strict commit at all;
	// it arrives only through the tolerant paths (configstore.Store downgrades
	// the gate on Load and SyncApply). Those are precisely the paths this
	// diagnostic exists for, so suppressing there silenced it on its whole
	// population. TestApplySystemSyslogWildcardFacilityDoesNotWarn_6829 keeps the
	// HOST surface quiet and is the control for this inversion.
	t.Run("wildcard any warns on a security stream", func(t *testing.T) {
		got, _ := apply(t, "any")
		if !strings.Contains(got, "unmapped facility name") {
			t.Errorf("`any` on a SECURITY STREAM did not warn. The enum has no `any`, so this "+
				"reached the stream through a tolerant load or a peer sync and was mapped to "+
				"local0 in silence — the exact substitution this diagnostic exists to "+
				"report. captured:\n%s", got)
		}
	})
}

// TestSyslogRenderRejectsLeadingHyphenSelector_6829 is the fail-on-revert guard
// for #6829 B1, driven through the real render site rather than the predicate.
//
// THE VECTOR. `syslogSelectorAtomSafe` admitted `-` at every offset, so a
// facility of `-host` rendered a drop-in whose first line is
// `-host.info<TAB>/var/log/d`. In legacy sysklogd / rsyslog syntax a token
// beginning `-` at the start of a line is not a facility selector at all — it
// is a HOSTNAME-FILTER directive, and it re-scopes every selector that follows
// it until the next such directive. So the byte does not merely appear in the
// output; it changes what the surrounding configuration MEANS. That is the
// construct substitution this belt exists to prevent, and it is reachable
// through the schema's unvalidated wildcard facility KEY (same chain as
// TestSyslogRenderUnsafeFacilityIsLoadReachable_5797).
//
// The bare `-` is the same defect with nothing after it.
//
// RED-on-revert: delete the leading-byte guard at the top of
// syslogSelectorAtomSafe (`if c := atom[0]; !(c >= 'a' ...)`), or move it to
// only one of the two call sites.
func TestSyslogRenderRejectsLeadingHyphenSelector_6829(t *testing.T) {
	for _, tc := range []struct {
		name               string
		facility, severity string
	}{
		{"hostname-filter facility", "-host", "info"},
		{"bare hyphen facility", "-", "info"},
		{"hostname-filter as a list member", "auth,-host", "info"},
		{"hostname-filter severity", "daemon", "-crit"},
		{"bare hyphen severity", "daemon", "-"},
		{"hyphen behind a severity modifier", "daemon", "=-crit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg([]*config.SyslogFileConfig{
				{Name: "d", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
			}, nil)
			body, ok := renderedFor(cfg, renderPrefix+"d.conf")
			if ok {
				t.Fatalf("facility=%q severity=%q RENDERED a managed drop-in:\n%s\n"+
					"A selector atom beginning with `-` is a sysklogd/rsyslog hostname-filter "+
					"directive, not a facility — it re-scopes every selector after it. The "+
					"belt must refuse it before it reaches the file (#6829 B1).",
					tc.facility, tc.severity, body)
			}
		})
	}
}

// TestSyslogRenderKeepsInteriorHyphens_6829 is the over-reach control for the
// guard above, and it is a SEPARATE test on purpose: sharing a body with the
// binder would put it behind that body's t.Fatalf, where it could never be
// observed running under the mutation it exists to bound.
//
// The leading-byte guard must not become "reject any hyphen". Every row here is
// a real Junos facility spelling or a real rsyslog priority, all of which
// rendered working drop-ins before the guard and must still render. These stay
// GREEN when the guard is deleted — that contrast is what makes them a control
// rather than a restatement of the fix.
func TestSyslogRenderKeepsInteriorHyphens_6829(t *testing.T) {
	for _, tc := range []struct {
		name               string
		facility, severity string
		want               string
	}{
		{"interior hyphen facility", "interactive-commands", "notice",
			"interactive-commands.notice\t/var/log/d\n"},
		{"trailing hyphen facility", "daemon-", "info", "daemon-.info\t/var/log/d\n"},
		{"interior hyphen in a list member", "auth,interactive-commands", "info",
			"auth,interactive-commands.info\t/var/log/d\n"},
		{"change-log remap still fires", "change-log", "warning", "local6.warning\t/var/log/d\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := syslogCfg([]*config.SyslogFileConfig{
				{Name: "d", Selectors: []config.SyslogFacility{{Facility: tc.facility, Severity: tc.severity}}},
			}, nil)
			body, ok := renderedFor(cfg, renderPrefix+"d.conf")
			if !ok {
				t.Fatalf("facility=%q severity=%q did NOT render. The #6829 B1 guard constrains "+
					"the FIRST byte of an atom only; an interior or trailing hyphen is ordinary "+
					"configuration and rejecting it deletes a working destination on upgrade.",
					tc.facility, tc.severity)
			}
			if want := "# Managed by xpf — do not edit\n" + tc.want; body != want {
				t.Errorf("rendered drop-in = %q, want %q", body, want)
			}
		})
	}
}
