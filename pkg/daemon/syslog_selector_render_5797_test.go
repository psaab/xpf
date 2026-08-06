package daemon

// #5797 render-site binding.
//
// syslog_selector_token_5797_test.go proves the PREDICATE
// (syslogSelectorTokenSafe) classifies tokens correctly. That is scaffolding:
// it stays green if both belt call sites are deleted, because nothing in it
// reaches production. This file binds the CONSUMER — it drives
// syslogDropinContents, the function that actually renders the rsyslog
// drop-ins, and asserts on the rendered bytes. Removing either
// `if !syslogSelectorTokenSafe(...)` guard turns these RED.
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
// Reverting `if !syslogSelectorTokenSafe(f.Facility) || ...` in
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
				{Name: "evil", Facility: tc.facility, Severity: tc.severity},
				{Name: "audit", Facility: "daemon", Severity: "info"},
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
				{User: "root", Facility: tc.facility, Severity: tc.severity},
				{User: "operator", Facility: "daemon", Severity: "info"},
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
				{Name: "d", Facility: tc.facility, Severity: tc.severity},
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
		{Name: "audit", Facility: "daemon;*.* @@collector.example:514", Severity: "info"},
		{Name: "ops", Facility: "daemon", Severity: "info"},
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
			{Name: "audit", Facility: "daemon;*.*", Severity: "info"},
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
			{User: "root", Facility: "daemon", Severity: "info;*.*"},
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
			[]*config.SyslogFileConfig{{Name: "audit", Facility: "authorization", Severity: "info"}},
			[]*config.SyslogUserConfig{{User: "*", Facility: "any", Severity: "emergency"}},
		), renderPrefix)

		if got := buf.String(); strings.Contains(got, "unsafe selector token") {
			t.Errorf("a config with only legitimate tokens must not warn. captured:\n%s", got)
		}
	})
}

// TestSyslogRenderUnsafeFacilityIsCommitReachable_5797 is the reachability
// chain, and the reason the file/user belts are load-bearing rather than
// defence-in-depth. It drives the REAL operator path — parse the set command,
// SchemaValidate it, CompileConfig it — and shows an injecting facility
// arriving at the render function from an ordinary commit, then being dropped.
//
// Deliberate coupling: the SchemaValidate assertion is `must pass`. If a future
// change adds a key validator to the `<facility> <severity>` wildcard, this
// test fails — that is the intent. It forces whoever adds that gate to
// re-derive whether the render belt is still needed instead of deleting it on
// the assumption that the schema already covers this.
func TestSyslogRenderUnsafeFacilityIsCommitReachable_5797(t *testing.T) {
	const injecting = "daemon;*.* /tmp/pwn"

	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand(`set system syslog file audit "` + injecting + `" info`)
	if err != nil {
		t.Fatalf("parse set command: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("the `<facility> <severity>` wildcard now rejects %q at commit-check: %v\n"+
			"That is a NEW gate. Re-derive whether the syslogDropinContents belt is still the "+
			"only line of defence before relying on it or removing it (#5797).", injecting, err)
	}

	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.System.Syslog.Files) != 1 || cfg.System.Syslog.Files[0].Facility != injecting {
		t.Fatalf("compiled facility = %+v, want the verbatim %q — the reachability premise of "+
			"this test no longer holds", cfg.System.Syslog.Files, injecting)
	}

	if body, ok := renderedFor(cfg, renderPrefix+"audit.conf"); ok {
		t.Errorf("a commit-clean config wrote an rsyslog drop-in built from %q (#5797):\n%s",
			injecting, body)
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

	// A Junos facility name the runtime cannot map: the substitution to local0
	// must be reported.
	for _, facility := range []string{"authorization", "kernel", "interactive-commands", "typo"} {
		t.Run("unmapped/"+facility, func(t *testing.T) {
			got := apply(t, facility)
			if !strings.Contains(got, "unmapped facility name") {
				t.Errorf("host facility %q silently became local0 with no warning; records leave "+
					"under a facility the configuration never names (#5797). captured:\n%s",
					facility, got)
			}
			if !strings.Contains(got, facility) {
				t.Errorf("the warning must name the unmapped facility %q. captured:\n%s", facility, got)
			}
		})
	}

	// Negative control: a mapped name must not warn.
	for _, facility := range []string{"daemon", "local0", "change-log", "auth"} {
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
			Facilities:    []config.SyslogFacility{{Facility: "authorization", Severity: "info"}},
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
	if !strings.Contains(got, "unmapped facility name") {
		t.Errorf("the unmapped-facility warning was lost because the client could not be "+
			"constructed — classification must not sit behind the dial (#6829). The "+
			"operator with an unreachable collector is the one who most needs to be "+
			"told their facility name is wrong. captured:\n%s", got)
	}
	if !strings.Contains(got, "authorization") {
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
		cs := d.slogHandler.Clients()
		if len(cs) != 1 {
			t.Fatalf("want exactly one installed client, got %d", len(cs))
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
		if got := apply(t, "authorization").Facility; got != logging.FacilityLocal0 {
			t.Errorf("installed client Facility = %d, want FacilityLocal0 (%d) — the warning "+
				"promises records leave under local0, so that must be what is installed",
				got, logging.FacilityLocal0)
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
				Name: "audit", Host: "192.0.2.10", Port: 514,
				Facility: facility, Severity: "info",
			},
		}
		er := logging.NewEventReader(nil, nil)
		d.applySyslogConfig(er, cfg)
		return buf.String(), er
	}

	t.Run("unmapped facility warns", func(t *testing.T) {
		got, er := apply(t, "authorization")
		// #6829 F2: bind the VALUE on the audit stream — the site this file
		// calls the worst in the daemon to misroute silently. It has the same
		// compute/assign split as the host path, so a log-only assertion cannot
		// see either half being dropped.
		if cs := er.SyslogClients(); len(cs) == 1 && cs[0].Facility != logging.FacilityLocal0 {
			t.Errorf("installed audit-stream Facility = %d, want FacilityLocal0 (%d) — the "+
				"warning promises records leave under local0", cs[0].Facility, logging.FacilityLocal0)
		}
		if !strings.Contains(got, "unmapped facility name") {
			t.Errorf("the security/audit stream silently mapped an unmappable facility to "+
				"local0 with no warning — this is the audit path (#5797/#6829). captured:\n%s", got)
		}
		if !strings.Contains(got, "authorization") {
			t.Errorf("the warning must name the unmapped facility. captured:\n%s", got)
		}
	})

	t.Run("mapped facility stays quiet", func(t *testing.T) {
		got, er := apply(t, "auth")
		if strings.Contains(got, "unmapped facility name") {
			t.Errorf("`auth` is mapped; a correct config must not warn. captured:\n%s", got)
		}
		cs := er.SyslogClients()
		if len(cs) != 1 {
			t.Fatalf("want one installed audit-stream client, got %d", len(cs))
		}
		if cs[0].Facility != logging.FacilityAuth {
			t.Errorf("installed audit-stream Facility = %d, want FacilityAuth (%d) — the "+
				"authored facility must survive the compute/assign split", cs[0].Facility, logging.FacilityAuth)
		}
	})

	t.Run("wildcard any stays quiet", func(t *testing.T) {
		if got, _ := apply(t, "any"); strings.Contains(got, "unmapped facility name") {
			t.Errorf("`any` names no facility on purpose; warning about it is false. captured:\n%s", got)
		}
	})
}
