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
		{"severity newline", "daemon", "info\n*.* /tmp/pwn"},
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
// applySystemSyslog installs real clients, so this uses a documentation-range
// literal (RFC 5737) and UDP, which resolves without a connect or any DNS.
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
