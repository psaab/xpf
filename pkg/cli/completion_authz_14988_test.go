package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14988 (D37-03): the interactive completer and `?` help bypassed
// checkPermission, checkCommandRegex and ConfigurationLoginRegexesFor.
// The gRPC Complete RPC was gated for the same disclosure in
// #14144/#14708/#14952; the on-box completer kept returning live
// ActiveConfig values (zone/policy/address/interface names with
// descriptions and CIDRs, via valueProvider and cmdtree DynamicFns),
// config-schema candidates under denied subtrees, and operational
// candidates for commands the class cannot run.
//
// Tests drive the REAL entry points: cliCompleter.Do (TAB and, via
// completeForHelp, the `?` listener's candidate computation),
// completeConfigWithDesc, and the filtered help helpers. The store is
// real and committed, because the gate reads ActiveConfig.

const completion14988Config = `system {
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class limited-op {
            permissions [ view ];
            deny-commands "^show configuration";
        }
        class view-only {
            permissions [ view ];
        }
        class allow-interfaces {
            permissions [ view configure ];
            allow-configuration "^interfaces";
        }
        class open-view {
            permissions [ view configure ];
        }
        user limited { class limited-view; }
        user op { class limited-op; }
        user allowed { class allow-interfaces; }
        user opener { class open-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
        security-zone untrust {
            description "SECRET-UNTRUST-DESC";
            host-inbound-traffic { system-services [ https ]; }
            interfaces [ ge-0/0/1.0 ];
        }
    }
    address-book {
        global {
            address web-net 203.0.113.0/24;
            address db-net 198.51.100.0/24;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                description "SECRET-POLICY-DESC";
                match { source-address web-net; destination-address db-net; application junos-http; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { description "SECRET-IFACE-DESC"; family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
`

func completion14988Store(t *testing.T) *configstore.Store {
	t.Helper()
	st := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := st.LoadOverride(completion14988Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	st.ExitConfigure()
	if st.ActiveConfig() == nil {
		t.Fatal("no active config; the cells below would be vacuous")
	}
	return st
}

func completion14988CLI(t *testing.T, class string, configMode bool) (*CLI, *cliCompleter) {
	t.Helper()
	st := completion14988Store(t)
	if configMode {
		if err := st.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if !st.InConfigMode() {
			t.Fatal("store not in config mode")
		}
	}
	c := &CLI{store: st, userClass: class}
	return c, &cliCompleter{cli: c}
}

func hasCandNamed(cands []completionCandidate, want string) bool {
	for _, c := range cands {
		if c.name == want {
			return true
		}
	}
	return false
}

func assertNoSecrets14988(t *testing.T, what string, cands []completionCandidate) {
	t.Helper()
	joined := strings.Join(candNames(cands), " ")
	for _, c := range cands {
		joined += " " + c.desc
	}
	for _, secret := range []string{
		"SECRET-TRUST-DESC", "SECRET-UNTRUST-DESC", "SECRET-POLICY-DESC", "SECRET-IFACE-DESC",
		"203.0.113.0/24", "198.51.100.0/24", "web-net", "db-net", "allow-web", "trust", "untrust",
	} {
		if strings.Contains(joined, secret) {
			t.Errorf("%s: leaked %q in candidates=%v", what, secret, cands)
		}
	}
}

// --- `?` / TAB candidate computation (the shared helper both use) ---

func TestCompletionDeniedConfigurationDoesNotDisclose14988(t *testing.T) {
	// Control: open class DOES get live values (test is not vacuous).
	_, open := completion14988CLI(t, "open-view", true)
	openCands := open.cli.completeForHelp([]string{"set", "security", "zones", "security-zone"}, "")
	if !hasCandNamed(openCands, "trust") {
		t.Fatalf("control (open-view) missing trust zone; test would be vacuous: %v", candNames(openCands))
	}

	_, limited := completion14988CLI(t, "limited-view", true)
	for _, words := range [][]string{
		{"set", "security", "zones", "security-zone"},
		{"set", "security", "policies", "from-zone"},
		{"set", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"},
		// Cross-hierarchy: interface names live under interfaces, but a
		// security value slot must not leak security values either way;
		// zone-typed slots draw from security zones.
		{"set", "security", "zones", "security-zone", "trust"},
	} {
		cands := limited.cli.completeForHelp(words, "")
		assertNoSecrets14988(t, "config "+strings.Join(words, " "), cands)
	}

	// Operational `show configuration <denied path>` via TAB/?.
	_, limitedOpMode := completion14988CLI(t, "limited-view", false)
	for _, words := range [][]string{
		{"show", "configuration", "security", "zones", "security-zone"},
		{"show", "configuration", "security"},
	} {
		cands := limitedOpMode.cli.completeForHelp(words, "")
		assertNoSecrets14988(t, "op "+strings.Join(words, " "), cands)
	}

	// deny-commands "^show configuration": operational completion must not leak.
	_, opDenied := completion14988CLI(t, "limited-op", false)
	cands := opDenied.cli.completeForHelp([]string{"show", "configuration", "security", "zones", "security-zone"}, "")
	assertNoSecrets14988(t, "deny-commands show configuration", cands)

	// Non-denied subtree live values still work for limited-view.
	ifResp := limited.cli.completeForHelp([]string{"set", "interfaces"}, "")
	if !hasCandNamed(ifResp, "ge-0/0/0") {
		t.Errorf("limited-view should still complete non-denied interfaces, got %v", candNames(ifResp))
	}
}

// TestCompletionTabDoDenied14988 drives the real cliCompleter.Do entry.
// Do only surfaces suffixes, so use a prefix that makes the denied value
// the unique completion: if gating works, Do returns no completion.
func TestCompletionTabDoDenied14988(t *testing.T) {
	_, ccOpen := completion14988CLI(t, "open-view", true)
	// Open control: TAB on "set security zones security-zone tr" completes.
	suffixes, _ := ccOpen.Do([]rune("set security zones security-zone tr"), len([]rune("set security zones security-zone tr")))
	if len(suffixes) == 0 {
		t.Fatalf("open control: expected a completion suffix, got none (vacuous)")
	}

	_, ccLim := completion14988CLI(t, "limited-view", true)
	suffixes, _ = ccLim.Do([]rune("set security zones security-zone tr"), len([]rune("set security zones security-zone tr")))
	if len(suffixes) != 0 {
		t.Errorf("limited-view TAB leaked a denied completion suffix: %q", suffixes)
	}

	// Operational TAB: show configuration under denied subtree.
	_, ccLimOp := completion14988CLI(t, "limited-view", false)
	suffixes, _ = ccLimOp.Do([]rune("show configuration security zones security-zone tr"), len([]rune("show configuration security zones security-zone tr")))
	if len(suffixes) != 0 {
		t.Errorf("limited-view operational TAB leaked a denied completion suffix: %q", suffixes)
	}
}

// allow-configuration is an allowlist: only the allowed subtree offers
// live values / candidates; everything else is withheld.
func TestCompletionAllowConfigurationAllowlist14988(t *testing.T) {
	_, cc := completion14988CLI(t, "allow-interfaces", true)
	if cands := cc.cli.completeForHelp([]string{"set", "interfaces"}, ""); !hasCandNamed(cands, "ge-0/0/0") {
		t.Errorf("allow-interfaces should complete allowed interfaces, got %v", candNames(cands))
	}
	sec := cc.cli.completeForHelp([]string{"set", "security", "zones", "security-zone"}, "")
	assertNoSecrets14988(t, "allowlist security", sec)
	if len(sec) != 0 {
		t.Errorf("allowlist class got candidates under non-allowed security: %v", candNames(sec))
	}
}

// Coarse permission gate: a view-only class gets no config-mode verb
// candidates and no operational candidates for commands it cannot run.
func TestCompletionCoarsePermissionGate14988(t *testing.T) {
	// Config-mode top level for a view-only class: no candidates
	// (it cannot enter configure at all).
	_, cc := completion14988CLI(t, "view-only", true)
	if cands := cc.cli.completeForHelp(nil, ""); len(cands) != 0 {
		t.Errorf("view-only class got config-mode candidates %v, want none", candNames(cands))
	}
	// Operational: `clear` requires PermClear, read-only/view classes
	// must not be offered its subtree; `show` stays.
	_, ccOp := completion14988CLI(t, "view-only", false)
	top := ccOp.cli.completeForHelp(nil, "")
	if hasCandNamed(top, "clear") || hasCandNamed(top, "configure") || hasCandNamed(top, "request") {
		t.Errorf("view-only class offered non-view operational commands: %v", candNames(top))
	}
	if !hasCandNamed(top, "show") {
		t.Errorf("view-only class lost `show` completion: %v", candNames(top))
	}
	// Word-level: completing "clear ..." offers nothing.
	if cands := ccOp.cli.completeForHelp([]string{"clear"}, ""); len(cands) != 0 {
		t.Errorf("view-only class got clear subtree candidates: %v", candNames(cands))
	}

	// Unknown class fails closed (checkPermission denies every command).
	_, ccUnknown := completion14988CLI(t, "nosuchclass14988", false)
	if cands := ccUnknown.cli.completeForHelp(nil, ""); len(cands) != 0 {
		t.Errorf("unknown class got candidates %v, want none (fail closed)", candNames(cands))
	}

	// Unset class (legacy no-RBAC) is unchanged.
	_, ccUnset := completion14988CLI(t, "", false)
	if cands := ccUnset.cli.completeForHelp(nil, ""); !hasCandNamed(cands, "clear") {
		t.Errorf("unset class lost legacy completion: %v", candNames(cands))
	}
}

// Super-user (PermAll, no regexes) keeps full completion — the
// neighbouring legitimate behaviour.
func TestCompletionSuperUserUnchanged14988(t *testing.T) {
	_, cc := completion14988CLI(t, "super-user", true)
	if cands := cc.cli.completeForHelp([]string{"set", "security", "zones", "security-zone"}, ""); !hasCandNamed(cands, "trust") {
		t.Errorf("super-user lost trust completion: %v", candNames(cands))
	}
	_, ccOp := completion14988CLI(t, "super-user", false)
	if cands := ccOp.cli.completeForHelp(nil, ""); !hasCandNamed(cands, "clear") {
		t.Errorf("super-user lost operational completion: %v", candNames(cands))
	}
}

// Help (`?` / `help` command) candidate lists are filtered the same way.
func TestHelpCandidatesFiltered14988(t *testing.T) {
	c, _ := completion14988CLI(t, "view-only", false)
	help := c.filteredOperationalHelp()
	joined := strings.Join(candNames(help), " ")
	if strings.Contains(joined, "clear") || strings.Contains(joined, "configure") {
		t.Errorf("view-only help listed non-view commands: %v", candNames(help))
	}
	if !hasCandNamed(help, "show") {
		t.Errorf("view-only help lost show: %v", candNames(help))
	}
	if cfgHelp := c.filteredConfigHelp(); len(cfgHelp) != 0 {
		t.Errorf("view-only class got config help candidates: %v", candNames(cfgHelp))
	}
	su, _ := completion14988CLI(t, "super-user", false)
	if got := su.filteredConfigHelp(); !hasCandNamed(got, "set") {
		t.Errorf("super-user config help lost set: %v", candNames(got))
	}
}
