package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #16073 (R15942-05): the gRPC Complete admission gate judged the raw
// typed line, so unique abbreviations stepped around anchored
// deny/allow patterns written against the canonical command. The
// data-source twin (operationalAllowed, #15942) already canonicalises
// with canonicalOperationalWords; admission did not, so the two gates
// on one command judged different strings.
//
// Config shapes below reuse the #14952 classes' spellings:
//   - limited-op:  deny-commands "^show configuration" (anchored ancestor)
//   - anchored-pol: deny-commands "^show security policies$" (exact
//     canonical leaf — the ledger's decisive case: `sh sec pol`)
//   - view-allowlist: allow-commands "^show version" (allowlist case
//     must stay admitted after canonicalisation, including abbreviated)

const complete16073Config = `
system {
    login {
        class limited-op {
            permissions [ view configure ];
            deny-commands "^show configuration";
        }
        class anchored-pol {
            permissions [ view ];
            deny-commands "^show security policies$";
        }
        class anchored-ver {
            permissions [ view ];
            deny-commands "^show version$";
        }
        class view-allowlist {
            permissions [ view ];
            allow-commands "^show version";
        }
        class open-view {
            permissions [ view ];
        }
        user limitedop { class limited-op; }
        user poluser { class anchored-pol; }
        user veruser { class anchored-ver; }
        user allowlistuser { class view-allowlist; }
        user openuser { class open-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC-16073";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { description "SECRET-IFACE-DESC-16073"; family inet { address 10.0.0.1/24; } } }
}
`

const complete16073Passwd = `root:x:0:0:root:/root:/bin/bash
limitedop:x:4271:4271::/home/limitedop:/bin/bash
poluser:x:4272:4272::/home/poluser:/bin/bash
veruser:x:4273:4273::/home/veruser:/bin/bash
allowlistuser:x:4274:4274::/home/allowlistuser:/bin/bash
openuser:x:4275:4275::/home/openuser:/bin/bash
`

const (
	uidLimitedOp16073   = 4271
	uidAnchoredPol16073 = 4272
	uidAnchoredVer16073 = 4273
	uidAllowlist16073   = 4274
	uidOpenView16073    = 4275
)

func complete16073Server(t *testing.T) *Server {
	t.Helper()
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwdPath, []byte(complete16073Passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(passwdPath))

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(complete16073Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func wantDenied16073(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s was ALLOWED, want PermissionDenied (#16073)", what)
		return
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("%s denial code = %s, want PermissionDenied (err=%v)", what, status.Code(err), err)
	}
}

func wantAdmitted16073(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s was DENIED, want admitted (#16073): %v", what, err)
	}
}

// TestCompleteCanonicalAdmission16073 is the decisive regression check
// from #16073: an abbreviated denied command at Complete must be denied
// at admission exactly as its canonical spelling is, and an allowlisted
// abbreviation must still complete.
//
// RED-on-revert: without canonicalisation in completeLineForms, every
// abbreviated denied cell below is admitted (raw `sh conf` /
// `sh sec pol` / `sh ver` matches no anchored canonical pattern), and
// the abbreviated allowlist cell is denied (raw `sh ver` matches no
// `^show version` allow).
func TestCompleteCanonicalAdmission16073(t *testing.T) {
	s := complete16073Server(t)
	full := complete14952Method()
	admit := func(uid int, line string, cfgMode bool) error {
		return s.authorizeRPC(ctxWithPeerUID(uint32(uid)), full,
			&pb.CompleteRequest{Line: line, Pos: int32(len(line)), ConfigMode: cfgMode})
	}

	// Anchored ancestor deny ^show configuration: abbreviated spellings
	// of `show configuration …` must deny at admission, operational and
	// (via `run`) config-mode alike. Pre-fix `sh conf` was admitted.
	for _, line := range []string{
		"show configuration security zones security-zone ",
		"sh conf ",
		"sh conf sec ",
		"sh configuration ",
		"show conf ",
		"show conf security ",
	} {
		wantDenied16073(t, "limited-op Complete{"+line+"}",
			admit(uidLimitedOp16073, line, false))
	}
	runLine := "run sh conf sec "
	wantDenied16073(t, "limited-op Complete{ConfigMode:true, "+runLine+"}",
		admit(uidLimitedOp16073, runLine, true))
	// Controls: the same class keeps non-denied completion, canonical
	// and abbreviated.
	wantAdmitted16073(t, "limited-op Complete{show interfaces }",
		admit(uidLimitedOp16073, "show interfaces ", false))
	wantAdmitted16073(t, "limited-op Complete{sh int }",
		admit(uidLimitedOp16073, "sh int ", false))

	// Anchored leaf deny ^show security policies$: the ledger's exact
	// decisive case. `sh sec pol` must deny; its sub-paths must deny via
	// the canonical prefix walk; a sibling command stays admitted.
	for _, line := range []string{
		"show security policies ",
		"sh sec pol ",
		"sh sec pol",
		"show sec pol from-zone trust ",
		"sh sec pol from-zone trust ",
	} {
		wantDenied16073(t, "anchored-pol Complete{"+line+"}",
			admit(uidAnchoredPol16073, line, false))
	}
	wantAdmitted16073(t, "anchored-pol Complete{show security zones }",
		admit(uidAnchoredPol16073, "show security zones ", false))
	wantAdmitted16073(t, "anchored-pol Complete{sh sec zones }",
		admit(uidAnchoredPol16073, "sh sec zones ", false))

	// Anchored leaf deny ^show version$ with the no-trailing-space
	// (word-still-being-completed) spelling.
	wantDenied16073(t, "anchored-ver Complete{sh ver}",
		admit(uidAnchoredVer16073, "sh ver", false))
	wantDenied16073(t, "anchored-ver Complete{show version }",
		admit(uidAnchoredVer16073, "show version ", false))
	wantAdmitted16073(t, "anchored-ver Complete{show interfaces }",
		admit(uidAnchoredVer16073, "show interfaces ", false))

	// Allowlist ^show version: the allowlisted abbreviation must stay
	// admitted after canonicalisation (canonicalised to `show version`,
	// which the allow matches), while a non-listed abbreviated command
	// denies.
	wantAdmitted16073(t, "allowlist Complete{show version }",
		admit(uidAllowlist16073, "show version ", false))
	wantAdmitted16073(t, "allowlist Complete{sh ver}",
		admit(uidAllowlist16073, "sh ver", false))
	wantAdmitted16073(t, "allowlist Complete{sh ver }",
		admit(uidAllowlist16073, "sh ver ", false))
	wantDenied16073(t, "allowlist Complete{sh conf }",
		admit(uidAllowlist16073, "sh conf ", false))
	wantDenied16073(t, "allowlist Complete{show interfaces }",
		admit(uidAllowlist16073, "show interfaces ", false))

	// Control: an unrestricted class keeps abbreviated completion.
	wantAdmitted16073(t, "open-view Complete{sh sec pol }",
		admit(uidOpenView16073, "sh sec pol ", false))
	wantAdmitted16073(t, "open-view Complete{sh conf }",
		admit(uidOpenView16073, "sh conf ", false))
}

// TestCompleteLineFormsCanonical16073 pins the canonical forms
// themselves, including that config-mode `set …` lines keep their raw
// form (they are not operational commands and must not be judged
// against the operational tree).
func TestCompleteLineFormsCanonical16073(t *testing.T) {
	cases := []struct {
		line     string
		cfgMode  bool
		wantFull string
		wantCfg  bool
	}{
		{"sh conf ", false, "show configuration", true},
		{"sh conf sec ", false, "show configuration security", true},
		{"sh sec pol ", false, "show security policies", false},
		{"sh ver", false, "show version", false},
		{"show version ", false, "show version", false},
		{"sh sec zones security-zone trust ", false, "show security zones security-zone trust", false},
		{"set security zones security-zone ", true, "set security zones security-zone", false},
		{"run sh conf ", true, "show configuration", true},
		{"show configuration security ", false, "show configuration security", true},
	}
	for _, tc := range cases {
		full, _, isCfg := completeLineForms(&pb.CompleteRequest{
			Line: tc.line, Pos: int32(len(tc.line)), ConfigMode: tc.cfgMode})
		if full != tc.wantFull || isCfg != tc.wantCfg {
			t.Errorf("completeLineForms(%q cfg=%v) = (%q, isShowConfig=%v), want (%q, %v)",
				tc.line, tc.cfgMode, full, isCfg, tc.wantFull, tc.wantCfg)
		}
		if strings.Contains(full, "  ") {
			t.Errorf("completeLineForms(%q) full %q contains double space", tc.line, full)
		}
	}
}
