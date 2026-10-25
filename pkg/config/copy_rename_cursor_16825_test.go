package config

import (
	"reflect"
	"testing"
)

// #16825 (R3-F09-04): #15757's bare-destination fix made
// configMutationPaths adjudicate a NON-bare copy/rename destination
// WITHOUT the edit cursor (ResolveBareCopyRenameDestination is
// identity for non-bare dst), while the local CLI executor
// (handleCopyRename) and the remote CLI prepend the cursor via
// PrependEditPathForCopyDst. Under [edit system],
// `copy login user operator to login user root` was therefore judged
// at `login user root`, missed an anchored
// `deny-configuration ^system login user root`, and committed
// `system login user root` — fail-open; anchored allows false-denied
// in mirror.
//
// Fix: configMutationPaths resolves the destination exactly as the
// executor does — PrependEditPathForCopyDst(editPath, fullSrc, dst)
// then ResolveBareCopyRenameDestination(fullSrc, that) — via the one
// shared helper ResolveCopyRenameDestination, which the gate and
// both cursor-prepending executors (pkg/cli, cmd/cli) now call.
//
// FAIL-ON-REVERT: reverting configMutationPaths to
// ResolveBareCopyRenameDestination(fullSrc, dst) turns the
// non-bare-under-cursor deny cells RED (they were RED pre-fix).

func TestCopyRenameNonBareDstUnderCursorAuthz16825(t *testing.T) {
	denyRoot := classWithConfigRegex9154(t, "", `^system login user root`)

	// Defect cells: non-bare dst under [edit system]. Executor lands
	// at system login user root; gate must deny. (#16080 also fences
	// system login, but the anchored deny must bite on its own —
	// the allow-mirror and helper units below isolate the regex leg.)
	for _, verb := range []string{"copy", "rename"} {
		if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"system"},
			verb+" login user operator to login user root"); err == nil {
			t.Errorf("%s under [edit system] to non-bare login user root ALLOWED; "+
				"executor creates system login user root, denied by ^system login user root (#16825)", verb)
		}
		if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"system"},
			verb+" login user operator to user root"); err == nil {
			t.Errorf("%s under [edit system] to bare user root ALLOWED (#16825/#15757)", verb)
		}
	}
	// Non-credential deny isolates the anchored-regex leg from the
	// #16080 fence (which denies system login regardless): expanded
	// dst system services telnet must be denied, bare form too.
	denySvc := classWithConfigRegex9154(t, "", `^system services telnet`)
	for _, verb := range []string{"copy", "rename"} {
		if err := AuthorizeConfigMutation(denySvc, "limited", []string{"system"},
			verb+" services ssh to services telnet"); err == nil {
			t.Errorf("%s under [edit system] to non-bare services telnet ALLOWED; "+
				"expanded dst system services telnet is denied (#16825)", verb)
		}
		if err := AuthorizeConfigMutation(denySvc, "limited", []string{"system"},
			verb+" services ssh to telnet"); err == nil {
			t.Errorf("%s under [edit system] to bare telnet ALLOWED (#16825/#15757)", verb)
		}
	}

	// Controls: root-spelled full dst (nil cursor) and bare dst under
	// cursor stay denied; non-denied destinations stay allowed.
	if err := AuthorizeConfigMutation(denyRoot, "limited", nil,
		"copy system login user operator to system login user root"); err == nil {
		t.Error("root-spelled full-dst copy control ALLOWED (#16825)")
	}
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"system"},
		"copy services ssh to services telnet"); err != nil {
		t.Errorf("non-bare copy under [edit system] to non-denied services telnet refused: %v (#16825)", err)
	}
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"security"},
		"copy zones security-zone operator to zones security-zone alice"); err != nil {
		t.Errorf("non-bare copy under [edit security] to non-denied zone refused: %v (#16825)", err)
	}
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"security"},
		"rename zones security-zone operator to zones security-zone alice"); err != nil {
		t.Errorf("non-bare rename under [edit security] to non-denied zone refused: %v (#16825)", err)
	}
	// Non-bare dst that expands OUTSIDE the deny stays allowed even
	// though its typed form shares a suffix with the denied path.
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"security"},
		"copy zones security-zone operator to login user root"); err != nil {
		t.Errorf("copy under [edit security] to security login user root (not denied) refused: %v (#16825)", err)
	}

	// Anchored ALLOW mirror (false-deny direction): allow only
	// ^system login — a non-bare copy under [edit system] whose
	// expanded dst is inside the allow must pass, one outside must not.
	// Use a non-credential subtree to isolate the regex leg from #16080.
	allowSys := classWithConfigRegex9154(t, `^system`, "")
	if err := AuthorizeConfigMutation(allowSys, "limited", []string{"system"},
		"copy services ssh to services telnet"); err != nil {
		t.Errorf("non-bare copy under [edit system] inside allow ^system refused: %v (#16825)", err)
	}
	allowSec := classWithConfigRegex9154(t, `^security`, "")
	if err := AuthorizeConfigMutation(allowSec, "limited", []string{"system"},
		"copy services ssh to services telnet"); err == nil {
		t.Error("non-bare copy under [edit system] ALLOWED under allow ^security; expanded dst is system services telnet (#16825)")
	}
	if err := AuthorizeConfigMutation(allowSec, "limited", []string{"security"},
		"copy zones security-zone a to zones security-zone b"); err != nil {
		t.Errorf("non-bare copy under [edit security] inside allow ^security refused: %v (#16825)", err)
	}
}

func TestResolveCopyRenameDestination16825(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit []string
		src  []string
		dst  []string
		want []string
	}{
		// Defect shape: non-bare dst prepends cursor.
		{"non-bare under cursor", []string{"system"},
			[]string{"login", "user", "operator"}, []string{"login", "user", "root"},
			[]string{"system", "login", "user", "root"}},
		// Bare dst under cursor: source parent, NOT cursor+dst and
		// NOT system user root (#15757 shape must stay).
		{"bare under cursor", []string{"system"},
			[]string{"login", "user", "operator"}, []string{"user", "root"},
			[]string{"system", "login", "user", "root"}},
		// Bare dst, nil cursor.
		{"bare nil cursor", nil,
			[]string{"system", "login", "user", "operator"}, []string{"user", "root"},
			[]string{"system", "login", "user", "root"}},
		// Full dst, nil cursor: identity.
		{"full nil cursor", nil,
			[]string{"system", "login", "user", "operator"}, []string{"system", "login", "user", "root"},
			[]string{"system", "login", "user", "root"}},
		// Non-bare dst already root-spelled under cursor: executor
		// prepends cursor regardless (executor truth; gate matches).
		{"root-spelled under cursor prepends", []string{"system"},
			[]string{"login", "user", "operator"}, []string{"system", "login", "user", "root"},
			[]string{"system", "system", "login", "user", "root"}},
		// Bare policy dst under zone-pair cursor.
		{"bare policy", []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"},
			[]string{"policy", "a"}, []string{"policy", "b"},
			[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "b"}},
		// Non-bare dst to a different subtree under cursor.
		{"non-bare cross-subtree", []string{"security"},
			[]string{"zones", "security-zone", "operator"}, []string{"zones", "security-zone", "alice"},
			[]string{"security", "zones", "security-zone", "alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveCopyRenameDestination(tc.edit, tc.src, tc.dst); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ResolveCopyRenameDestination(%v, %v, %v) = %v, want %v (#16825)", tc.edit, tc.src, tc.dst, got, tc.want)
			}
		})
	}
}
