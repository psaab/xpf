package config

import "testing"

// #9391 (from the #9156 leaf-run gate): `system login user <u>` declares `uid`
// with no valueType and no validator, so it is an ADMISSION HEAD —
// validateModifierChild has nothing to reject the token that follows it with,
// and the reader kept only the head.
//
// The loss is ONE-DIRECTIONAL and that is what makes it severe rather than
// merely annoying. The reverse spelling is rejected (`class` IS typed), so a
// class can never be GAINED this way — but whatever `class` is packed behind
// `uid` is DROPPED, and any previously authored class STANDS.

func loginUsers9391(t *testing.T, lines ...string) map[string]*LoginUser {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	if err := SchemaValidateWithDefinitions(tree, tree, nil); err != nil {
		t.Fatalf("STRICT REJECT (the arm cannot be read): %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	out := map[string]*LoginUser{}
	if cfg.System.Login != nil {
		for _, u := range cfg.System.Login.Users {
			out[u.Name] = u
		}
	}
	return out
}

// TestLoginUserDowngradeIsNotSilentlyDropped9391 is the harmful half, and it is
// NOT the fail-closed one.
//
// An operator demoting an admin writes the idiomatic one-line `set`. Before
// this fix the demotion was dropped and the user kept `super-user`:
// reconcileSudoers keys the passwordless-root grant on Class == "super-user",
// so the demoted admin KEPT the xpf-<user> NOPASSWD drop-in — exactly the #3889
// defect that revocation sweep was written to close, reached again by spelling
// — and pkg/authz evaluated the retained super-user class on every gRPC and
// REST call.
func TestLoginUserDowngradeIsNotSilentlyDropped9391(t *testing.T) {
	// ORACLE: the same demotion on separate lines.
	oracle := loginUsers9391(t,
		"set system login user admin class super-user",
		"set system login user admin uid 2001",
		"set system login user admin class read-only",
	)
	if got := oracle["admin"].Class; got != "read-only" {
		t.Fatalf("ORACLE: separate lines give class=%q, want read-only — the control is "+
			"broken, so the arm below cannot be read", got)
	}

	got := loginUsers9391(t,
		"set system login user admin class super-user",
		"set system login user admin uid 2001 class read-only",
	)
	if got["admin"].Class != oracle["admin"].Class {
		t.Errorf("the one-line demotion gives class=%q; the separate-lines oracle gives "+
			"%q. A dropped demotion leaves the operator's own commit saying read-only "+
			"while reconcileSudoers keeps the passwordless-root grant and pkg/authz "+
			"evaluates super-user", got["admin"].Class, oracle["admin"].Class)
	}
	if got["admin"].UID != 2001 {
		t.Errorf("uid = %d, want 2001 — the head must survive its own run", got["admin"].UID)
	}
}

// TestLoginUserFreshClassSurvivesTheRun9391 is the other half: a user with NO
// prior class. That direction failed CLOSED (class="" denies at pkg/authz), so
// it was an availability bug rather than an authorization one — but it is the
// same drop and it is fixed by the same expansion.
func TestLoginUserFreshClassSurvivesTheRun9391(t *testing.T) {
	oracle := loginUsers9391(t,
		"set system login user alice uid 2001",
		"set system login user alice class super-user",
	)
	got := loginUsers9391(t, "set system login user alice uid 2001 class super-user")
	if oracle["alice"].Class != "super-user" {
		t.Fatalf("ORACLE broken: class=%q", oracle["alice"].Class)
	}
	if got["alice"].Class != oracle["alice"].Class || got["alice"].UID != oracle["alice"].UID {
		t.Errorf("one-line gives uid=%d class=%q; oracle gives uid=%d class=%q",
			got["alice"].UID, got["alice"].Class, oracle["alice"].UID, oracle["alice"].Class)
	}
}

// TestLoginUserClassHeadIsStillRejected9391 pins the direction.
//
// `class` is TYPED, so a run headed by it is refused — which is why a class can
// only ever be LOST here, never gained. Expanding the run at the READER must
// not relax what the commit gate accepts, or the fix would open the direction
// the defect could not reach.
func TestLoginUserClassHeadIsStillRejected9391(t *testing.T) {
	tree := &ConfigTree{}
	p, err := ParseSetCommand("set system login user alice class super-user uid 2001")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := tree.SetPath(p); err != nil {
		t.Fatalf("%v", err)
	}
	if err := SchemaValidateWithDefinitions(tree, tree, nil); err == nil {
		t.Fatalf("a TYPED head must still be rejected — expanding the run is a READER " +
			"change and must not widen what the commit gate accepts")
	}
}

// TestLoginUserAuthenticationBodyIsUntouched9391 is the bound on the remedy.
//
// expandFlatRun was chosen over hoistAndSplitRun8939 precisely because the
// stronger helper descends into a container leaf's body, and `authentication`
// is one whose packed spelling the #6662 gate exists to REJECT. This pins that
// an authored `authentication` block still reaches the reader as authored.
func TestLoginUserAuthenticationBodyIsUntouched9391(t *testing.T) {
	got := loginUsers9391(t,
		"set system login user alice uid 2001 class super-user",
		"set system login user alice authentication encrypted-password \"$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/\"",
	)
	u := got["alice"]
	if u.Class != "super-user" || u.UID != 2001 {
		t.Fatalf("the run expansion regressed: uid=%d class=%q", u.UID, u.Class)
	}
	if u.EncryptedPassword == "" {
		t.Errorf("the authentication body must still reach the reader; got an empty " +
			"password, so lifting out of `authentication` would have changed what the " +
			"lenient path compiles relative to what #6662 rejects")
	}
}
