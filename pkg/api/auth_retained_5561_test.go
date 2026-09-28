package api

import (
	"testing"
	"time"
)

// auth_retained_5561_test.go pins AuthForRetainedListener's semantics (#5561
// round 12). The daemon-side tests prove the reconciler CALLS it at the right
// moments; these prove the function itself computes the set that makes those
// call sites correct — in particular the nil-is-universal rule, without which
// the round-9 hoist (publish the credential before a new off-box socket serves)
// would silently publish an empty deny-all set instead.

func TestAuthForRetainedListenerNilLiveIsUniversal_5561(t *testing.T) {
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}, APIKeys: map[string]bool{"k": true}}
	got := AuthForRetainedListener(nil, next)
	if got == nil {
		t.Fatal("a nil live snapshot yielded nil — that would leave a listener with NO auth")
	}
	if got.Users["admin"] != "pw" || !got.APIKeys["k"] {
		t.Fatalf("got %+v, want the full set. A nil live snapshot is dynamicAuthMiddleware's "+
			"pass-through: that listener already accepts everyone, so `next` is unambiguously "+
			"a tightening and must be published whole (the #5561 round-9 case)", got)
	}
}

func TestAuthForRetainedListenerDropsRevoked_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "pw", "gone": "x"}, APIKeys: map[string]bool{"k": true, "old": true}}
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}, APIKeys: map[string]bool{"k": true}}
	got := AuthForRetainedListener(live, next)
	if _, ok := got.Users["gone"]; ok {
		t.Fatalf("got %+v: a credential the committed config no longer carries survived — a "+
			"revocation must land on the retained listener immediately (#5561 round 7)", got)
	}
	if got.APIKeys["old"] {
		t.Fatalf("got %+v: a revoked api-key survived", got)
	}
	if got.Users["admin"] != "pw" || !got.APIKeys["k"] {
		t.Fatalf("got %+v: a credential that was already accepted here AND is still committed "+
			"was dropped — that is over-restriction with no property behind it", got)
	}
}

func TestAuthForRetainedListenerWithholdsGrants_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "pw"}}
	next := &AuthConfig{
		Users:   map[string]string{"admin": "pw", "autobot": "new"},
		APIKeys: map[string]bool{"fresh": true},
	}
	got := AuthForRetainedListener(live, next)
	if _, ok := got.Users["autobot"]; ok {
		t.Fatalf("got %+v: a principal this listener never accepted was granted. The credential "+
			"set was committed together with the endpoint it is meant for; a listener retained "+
			"by a failed rebind is not that endpoint", got)
	}
	if got.APIKeys["fresh"] {
		t.Fatalf("got %+v: an api-key this listener never accepted was granted", got)
	}
}

// A same-username secret ROTATION is a revocation plus a grant, and the match is
// on the PAIR: the old secret goes, the new one does not arrive. Asserting the
// pair rule explicitly is what keeps a future "match on username" relaxation
// from silently publishing a new secret on an address the operator was moving
// away from.
func TestAuthForRetainedListenerRotationIsNotAGrant_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "old"}}
	next := &AuthConfig{Users: map[string]string{"admin": "new"}}
	got := AuthForRetainedListener(live, next)
	if got == nil {
		t.Fatal("got nil — a nil snapshot disables authentication entirely, the opposite of the " +
			"fail-closed outcome a disjoint rotation calls for")
	}
	if pw, ok := got.Users["admin"]; ok {
		t.Fatalf("got admin=%q: the rotation was published to the retained listener. Revoking "+
			"the old secret tightens; granting the new one does not, and the new one was "+
			"committed for the endpoint that failed to bind", pw)
	}
	if CredentialCount(got) != 0 {
		t.Fatalf("got %+v, want an EMPTY (non-nil) set — every non-exempt request is then "+
			"rejected, which is the intended fail-closed state", got)
	}
}

// The result must not alias either operand: the live snapshot is read from a
// running server and `next` is the caller's config, so sharing a map would let a
// later edit rewrite what a listener enforces.
func TestAuthForRetainedListenerDoesNotAlias_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "pw"}}
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}}
	got := AuthForRetainedListener(live, next)
	next.Users["sneak"] = "in"
	live.Users["also"] = "in"
	if _, ok := got.Users["sneak"]; ok {
		t.Fatalf("got %+v: the result aliases next.Users, so editing the config after the "+
			"publish changes what the listener accepts", got)
	}
	if _, ok := got.Users["also"]; ok {
		t.Fatalf("got %+v: the result aliases live.Users", got)
	}
}

// The no-alias property must hold on the UNIVERSAL-live path too. That branch
// used to return `next` itself, so the claim above ("neither operand is ever
// shared") was true only of the branch its own test happened to take — and this
// is the branch the round-9 hoist relies on, where the snapshot published before
// an off-box socket is created comes straight from the config the reconciler is
// still holding (#5561 round 14).
func TestAuthForRetainedListenerUniversalLiveDoesNotAlias_5561(t *testing.T) {
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}, APIKeys: map[string]bool{"k": true}}
	got := AuthForRetainedListener(nil, next)
	if got == nil {
		t.Fatal("got nil: a nil live snapshot is the UNIVERSAL set, so next is a tightening and " +
			"must be published whole")
	}
	if got == next {
		t.Fatal("the result IS next: a later edit of the config rewrites what the listener enforces")
	}
	next.Users["sneak"] = "in"
	next.APIKeys["sneaky-key"] = true
	if _, ok := got.Users["sneak"]; ok {
		t.Fatalf("got %+v: the result aliases next.Users", got)
	}
	if got.APIKeys["sneaky-key"] {
		t.Fatalf("got %+v: the result aliases next.APIKeys", got)
	}
	// Still the whole committed set — the copy must not lose anything.
	if got.Users["admin"] != "pw" || !got.APIKeys["k"] {
		t.Fatalf("got %+v, want a faithful copy of the committed set", got)
	}
}

// A nil `next` is the remove-all-api-auth direction, which reconcileTo handles
// separately behind its loopback gate; the helper must not manufacture a
// credential set for it.
func TestAuthForRetainedListenerNilNext_5561(t *testing.T) {
	if got := AuthForRetainedListener(&AuthConfig{Users: map[string]string{"a": "b"}}, nil); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

// TestCredentialCountIgnoresDisabledAPIKeys_5561 pins the two operands of the
// reconciler's `withheld` figure against each other (#5561 round 19, finding 3).
//
// pkg/daemon's management reconciler logs
// CredentialCount(next.Auth) - CredentialCount(AuthForRetainedListener(...)).
// That subtraction is only meaningful if both sides count the same things, and
// AuthForRetainedListener copies an api-key only when it is mapped to TRUE —
// which is also the only case constantTimeAPIKeyMatch will ever match. A count
// that included the false entries therefore reported a credential as withheld
// that no listener could have honoured in either snapshot.
//
// Log-only, so the assertion is the identity itself rather than any behaviour:
// a disabled key must contribute nothing to either operand.
func TestCredentialCountIgnoresDisabledAPIKeys_5561(t *testing.T) {
	if n := CredentialCount(&AuthConfig{APIKeys: map[string]bool{"revoked": false}}); n != 0 {
		t.Fatalf("a snapshot whose only api-key is mapped to false counts %d credentials, want 0. "+
			"constantTimeAPIKeyMatch skips !valid, so that key authenticates nobody", n)
	}

	// A SEPARATE arm, deliberately not folded into the case above: constantTimeAPIKeyMatch
	// skips `!valid || key == ""`, so it has two independent reasons to reject a key and
	// CredentialCount must mirror both. One fixture carrying a disabled key AND an empty
	// key would stay red if either arm regressed, so it could not tell them apart —
	// each needs its own distinguishing mutation. (#5561 round 19 fixed the valid flag
	// and left this one; the empty-key shape is real, see auth_empty_secret_5636_test.go.)
	if n := CredentialCount(&AuthConfig{APIKeys: map[string]bool{"": true}}); n != 0 {
		t.Fatalf("a snapshot whose only api-key is the EMPTY STRING counts %d credentials, want 0. "+
			"constantTimeAPIKeyMatch skips key == \"\" as well as !valid, so an empty key "+
			"authenticates nobody however it is flagged — counting it makes the reconciler "+
			"report a credential that cannot be used", n)
	}

	// The consumer shape: the retained-listener set and the committed set differ
	// by nothing a listener could use, so nothing was withheld.
	live := &AuthConfig{Users: map[string]string{"admin": "pw"}, APIKeys: map[string]bool{"k": true}}
	next := &AuthConfig{
		Users:   map[string]string{"admin": "pw"},
		APIKeys: map[string]bool{"k": true, "revoked": false},
	}
	publish := AuthForRetainedListener(live, next)
	if withheld := CredentialCount(next) - CredentialCount(publish); withheld != 0 {
		t.Fatalf("the reconciler would warn that it withheld %d credentials from the retained "+
			"listener, but the only difference between the committed set and the published one "+
			"is an api-key mapped to false — a credential neither snapshot would ever accept. "+
			"An over-reported withholding is a warning an operator has to go and disprove "+
			"(committed %+v, published %+v)", withheld, next, publish)
	}
}

// A reused credential whose class changes is a grant to the retained endpoint,
// even though its secret is unchanged. Withhold it until the endpoint converges.
func TestAuthForRetainedListenerWithholdsPrivilegeUpgrade10826(t *testing.T) {
	live := &AuthConfig{
		Users:         map[string]string{"admin": "same-password"},
		UserClasses:   map[string]string{"admin": "read-only"},
		APIKeys:       map[string]bool{"same-api-key": true},
		APIKeyClasses: map[string]string{"same-api-key": "read-only"},
	}
	next := &AuthConfig{
		Users:         map[string]string{"admin": "same-password"},
		UserClasses:   map[string]string{"admin": "super-user"},
		APIKeys:       map[string]bool{"same-api-key": true},
		APIKeyClasses: map[string]string{"same-api-key": "super-user"},
	}
	got := AuthForRetainedListener(live, next)
	if CredentialCount(got) != 0 || len(got.Users) != 0 || len(got.APIKeys) != 0 {
		t.Fatalf("retained listener received the privilege-upgraded credential set: %+v; "+
			"unchanged secrets do not make a class change safe on an address this commit is leaving",
			got)
	}
}

func TestAuthForRetainedListenerWithholdsExpiryExtension10826(t *testing.T) {
	now := time.Now()
	const key = "same-api-key"
	live := &AuthConfig{
		APIKeys:       map[string]bool{key: true},
		APIKeyClasses: map[string]string{key: "read-only"},
		APIKeyExpires: map[string]time.Time{key: now.Add(time.Hour)},
	}
	next := &AuthConfig{
		APIKeys:       map[string]bool{key: true},
		APIKeyClasses: map[string]string{key: "read-only"},
		APIKeyExpires: map[string]time.Time{key: now.Add(2 * time.Hour)},
	}
	if got := AuthForRetainedListener(live, next); got.APIKeys[key] {
		t.Fatalf("retained listener received an extended credential lifetime: %+v", got)
	}
}
