package daemon

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// syslog_gate_render_agreement_6844_test.go -- #6844.
//
// The commit-time facility gate and the render belt must accept the SAME set.
//
// A gate looser than the belt produces the failure class #6844 exists to close:
// the config commits, the operator is told nothing, and the destination
// silently disappears at render — reconcileSyslogDropins does not merely skip
// the drop-in, it REMOVES the one a previous apply wrote. A gate tighter than
// the belt is the opposite regression: a strict-commit-clean, rsyslog-valid
// destination stops committing on upgrade.
//
// The first cut of the gate managed both at once. It rejected `auth,authpriv`
// and bare `*` — documented, supported, render-asserted forms — while admitting
// `.` and `_`, which the belt drops.
//
// They now share one predicate (config.SyslogSelectorFacilitySafe), so this
// holds by construction. That is exactly why the test is worth having: a future
// edit that gives either side its own alphabet again reds here, naming the
// token and the direction.

// facilityAgreementCorpus is a derived corpus rather than a hand list, so it
// covers bytes nobody thought to enumerate.
func facilityAgreementCorpus() []string {
	seen := map[string]bool{}
	var out []string
	add := func(names ...string) {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}

	// Every real name, and the rsyslog-native forms.
	base := []string{
		"any", "authorization", "change-log", "conflict-log", "daemon", "dfc",
		"firewall", "ftp", "interactive-commands", "kernel", "ntp", "pfe",
		"security", "user", "kern", "auth", "syslog", "external", "dcd",
		"local0", "local7", "*", "auth,authpriv", "auth,authpriv,daemon",
	}
	add(base...)

	// One byte of punctuation at a time, in every position — head, interior,
	// tail — because position matters here: a leading '-' is a hostname-filter
	// directive while an interior one is legal.
	for _, name := range []string{"daemon", "auth"} {
		for _, b := range []string{";", ".", ":", "_", "/", " ", "*", ",", "-", "!", "=", "@", "\t", "\x00"} {
			add(b+name, name+b, name[:2]+b+name[2:], b)
		}
	}
	// Length neighbourhood of the bound.
	for _, n := range []int{1, 20, 63, 64, 65, 128} {
		add(strings.Repeat("a", n))
	}
	// A generated tail, so the corpus is not only what I thought of.
	rng := rand.New(rand.NewSource(6844))
	const alphabet = "abcdefghijklmnopqrstuvwxyz-0123456789.,;:_*/ !="
	for i := 0; i < 400; i++ {
		var sb strings.Builder
		for j := 0; j < 1+rng.Intn(10); j++ {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		add(sb.String())
	}
	return out
}

// TestCommitGateAndRenderBeltAcceptTheSameFacilities_6844 is the agreement.
func TestCommitGateAndRenderBeltAcceptTheSameFacilities_6844(t *testing.T) {
	corpus := facilityAgreementCorpus()
	if len(corpus) < 300 {
		t.Fatalf("corpus collapsed to %d entries; the derivation is broken and this test "+
			"is no longer checking what it claims", len(corpus))
	}

	// Anti-vacuity in BOTH directions: a corpus that were entirely accepted, or
	// entirely rejected, would satisfy an agreement assertion while exercising
	// only one branch of each predicate.
	accepted, rejected := 0, 0
	for _, tok := range corpus {
		gateOK := config.ValidateSyslogFacility(tok) == nil
		beltOK := syslogSelectorFacilitySafe(tok)

		// The gate additionally rejects the empty token (a schema KEY always
		// has one) and bounds length; the belt has no opinion on either. Those
		// are the only two licensed disagreements, and they are named here so a
		// THIRD one cannot hide among them.
		switch {
		case tok == "":
			continue
		case len(tok) > 64:
			if gateOK {
				t.Errorf("gate accepted a %d-character facility; the length bound is gone", len(tok))
			}
			continue
		}

		if gateOK != beltOK {
			dir := "gate accepts, belt DROPS (commit succeeds, destination disappears)"
			if beltOK {
				dir = "belt writes, gate REJECTS (a valid config stops committing on upgrade)"
			}
			t.Errorf("facility %q: %s", tok, dir)
		}
		if gateOK {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted < 20 {
		t.Errorf("only %d corpus entries were ACCEPTED; the agreement holds vacuously "+
			"if nothing passes either predicate", accepted)
	}
	if rejected < 20 {
		t.Errorf("only %d corpus entries were REJECTED; the agreement holds vacuously "+
			"if nothing fails either predicate", rejected)
	}
}

// TestRenderAssertedFormsCommit_6844 is the specific regression Codex found: the
// two rsyslog-native forms the render tests assert must reach disk had stopped
// committing under the first cut of the gate.
func TestRenderAssertedFormsCommit_6844(t *testing.T) {
	for _, tok := range []string{"auth,authpriv", "auth,authpriv,daemon", "*"} {
		if err := config.ValidateSyslogFacility(tok); err != nil {
			t.Errorf("the commit gate rejects %q: %v\n"+
				"This form is documented in pkg/logging/README.md and asserted to render "+
				"as a working drop-in. Rejecting it warns a strict-commit-clean, "+
				"rsyslog-valid destination AWAY on upgrade.", tok, err)
		}
		if !syslogSelectorFacilitySafe(tok) {
			t.Errorf("the render belt drops %q, so the render assertions are stale", tok)
		}
	}
}
