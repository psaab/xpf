package config

import (
	"strings"
	"testing"
)

// TestAtSignRulingsAreOppositeOnPurpose8934 pins two rulings about `@` that
// were made the same day, in opposite directions, on different surfaces.
//
//	#8924  an SSH algorithm name MAY contain `@`  (aes256-gcm@openssh.com)
//	#8934  a community LITERAL may NOT contain `@` (@evil)
//
// Both are correct and they are not in tension: OpenSSH's grammar includes `@`
// in algorithm names, and FRR's community-literal grammar does not. But nothing
// pinned them apart, and each looks like "the repo's position on `@`" when read
// alone. Without this cell the likely failure is not a regression but a
// well-meant CORRECTION: someone finds one ruling, reads it as the policy, and
// "fixes" the other to match.
//
// Asserting them together makes the asymmetry deliberate and legible, and reds
// if either half is changed to agree with the other.
func TestAtSignRulingsAreOppositeOnPurpose8934(t *testing.T) {
	// RULING ONE — `@` is ACCEPTED in an SSH algorithm name. The schema offers
	// these as completions (quoted, since the lexer needs it), so refusing them
	// would make the tool contradict itself again (#8924).
	for _, alg := range []string{
		"aes256-gcm@openssh.com",
		"hmac-sha2-256-etm@openssh.com",
		"curve25519-sha256@libssh.org",
	} {
		if err := ValidateSSHAlgorithm(alg); err != nil {
			t.Errorf("ValidateSSHAlgorithm rejects %q (%v). OpenSSH algorithm "+
				"names legitimately carry `@`, the schema OFFERS these as "+
				"completions, and #8924 exists because the tool used to refuse "+
				"a value it suggested. If this was tightened to match the "+
				"community rule, that is the wrong direction (#8934).", alg, err)
		}
	}

	// RULING TWO — `@` is REJECTED in a non-regex community member, because
	// FRR's standard community-list takes only ASN:VALUE / A:B:C / a well-known
	// name, and a malformed literal fails the WHOLE frr-reload.
	for _, member := range []string{"@evil", "65000:a@b"} {
		err := ValidCommunityMember(member)
		if err == nil {
			t.Errorf("ValidCommunityMember accepts %q. A non-regex member "+
				"renders into an FRR `standard` community-list, which rejects "+
				"a malformed literal at config load -- and one "+
				"CMD_WARNING_CONFIG_FAILED fails the entire frr-reload. If "+
				"this was loosened to match the SSH rule, that is the wrong "+
				"direction (#8934).", member)
			continue
		}
		if !strings.Contains(err.Error(), "@") {
			t.Errorf("%q was rejected but the message does not name the "+
				"character (%v); an operator cannot act on it.", member, err)
		}
	}

	// THE ASYMMETRY IS PER-SURFACE, not per-character: the same `@` is fine
	// inside a community REGEX, where FRR compiles it with regcomp.
	if err := ValidCommunityMember("65000:.*@x"); err != nil {
		t.Errorf("ValidCommunityMember rejects the REGEX %q (%v). The reject is "+
			"deliberately limited to non-regex members; FRR's regcomp accepts "+
			"`@` as an ordinary literal inside an expanded list, so refusing it "+
			"there would false-reject a working config -- the "+
			"over-approximation this gate's scope note warns against (#8934).",
			"65000:.*@x", err)
	}
}
