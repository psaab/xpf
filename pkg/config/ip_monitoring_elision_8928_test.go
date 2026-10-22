package config

import (
	"strings"
	"testing"
)

// #8928: eliding a container drops its child BEFORE strict validation runs, so
// a dangling cross-reference commits clean — the elision suppresses its own
// detector.
//
// `services ip-monitoring` was one of the issue's two named instances and was
// recorded there as fixed. It was not: measured at master, the braced spelling
// rejected a typo'd rpm-probe and the elided spelling committed clean.
//
// THE CHAIN, which is why the pair was already admitted and still inert — the
// #8858 shape:
//
//	services      -> ip-monitoring   ADMITTED
//	ip-monitoring -> policy          MISSING     <- the break
//	match         -> rpm-probe       ADMITTED    (unreachable below the break)
//
// Only the missing link is added. `policy -> match` is deliberately NOT
// admitted: that pair is effective at THREE schema sites — `security policies
// from-zone <n> policy`, `security policies global policy` and `services
// ip-monitoring policy` — so admitting it would change security-policy
// compilation to fix an ip-monitoring defect. It is not needed: the body from
// `match` inward is already braced in the reachable spelling. That multi-site
// hazard is #8921's subject, and this change is scoped to stay out of it.

func TestIPMonitoringElisionDoesNotSuppressValidation8928(t *testing.T) {
	const (
		braced = `services { ip-monitoring { policy p1 { match { rpm-probe nosuchprobe; } } } }`
		elided = `services ip-monitoring policy p1 { match { rpm-probe nosuchprobe; } }`
	)
	strictErr := func(text string) error {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
		}
		_, err := compileTree(tree, compileOpts{}, nil)
		return err
	}

	// LIVENESS: the braced arm must reject FOR THE REFERENCE. Without this the
	// comparison below could be satisfied by any rejection at all.
	bErr := strictErr(braced)
	if bErr == nil {
		t.Fatal("the braced reference committed clean — the cross-reference check no longer " +
			"fires, so this cell cannot detect its suppression")
	}
	if !strings.Contains(bErr.Error(), "nosuchprobe") {
		t.Fatalf("the braced arm rejected, but not for the dangling probe (%v) — a different "+
			"rejection would make the elided comparison meaningless", bErr)
	}

	eErr := strictErr(elided)
	if eErr == nil {
		t.Fatalf("the ELIDED spelling committed clean while the braced spelling rejected %q. "+
			"The elision drops the policy before validation, so a typo'd rpm-probe reaches "+
			"production and probe-driven WAN failover silently never arms", "nosuchprobe")
	}
	if !strings.Contains(eErr.Error(), "nosuchprobe") {
		t.Errorf("the elided spelling rejected for a different reason than the braced one:\n"+
			" braced: %v\n elided: %v", bErr, eErr)
	}
}

// The multi-site pair must stay OUT of scope. If `policy match` is ever
// admitted, it becomes effective on the security-policy enforcement surface,
// and that is a decision requiring its own adjudication at those sites.
func TestPolicyMatchStaysUnadmitted8928(t *testing.T) {
	if compactNormalizeInScope("policy", "match") {
		t.Error("`policy match` is admitted. It is effective at three schema sites, two of " +
			"them `security policies ... policy`, so admitting it changes how security " +
			"policies compile. If that is intended it needs adjudication at each site (#8921), " +
			"not as a side effect of an ip-monitoring fix")
	}
}
