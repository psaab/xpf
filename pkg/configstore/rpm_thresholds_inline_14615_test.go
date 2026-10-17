package configstore

import (
	"strings"
	"testing"
)

// #14615: `thresholds successive-loss N;` written as a one-line
// hierarchical statement arrives as one node
// Keys=[thresholds,successive-loss,N] with no Children. compileRPM's
// thresholds arm iterated only prop.Children, so the value was dropped,
// ThresholdSuccessive stayed 0 and EffectiveSuccessiveLossThreshold()
// silently substituted the default 3 -- and `successive-loss 0` bypassed
// the >=1 validator entirely. The block spelling, the flat set spelling
// and the one-liner must all compile identically, and an inline 0 must
// be rejected at commit naming the leaf.

func rpmThresholdsText14615(thresholdsStmt string) string {
	return `services {
    rpm {
        probe WAN {
            test wan-a {
                probe-type icmp-ping;
                target 1.1.1.1;
                ` + thresholdsStmt + `
            }
        }
    }
}
`
}

func commitRPMThresholds14615(t *testing.T, text string) (int, error) {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer s.ExitConfigure()
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	compiled, err := s.Commit()
	if err != nil {
		return 0, err
	}
	probe := compiled.Services.RPM.Probes["WAN"]
	if probe == nil {
		t.Fatalf("compiled RPM probe WAN missing: %+v", compiled.Services.RPM)
	}
	test := probe.Tests["wan-a"]
	if test == nil {
		t.Fatalf("compiled RPM test wan-a missing: %+v", probe.Tests)
	}
	return test.ThresholdSuccessive, nil
}

func TestRPMThresholdsInlineHierarchical14615(t *testing.T) {
	// One-line hierarchical spelling: the defect site.
	got, err := commitRPMThresholds14615(t, rpmThresholdsText14615("thresholds successive-loss 1;"))
	if err != nil {
		t.Fatalf("inline thresholds successive-loss 1: Commit: %v", err)
	}
	if got != 1 {
		t.Fatalf("inline thresholds successive-loss 1: ThresholdSuccessive=%d, want 1", got)
	}

	// Control: braced block spelling.
	got, err = commitRPMThresholds14615(t, rpmThresholdsText14615("thresholds {\n                    successive-loss 1;\n                }"))
	if err != nil {
		t.Fatalf("block thresholds successive-loss 1: Commit: %v", err)
	}
	if got != 1 {
		t.Fatalf("block thresholds successive-loss 1: ThresholdSuccessive=%d, want 1 (control)", got)
	}

	// Control: a non-default value, so a coincidence with the default 3
	// cannot masquerade as a pass.
	got, err = commitRPMThresholds14615(t, rpmThresholdsText14615("thresholds successive-loss 10;"))
	if err != nil {
		t.Fatalf("inline thresholds successive-loss 10: Commit: %v", err)
	}
	if got != 10 {
		t.Fatalf("inline thresholds successive-loss 10: ThresholdSuccessive=%d, want 10", got)
	}
}

func TestRPMThresholdsInlineZeroRejected14615(t *testing.T) {
	_, err := commitRPMThresholds14615(t, rpmThresholdsText14615("thresholds successive-loss 0;"))
	if err == nil {
		t.Fatal("inline thresholds successive-loss 0: Commit succeeded, want rejection naming successive-loss")
	}
	if !strings.Contains(err.Error(), "successive-loss") {
		t.Fatalf("inline thresholds successive-loss 0: error %q does not name successive-loss", err)
	}

	// Control: the block spelling already rejects 0.
	_, err = commitRPMThresholds14615(t, rpmThresholdsText14615("thresholds {\n                    successive-loss 0;\n                }"))
	if err == nil {
		t.Fatal("block thresholds successive-loss 0: Commit succeeded, want rejection (control)")
	}
	if !strings.Contains(err.Error(), "successive-loss") {
		t.Fatalf("block thresholds successive-loss 0: error %q does not name successive-loss (control)", err)
	}
}

func TestRPMThresholdsInlineNonNumericRejected14615(t *testing.T) {
	_, err := commitRPMThresholds14615(t, rpmThresholdsText14615("thresholds successive-loss asd;"))
	if err == nil {
		t.Fatal("inline thresholds successive-loss asd: Commit succeeded, want rejection naming successive-loss")
	}
	if !strings.Contains(err.Error(), "successive-loss") {
		t.Fatalf("inline thresholds successive-loss asd: error %q does not name successive-loss", err)
	}
}
