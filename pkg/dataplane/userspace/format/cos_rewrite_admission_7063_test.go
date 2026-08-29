package format

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// cosCfg7063 builds a config with one dscp rewrite rule targeting `voice`, bound
// on one unit. schedClass controls which forwarding class the unit's
// scheduler-map materializes; "" means no scheduler-map at all, which is the
// synthetic-default case.
func cosCfg7063(t *testing.T, schedClass string) *config.Config {
	t.Helper()
	cos := &config.ClassOfServiceConfig{
		ForwardingClasses: map[string]*config.CoSForwardingClass{
			"voice":       {Name: "voice", Queue: 5},
			"best-effort": {Name: "best-effort", Queue: 0},
		},
		Schedulers:    map[string]*config.CoSScheduler{"s": {Name: "s"}},
		SchedulerMaps: map[string]*config.CoSSchedulerMap{},
		DSCPRewriteRules: map[string]*config.CoSDSCPRewriteRule{
			"rw": {Name: "rw", Entries: []*config.CoSDSCPRewriteRuleEntry{
				{ForwardingClass: "voice", LossPriority: "low", DSCPValue: 46},
			}},
		},
		Interfaces: map[string]*config.CoSInterface{},
	}
	unit := &config.CoSInterfaceUnit{DSCPRewriteRule: "rw"}
	if schedClass != "" {
		cos.SchedulerMaps["sm"] = &config.CoSSchedulerMap{
			Name:    "sm",
			Entries: map[string]*config.CoSSchedulerMapEntry{schedClass: {Scheduler: "s"}},
		}
		unit.SchedulerMap = "sm"
	}
	cos.Interfaces["ge-0-0-0"] = &config.CoSInterface{
		Units: map[int]*config.CoSInterfaceUnit{0: unit},
	}
	return &config.Config{
		ClassOfService: cos,
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0-0-0": {Units: map[int]*config.InterfaceUnit{0: {}}},
		}},
	}
}

// #7063: `Enforced: yes` was answered from the BINDING alone. The helper builds
// the rewrite matrix only over the queues the interface materializes
// (build_cos_iface_config), so a rule whose forwarding-classes do not intersect
// them rewrites nothing while the command claimed it was enforced.
//
// The issue says closing this needs "state the config alone does not carry".
// It does not, and this table is the evidence: `iface_classes` is the
// scheduler-map's resolved classes, or the synthetic `best-effort` queue when
// none resolve. Both are config.
//
// All four rows are required and each kills a different wrong fix:
//
//   - intersects -> enforced. Without it, "report inert whenever bound" passes.
//   - disjoint -> inert. The defect itself.
//   - no scheduler-map + rule targets best-effort -> ENFORCED. A fix that treated
//     "no scheduler-map" as "materializes nothing" would report this inert, which
//     is wrong in the opposite direction and invisible to the first two rows.
//   - no scheduler-map + rule targets voice -> inert. The synthetic default is
//     best-effort ALONE, so it must not excuse every class.
func TestRewriteRuleEnforcementHonoursTheAdmissionGate_7063(t *testing.T) {
	for _, tc := range []struct {
		name        string
		schedClass  string
		ruleClass   string
		wantEnforce bool
	}{
		{"scheduler-map materializes the rule's class", "voice", "voice", true},
		{"scheduler-map materializes a DIFFERENT class", "best-effort", "voice", false},
		{"no scheduler-map, rule targets best-effort", "", "best-effort", true},
		{"no scheduler-map, rule targets voice", "", "voice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cosCfg7063(t, tc.schedClass)
			cfg.ClassOfService.DSCPRewriteRules["rw"].Entries[0].ForwardingClass = tc.ruleClass

			out := FormatCoSRewriteRules(cfg, "", "")
			enforced := strings.Contains(out, "Enforced: yes")
			if enforced != tc.wantEnforce {
				if tc.wantEnforce {
					t.Errorf("a rule the helper WILL materialize was reported not enforced — the "+
						"gate is over-tight and now under-reports working rewrites:\n%s", out)
				} else {
					t.Errorf("a rule whose forwarding-classes the interface does not materialize "+
						"was reported Enforced: yes. The helper builds no rewrite entry for it, so "+
						"this converts an unanswered question into a confidently wrong answer — "+
						"the #6858 failure class inside the command written to expose it:\n%s", out)
				}
			}
			if tc.wantEnforce {
				return
			}
			// Name the reference, for the reason the dangling arm names its own:
			// a bare "not enforced" reads as "you forgot to bind it" to an
			// operator who did bind it, just where it cannot act.
			if !strings.Contains(out, "ge-0-0-0 unit 0") {
				t.Errorf("the inert reason does not say WHERE the rule is bound:\n%s", out)
			}
			// And it must not be reported as the DANGLING case: the unit exists.
			if strings.Contains(out, "is not a configured logical interface unit") {
				t.Errorf("an inert-but-real binding was reported as a dangling reference, which "+
					"sends the operator to check a name that is correct:\n%s", out)
			}
		})
	}
}

// A rule bound where it DOES apply is enforced, whatever another interface does
// with it. Without the reconciling delete an operator who bound the rule
// correctly on one interface and pointlessly on another would be told it is not
// enforced — a false negative produced by the fix for a false positive.
func TestRewriteRuleBoundUsefullySomewhereIsEnforced_7063(t *testing.T) {
	cfg := cosCfg7063(t, "voice")
	cfg.ClassOfService.SchedulerMaps["other"] = &config.CoSSchedulerMap{
		Name:    "other",
		Entries: map[string]*config.CoSSchedulerMapEntry{"best-effort": {Scheduler: "s"}},
	}
	cfg.ClassOfService.Interfaces["ge-0-0-1"] = &config.CoSInterface{
		Units: map[int]*config.CoSInterfaceUnit{0: {SchedulerMap: "other", DSCPRewriteRule: "rw"}},
	}
	cfg.Interfaces.Interfaces["ge-0-0-1"] = &config.InterfaceConfig{
		Units: map[int]*config.InterfaceUnit{0: {}},
	}
	out := FormatCoSRewriteRules(cfg, "", "")
	if !strings.Contains(out, "Enforced: yes") {
		t.Errorf("a rule that applies on ge-0-0-0 was reported not enforced because a SECOND "+
			"interface binds it where it cannot act. Enforcement is a property of the rule "+
			"across the box, not of the least useful binding:\n%s", out)
	}
}

// The synthetic default class is one wire fact spelled in two languages. A
// silent divergence would make this command confidently wrong for exactly the
// interfaces that have no scheduler-map — the case with no other signal.
//
// Parsed rather than mirrored in a comment, the same way
// TestSnapshotProtocolVersionLockstepWithRust parses control.rs.
func TestCoSSyntheticDefaultClassMatchesRust_7063(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..",
		"userspace-dp", "src", "afxdp", "forwarding_build", "cos.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the synthetic-default lockstep guard cannot run)", path, err)
	}
	re := regexp.MustCompile(`\(vec!\[0\],\s*vec!\["([^"]+)"\]\)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("the synthetic default queue literal was not found in %s. If it was "+
			"reshaped, update this guard rather than deleting it — the class it names is "+
			"what this package assumes for a unit whose scheduler-map resolves nothing", path)
	}
	if got := string(m[1]); got != cosSyntheticDefaultForwardingClass {
		t.Fatalf("synthetic default forwarding class skew: Go says %q, "+
			"forwarding_build/cos.rs says %q. A unit with no scheduler-map materializes the "+
			"Rust one, so this command would report enforcement against a class the helper "+
			"never creates", cosSyntheticDefaultForwardingClass, got)
	}
}
