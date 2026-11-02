package config

import (
	"strings"
	"testing"
)

// The dual-AST walker must cover unexported Config fields WITHOUT
// reflect.Value.Interface (it panics on them, which aborted every later
// pkg/config test from #16078 on). These cells pin both halves: a registered
// unexported field is compared, and an unregistered one is reported.
func TestDiffConfigSectionsComparesUnexportedFields(t *testing.T) {
	a, b := &Config{}, &Config{}
	if d := diffConfigSections(a, b); d != "" {
		t.Fatalf("identical configs reported a difference:\n%s", d)
	}
	b.userIdentificationStanzas = []string{"services user-identification"}
	if d := diffConfigSections(a, b); !strings.Contains(d, "section userIdentificationStanzas differs") {
		t.Errorf("a difference in the unexported userIdentificationStanzas was not reported; got:\n%s", d)
	}
}

func TestDiffConfigSectionsReportsUnregisteredUnexportedField(t *testing.T) {
	saved := unexportedConfigFieldDiffs["userIdentificationStanzas"]
	delete(unexportedConfigFieldDiffs, "userIdentificationStanzas")
	t.Cleanup(func() { unexportedConfigFieldDiffs["userIdentificationStanzas"] = saved })
	if d := diffConfigSections(&Config{}, &Config{}); !strings.Contains(d, "no comparator in unexportedConfigFieldDiffs") {
		t.Errorf("an unexported Config field with no comparator was not reported; got:\n%s", d)
	}
}
