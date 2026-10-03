package cmdtree

import "testing"

func TestCompletionWalkersLimitDynamicNodeToOneValue11835(t *testing.T) {
	oneValue := []string{"show", "security", "policies", "from-zone", "trust"}
	extraValue := []string{"show", "security", "policies", "from-zone", "trust", "unexpected"}

	if got := CompleteFromTree(OperationalTree, oneValue, "to-", nil); !contains(got, "to-zone") {
		t.Fatalf("completion after one dynamic value = %v, want to-zone", got)
	}
	if got := CompleteFromTreeWithDesc(OperationalTree, oneValue, "to-", nil); len(got) != 1 || got[0].Name != "to-zone" {
		t.Fatalf("described completion after one dynamic value = %v, want to-zone", got)
	}
	if got := LookupDesc(oneValue, "to-zone", false); got != "Filter by destination zone" {
		t.Fatalf("description after one dynamic value = %q, want %q", got, "Filter by destination zone")
	}

	if got := CompleteFromTree(OperationalTree, extraValue, "", nil); len(got) != 0 {
		t.Errorf("completion after a second dynamic value = %v, want none", got)
	}
	if got := CompleteFromTreeWithDesc(OperationalTree, extraValue, "", nil); len(got) != 0 {
		t.Errorf("described completion after a second dynamic value = %v, want none", got)
	}
	if got := LookupDesc(extraValue, "to-zone", false); got != "" {
		t.Errorf("description after a second dynamic value = %q, want none", got)
	}

}
