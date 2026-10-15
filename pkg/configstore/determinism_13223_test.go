package configstore

import "testing"

func TestPendingRenameAncestryDeterministic_13223(t *testing.T) {
	store := &Store{pendingRenameAncestry: map[uint64][]RenameDescriptor{
		9: {{SourcePath: []string{"nine"}}},
		2: {{SourcePath: []string{"two"}}},
		5: {{SourcePath: []string{"five"}}},
	}}
	for range 50 {
		got := store.PendingRenameAncestry()
		if len(got) != 3 || got[0].SourcePath[0] != "two" || got[1].SourcePath[0] != "five" || got[2].SourcePath[0] != "nine" {
			t.Fatalf("ancestry must follow ascending generation order, got %#v", got)
		}
	}
}
