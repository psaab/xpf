package cmdtree

import "testing"

func TestClassifyComparePipe18993(t *testing.T) {
	for _, tc := range []struct {
		name      string
		words     []string
		wantFound bool
		wantGlued bool
	}{
		{"spaced global", []string{"show", "configuration", "|", "compare", "rollback", "1"}, true, false},
		{"spaced scoped", []string{"show", "configuration", "system", "|", "compare", "rollback", "1"}, true, false},
		{"left glued global", []string{"show", "configuration|", "compare", "rollback", "1"}, true, true},
		{"left glued scoped", []string{"show", "configuration", "system|", "compare", "rollback", "1"}, true, true},
		{"right glued", []string{"show", "configuration", "|compare", "rollback", "1"}, true, true},
		{"both sides glued", []string{"show", "configuration", "system|compare", "rollback", "1"}, true, true},
		{"comment-end glued", []string{"show", "configuration", "/*x*/|", "compare", "rollback", "1"}, true, true},
		{"comment after pipe glued", []string{"show", "configuration", "|/*x*/compare", "rollback", "1"}, false, false},
		{"non-compare pipe", []string{"show", "configuration", "|", "display", "set"}, false, false},
		{"unrelated text", []string{"show", "configuration", "system"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, glued := ClassifyComparePipe(tc.words)
			if found != tc.wantFound || glued != tc.wantGlued {
				t.Fatalf("ClassifyComparePipe(%q) = (%v, %v); want (%v, %v)", tc.words, found, glued, tc.wantFound, tc.wantGlued)
			}
		})
	}
}
