package cmdtree

import "testing"

// TestOperationalGate18668 pins every error shape and the pipe-position
// classification shared by the local and remote operational dispatchers.
func TestOperationalGate18668(t *testing.T) {
	for _, tc := range []struct {
		name  string
		words []string
		want  string
	}{
		{
			name:  "keyword-only clear pipe",
			words: []string{"clear", "security", "|", "display", "set"},
			want:  `syntax error: "clear security" does not accept the output modifier "| display set"`,
		},
		{
			name:  "keyword-only request pipe",
			words: []string{"request", "chassis", "cluster", "|", "display", "set"},
			want:  `syntax error: "request chassis cluster" does not accept the output modifier "| display set"`,
		},
		{
			name:  "keyword-only show pipe",
			words: []string{"show", "chassis", "|", "display", "set"},
			want:  `syntax error: "show chassis" does not accept the output modifier "| display set"`,
		},
		{
			name:  "unknown token before pipe",
			words: []string{"clear", "security", "ike", "|", "display", "set"},
			want:  "unknown clear security command: ike",
		},
		{
			name:  "first bare pipe owns the suffix",
			words: []string{"clear", "security", "|", "display", "set", "|", "match", "x"},
			want:  `syntax error: "clear security" does not accept the output modifier "| display set | match x"`,
		},
		{
			name:  "ambiguous keyword",
			words: []string{"clear", "s"},
			want:  "ambiguous clear command: s",
		},
		{
			name:  "glued pipe token is ordinary word",
			words: []string{"show", "configuration", "|display", "set"},
			want:  `unknown show configuration command: |display (separate the pipe with spaces: "| display")`,
		},
		{
			name:  "glued pipe in first command word is ordinary word",
			words: []string{"show", "configuration|display", "set"},
			want:  `unknown show command: configuration|display (separate the pipe with spaces: "configuration | display")`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOperationalGate(tc.words)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("ValidateOperationalGate(%q) = %v; want %q", tc.words, err, tc.want)
			}
		})
	}

	if got := len(OperationalPipeConsumers); got != 1 || !OperationalPipeConsumers["show configuration"] {
		t.Fatalf("OperationalPipeConsumers = %v; want only show configuration", OperationalPipeConsumers)
	}
}

func TestOperationalGateControls18668(t *testing.T) {
	for _, words := range [][]string{
		nil,
		{},
		{"clear", "security"},
		{"show", "configuration", "|", "display", "set"},
		{"show", "system", "rollback", "1", "|", "display", "set"},
		{"show", "configuration", "security", "|", "display", "set"},
	} {
		if err := ValidateOperationalGate(words); err != nil {
			t.Errorf("ValidateOperationalGate(%q) = %v; want nil", words, err)
		}
	}
}
