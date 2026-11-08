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
			name:  "leaf show version pipe",
			words: []string{"show", "version", "|", "display", "set"},
			want:  `syntax error: "show version" does not accept the output modifier "| display set"`,
		},
		{
			name:  "leaf show hardware pipe",
			words: []string{"show", "chassis", "hardware", "|", "display", "xml"},
			want:  `syntax error: "show chassis hardware" does not accept the output modifier "| display xml"`,
		},
		{
			name:  "leaf show license pipe",
			words: []string{"show", "system", "license", "|", "display", "json"},
			want:  `syntax error: "show system license" does not accept the output modifier "| display json"`,
		},
		{
			name:  "loss-baseline with extra word",
			words: []string{"show", "chassis", "cluster", "data-plane", "statistics", "loss-baseline", "extra"},
			want:  `unknown show chassis cluster data-plane statistics command: loss-baseline`,
		},
		{
			name:  "loss-since missing token",
			words: []string{"show", "chassis", "cluster", "data-plane", "statistics", "loss-since"},
			want:  `unknown show chassis cluster data-plane statistics command: loss-since`,
		},
		{
			name:  "loss-since two tokens",
			words: []string{"show", "chassis", "cluster", "data-plane", "statistics", "loss-since", "a", "b"},
			want:  `unknown show chassis cluster data-plane statistics command: loss-since`,
		},
		{
			name:  "statistics junk suffix",
			words: []string{"show", "chassis", "cluster", "data-plane", "statistics", "junk"},
			want:  `unknown show chassis cluster data-plane statistics command: junk`,
		},
		{
			name:  "leaf trailing bare pipe",
			words: []string{"show", "version", "|"},
			want:  `syntax error: "show version" does not accept the output modifier "|"`,
		},
		{
			name:  "leaf owns multiple pipes",
			words: []string{"show", "version", "|", "display", "xml", "|", "match", "x"},
			want:  `syntax error: "show version" does not accept the output modifier "| display xml | match x"`,
		},
		{
			name:  "options re-entry leaf pipe",
			words: []string{"show", "security", "flow", "session", "summary", "zone", "trust", "|", "display", "xml"},
			want:  `syntax error: "show security flow session summary" does not accept the output modifier "| display xml"`,
		},

		{
			name:  "leaf trailing word before pipe",
			words: []string{"show", "version", "extra", "|", "display", "xml"},
			want:  "unknown show version command: extra",
		},
		{
			name:  "leaf glued output pipe",
			words: []string{"show", "version", "|display", "xml"},
			want:  `unknown show version command: |display (separate the pipe with spaces: "| display")`,
		},
		{
			name:  "leaf trailing word without pipe",
			words: []string{"show", "version", "extra"},
			want:  "unknown show version command: extra",
		},
		{
			name:  "unknown token before pipe",
			words: []string{"clear", "security", "ike", "|", "display", "set"},
			want:  "unknown clear security command: ike",
		},
		{
			name:  "quoted pipe token is an ordinary unknown word",
			words: []string{"clear", "security", "'|'"},
			want:  "unknown clear security command: '|'",
		},
		{
			name:  "selector leaf bare pipe",
			words: []string{"show", "class-of-service", "interface", "|", "display", "xml"},
			want:  `syntax error: "show class-of-service interface" does not accept the output modifier "| display xml"`,
		},
		{
			name:  "selector leaf pipe after selector",
			words: []string{"show", "class-of-service", "interface", "reth0.80", "|", "display", "xml"},
			want:  `syntax error: "show class-of-service interface" does not accept the output modifier "| display xml"`,
		},
		{
			name:  "selector leaf rejects a second trailing word",
			words: []string{"show", "class-of-service", "interface", "reth0.80", "extra"},
			want:  "unknown show class-of-service interface command: extra",
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
		{"show", "system", "rollback"},
		{"show", "configuration", "security", "'|'"},
		{"show", "security", "flow", "session", "summary", "zone", "trust"},
		{"show", "class-of-service", "interface", "reth0.80"},
		{"show", "class-of-service", "interface", "'|'"},
		{"show", "chassis", "cluster", "data-plane", "statistics", "loss-baseline"},
		{"show", "chassis", "cluster", "data-plane", "statistics", "loss-since", "opaque-token"},
	} {
		if err := ValidateOperationalGate(words); err != nil {
			t.Errorf("ValidateOperationalGate(%q) = %v; want nil", words, err)
		}
	}
	if !OperationalTree["show"].Children["chassis"].Children["cluster"].Children["data-plane"].Children["statistics"].LossProbe {
		t.Fatal("show chassis cluster data-plane statistics must declare its loss probes")
	}
	if !OperationalTree["show"].Children["class-of-service"].Children["interface"].OptionalSelector {
		t.Fatal("show class-of-service interface must declare its one optional selector")
	}
}

func TestOperationalGateKeepsHandlerOwnedGrammar18668(t *testing.T) {
	for _, tc := range []struct {
		name  string
		words []string
	}{
		{
			name:  "incomplete required value remains handler-owned",
			words: []string{"show", "system", "rollback"},
		},
		{
			name:  "quoted pipe argument remains data",
			words: []string{"show", "configuration", "security", "'|'"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateOperationalGate(tc.words); err != nil {
				t.Fatalf("ValidateOperationalGate(%q) = %v; want handler-owned command", tc.words, err)
			}
		})
	}
}
