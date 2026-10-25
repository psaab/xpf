package config

import (
	"strings"
	"testing"
)

// #16698: ClassifyLoadContent sent a whole body to flat replay if ANY
// uncommented line was a flat-verb line, with no brace-depth check. The
// box's own hierarchical rendering of an unquoted event-options
// change-configuration command puts `set system host-name pwned;` on its
// own line inside `commands { ... }`, so `show configuration > file`
// followed by `load override`/`load merge` of that file failed loud at
// line 1 (`system {` is not a flat command). A hierarchically authored
// bare command carries no quote provenance, so Format prints it bare.

const hierEventUnquoted16698 = `event-options {
    policy p {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    set system host-name pwned;
                }
            }
        }
    }
}
system {
    host-name before;
}
`

const hierEventQuoted16698 = `event-options {
    policy p {
        events ping_test_failed;
        then {
            change-configuration {
                commands "set system host-name pwned";
            }
        }
    }
}
`

func TestClassifyHierEventCommandNotFlat16698(t *testing.T) {
	for name, body := range map[string]string{
		"unquoted commands block": hierEventUnquoted16698,
		"quoted commands leaf":    hierEventQuoted16698,
	} {
		t.Run(name, func(t *testing.T) {
			flat, _, err := ClassifyLoadContent(body)
			if err != nil {
				t.Fatalf("ClassifyLoadContent error = %v", err)
			}
			if flat {
				t.Errorf("flat = true, want false: a flat-verb line at brace depth > 0 "+
					"is a hierarchical value, not a flat script (#16698)\n%s", body)
			}
		})
	}
}

func TestClassifyBraceDepthControls16698(t *testing.T) {
	cases := map[string]struct {
		body string
		flat bool
	}{
		// Flat scripts stay flat: every verb line is at depth 0.
		"flat set": {body: "set system host-name a\nset system domain-name b\n", flat: true},
		// A quoted brace is string data to the real lexer, not structure:
		// it must not push following flat lines inside a phantom block.
		"flat quoted open brace":  {body: "set system host-name \"{\"\nset system domain-name b\n", flat: true},
		"flat quoted close brace": {body: "set system host-name \"}\"\nset system domain-name b\n", flat: true},
		// A flat-verb line after the hierarchical block has closed is at
		// depth 0 again: the mixed body still routes flat (and the store
		// then fails loud on the hierarchical line, as before).
		"verb after block closes": {body: "system {\n    host-name a;\n}\nset system host-name b\n", flat: true},
		// Verb inside braces only: hierarchical.
		"verb only inside braces": {body: "system {\n    set system host-name b;\n}\n", flat: false},
		// Ordinary hierarchical bodies are unchanged.
		"plain hierarchical": {body: "system {\n    host-name a;\n}\n", flat: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			flat, _, err := ClassifyLoadContent(tc.body)
			if err != nil {
				t.Fatalf("ClassifyLoadContent error = %v", err)
			}
			if flat != tc.flat {
				t.Errorf("flat = %v, want %v (#16698)\n%s", flat, tc.flat, tc.body)
			}
		})
	}
}

// The authorization gate must adjudicate the hierarchical rendering of
// the event body (the outer event-options leaf), not just the embedded
// verb line taken verbatim.
func TestLoadMutationLinesHierEvent16698(t *testing.T) {
	lines, err := LoadMutationLines(hierEventUnquoted16698)
	if err != nil {
		t.Fatalf("LoadMutationLines error = %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "event-options policy p then change-configuration commands") {
		t.Errorf("gate did not render the hierarchical form; the event leaf was "+
			"never adjudicated as authored (#16698): %q", joined)
	}
	if !strings.Contains(joined, "system host-name before") {
		t.Errorf("rendered lines omit the plain hierarchical leaf: %q", joined)
	}
}
