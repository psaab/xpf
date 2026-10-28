package config

import (
	"strings"
	"testing"
)

// #17183 (R4-Q50-04): the seven CoS code-point kinds were seven hand-copied
// loops recording definedness three ways. #15681 fixed entryless-but-defined
// for the inet-precedence classifier only, so an entryless dscp or ieee-802.1
// classifier or rewrite-rule bound to a unit failed strict commit as
// "undefined" while the inet-precedence / exp twins committed. All seven now
// compile through compileCoSCodePointKind and both binding consumers ask the
// one cosCodePointKind.isDefined predicate.
//
// FAIL-ON-REVERT: restoring `if len(Entries) > 0` around the map-backed
// stores, or checking the Defs maps instead of isDefined in either gate,
// makes the four entryless rows below fail strict commit again.

type cosEntrylessKind17183 struct {
	name    string
	def     string // definition prefix, name appended
	bind    string // unit binding suffix ("" when Junos cannot bind the kind)
	entry   string // one populated entry tail
	defined func(*ClassOfServiceConfig) bool
	warnSub string
}

func cosEntrylessKinds17183() []cosEntrylessKind17183 {
	return []cosEntrylessKind17183{
		{
			name:  "classifiers dscp",
			def:   "set class-of-service classifiers dscp R",
			bind:  "classifiers dscp R",
			entry: " forwarding-class BE loss-priority low code-points 000000",
			defined: func(cos *ClassOfServiceConfig) bool {
				d, ok := cos.DSCPClassifiers["R"]
				return ok && d != nil && len(d.Entries) == 0
			},
			warnSub: `references undefined dscp classifier "R"`,
		},
		{
			name:  "classifiers ieee-802.1",
			def:   "set class-of-service classifiers ieee-802.1 R",
			bind:  "classifiers ieee-802.1 R",
			entry: " forwarding-class BE loss-priority low code-points 0",
			defined: func(cos *ClassOfServiceConfig) bool {
				d, ok := cos.IEEE8021Classifiers["R"]
				return ok && d != nil && len(d.Entries) == 0
			},
			warnSub: `references undefined ieee-802.1 classifier "R"`,
		},
		{
			name:  "classifiers inet-precedence",
			def:   "set class-of-service classifiers inet-precedence R",
			bind:  "classifiers inet-precedence R",
			entry: " forwarding-class BE loss-priority low code-points 0",
			defined: func(cos *ClassOfServiceConfig) bool {
				d, ok := cos.INetPrecedenceClassifierDefs["R"]
				return ok && d != nil && len(d.Entries) == 0
			},
			warnSub: `references undefined inet-precedence classifier "R"`,
		},
		{
			name:  "rewrite-rules inet-precedence",
			def:   "set class-of-service rewrite-rules inet-precedence R",
			bind:  "",
			entry: " forwarding-class BE loss-priority low code-point 0",
			defined: func(cos *ClassOfServiceConfig) bool {
				kind, ok := cosCodePointKindBy("rewrite-rules", "inet-precedence")
				return ok && kind.isDefined(cos, "R")
			},
		},
		{
			name:  "rewrite-rules exp",
			def:   "set class-of-service rewrite-rules exp R",
			bind:  "",
			entry: " forwarding-class BE loss-priority low code-point 0",
			defined: func(cos *ClassOfServiceConfig) bool {
				kind, ok := cosCodePointKindBy("rewrite-rules", "exp")
				return ok && kind.isDefined(cos, "R")
			},
		},
		{
			name:  "rewrite-rules dscp",
			def:   "set class-of-service rewrite-rules dscp R",
			bind:  "rewrite-rules dscp R",
			entry: " forwarding-class BE loss-priority low code-point 000000",
			defined: func(cos *ClassOfServiceConfig) bool {
				d, ok := cos.DSCPRewriteRules["R"]
				return ok && d != nil && len(d.Entries) == 0
			},
			warnSub: `references undefined dscp rewrite-rule "R"`,
		},
		{
			name:  "rewrite-rules ieee-802.1",
			def:   "set class-of-service rewrite-rules ieee-802.1 R",
			bind:  "rewrite-rules ieee-802.1 R",
			entry: " forwarding-class BE loss-priority low code-point 0",
			defined: func(cos *ClassOfServiceConfig) bool {
				d, ok := cos.IEEE8021RewriteRules["R"]
				return ok && d != nil && len(d.Entries) == 0
			},
			warnSub: `references undefined ieee-802.1 rewrite-rule "R"`,
		},
	}
}

func compileLines17183(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	return CompileConfig(tree)
}

// TestCoSEntrylessKindsCommitAndResolve17183 is the acceptance probe as a
// real table test: all seven entryless kinds commit strict with the name
// resolvable (via the unit binding where Junos has one, via isDefined for
// the two unbindable inert rewrite kinds), the populated twin still
// commits, and no undefined warning fires for the defined name.
func TestCoSEntrylessKindsCommitAndResolve17183(t *testing.T) {
	for _, k := range cosEntrylessKinds17183() {
		for _, populated := range []bool{false, true} {
			t.Run(k.name, func(t *testing.T) {
				def := k.def
				if populated {
					def += k.entry
				}
				lines := []string{
					"set class-of-service forwarding-classes queue 0 BE",
					"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
					def,
				}
				if k.bind != "" {
					lines = append(lines, "set class-of-service interfaces ge-0/0/0 unit 0 "+k.bind)
				}
				cfg, err := compileLines17183(t, lines...)
				if err != nil {
					t.Fatalf("entryless=%v kind %s strict commit rejected: %v", !populated, k.name, err)
				}
				if !populated && !k.defined(cfg.ClassOfService) {
					t.Fatalf("entryless kind %s: name R not recorded as defined (cos=%+v)", k.name, cfg.ClassOfService)
				}
				if k.warnSub != "" {
					for _, w := range ValidateConfig(cfg) {
						if strings.Contains(w, k.warnSub) {
							t.Fatalf("defined entryless %s warned undefined: %q", k.name, w)
						}
					}
				}
			})
		}
	}
}

// The unified predicate must not become fail-open: a never-defined name on
// each bindable kind still rejects strict (the #7337 gate, through the new
// loop) and still warns on the tolerant ValidateConfig path.
func TestCoSUndefinedKindsStillReject17183(t *testing.T) {
	for _, k := range cosEntrylessKinds17183() {
		if k.bind == "" {
			continue
		}
		t.Run(k.name, func(t *testing.T) {
			_, err := compileLines17183(t,
				"set class-of-service forwarding-classes queue 0 BE",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set class-of-service interfaces ge-0/0/0 unit 0 "+k.bind,
			)
			if err == nil || !strings.Contains(err.Error(), k.warnSub) {
				t.Fatalf("undefined %s binding: err=%v, want substring %q", k.name, err, k.warnSub)
			}
		})
	}
}
