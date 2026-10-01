package config

import (
	"reflect"
	"strings"
	"testing"
)

// FAIL ON REVERT: these out-of-normalizer `then` heads leave the compact leaf
// intact, so compileFilterThen's leaf arm is the only reader of the trailing
// routing-instance. Dropping that arm leaves a clean config with no steering;
// it also disarms the strict conflict gates for discard/reject/next-term.
func TestThenLeafOutOfScopeHeadsKeepRoutingInstance11354(t *testing.T) {
	const ri = "ri54"
	heads := []struct {
		name, head, action, rejectMessageType string
		log, syslog, nextTerm                 bool
		terminals                             []string
		strictConflict                        []string
	}{
		{name: "accept", head: "accept", action: "accept", terminals: []string{"accept"}},
		{name: "discard", head: "discard", action: "discard", terminals: []string{"discard"},
			strictConflict: []string{"routing-instance " + ri, "discard", "mutually exclusive"}},
		{name: "reject", head: "reject", action: "reject", terminals: []string{"reject"},
			strictConflict: []string{"routing-instance " + ri, "reject", "mutually exclusive"}},
		{name: "reject-message-type", head: "reject administratively-prohibited", action: "reject",
			rejectMessageType: "administratively-prohibited", terminals: []string{"reject"},
			strictConflict: []string{"routing-instance " + ri, "reject", "mutually exclusive"}},
		{name: "next", head: "next", nextTerm: true,
			strictConflict: []string{"routing-instance " + ri, "next term"}},
		{name: "next-term", head: "next term", nextTerm: true,
			strictConflict: []string{"routing-instance " + ri, "next term"}},
		{name: "syslog", head: "syslog", log: true, syslog: true},
	}
	shapes := []struct {
		name    string
		grouped bool
	}{
		{name: "compact-leaf"},
		{name: "apply-groups", grouped: true},
	}

	for _, shape := range shapes {
		for _, head := range heads {
			shape, head := shape, head
			t.Run(shape.name+"/"+head.name, func(t *testing.T) {
				tree := thenLeafFixture11354(t, head.head+" routing-instance "+ri, shape.grouped)
				cfg, err := CompileConfig(tree)
				if len(head.strictConflict) > 0 {
					if err == nil {
						t.Fatalf("strict compile accepted conflicting then %s routing-instance %s; the leaf fields did not reach the #3308/#9140 gate", head.head, ri)
					}
					for _, part := range head.strictConflict {
						if !strings.Contains(err.Error(), part) {
							t.Fatalf("strict error %q does not identify conflict component %q", err, part)
						}
					}
				} else {
					if err != nil {
						t.Fatalf("valid then %s routing-instance %s must compile: %v", head.head, ri, err)
					}
					if len(cfg.Warnings) != 0 {
						t.Fatalf("valid leaf FBF config must not warn, got %v", cfg.Warnings)
					}
				}

				lenient, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("lenient compile failed: %v", err)
				}
				term := firstInetTerm(t, lenient, "f11354")
				if term.RoutingInstance != ri {
					t.Errorf("compiled routing-instance=%q, want %q", term.RoutingInstance, ri)
				}
				if term.Action != head.action {
					t.Errorf("compiled action=%q, want %q", term.Action, head.action)
				}
				if term.RejectMessageType != head.rejectMessageType {
					t.Errorf("compiled reject-message-type=%q, want %q", term.RejectMessageType, head.rejectMessageType)
				}
				if term.Log != head.log || term.Syslog != head.syslog || term.NextTerm != head.nextTerm {
					t.Errorf("compiled log=%t syslog=%t next-term=%t, want %t/%t/%t",
						term.Log, term.Syslog, term.NextTerm, head.log, head.syslog, head.nextTerm)
				}
				if !reflect.DeepEqual(term.TerminalActions, head.terminals) {
					t.Errorf("compiled terminal-actions=%v, want %v", term.TerminalActions, head.terminals)
				}
			})
		}
	}
}

func thenLeafFixture11354(t *testing.T, thenBody string, grouped bool) *ConfigTree {
	t.Helper()
	term := "firewall { family inet { filter f11354 { term t1 { then " + thenBody + "; } } } }"
	text := "routing-instances { ri54 { instance-type forwarding; } }\n"
	if grouped {
		text += "groups { g { " + term + " } }\napply-groups [ g ];"
	} else {
		text += term
	}
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 || tree == nil {
		t.Fatalf("fixture parse errors = %v", errs)
	}
	return tree
}
