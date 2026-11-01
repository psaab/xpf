package config

import (
	"reflect"
	"sort"
	"testing"
)

// #18762: every leaf of `security flow tcp-session`, ENUMERATED FROM THE
// SCHEMA so a leaf added later cannot escape, must compile to the same
// TCPSession whether it is written braced, with tcp-session elided
// (`tcp-session leaf v;`), or with flow elided too (`flow tcp-session leaf
// v;`). For the time-wait-state children the container is one level deeper,
// so they are also written with time-wait-state packed onto tcp-session
// (`tcp-session time-wait-state child v;`).
//
// strict-syn-check, rst-sequence-check, maximum-window and time-wait-state
// each committed clean in an elided spelling while compiling to the zero
// value: a security or session-handling knob silently absent.
func TestTCPSessionEveryLeafEverySpelling18762(t *testing.T) {
	ts := setSchema.children["security"].children["flow"].children["tcp-session"]
	if ts == nil || len(ts.children) < 10 {
		t.Fatalf("schema walk: security flow tcp-session has %v children; the enumeration source is broken", ts)
	}
	type row struct{ name, braced, elided, twoLevel string }
	var rows []row
	val := func(n *schemaNode) (string, bool) {
		if n.args == 0 {
			return "", true
		}
		if len(n.valueExamples) == 0 {
			return "", false
		}
		return " " + n.valueExamples[0], true
	}
	names := make([]string, 0, len(ts.children))
	for name := range ts.children {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		n := ts.children[name]
		if len(n.children) > 0 { // time-wait-state: walk its children
			kids := make([]string, 0, len(n.children))
			for k := range n.children {
				kids = append(kids, k)
			}
			sort.Strings(kids)
			for _, k := range kids {
				v, ok := val(n.children[k])
				if !ok {
					t.Errorf("tcp-session %s %s has no valueExamples; add one so this cell covers it", name, k)
					continue
				}
				rows = append(rows, row{
					name:     name + " " + k,
					braced:   `security { flow { tcp-session { ` + name + ` { ` + k + v + `; } } } }`,
					elided:   `security { flow { tcp-session { ` + name + ` ` + k + v + `; } } }`,
					twoLevel: `security { flow { tcp-session ` + name + ` ` + k + v + `; } }`,
				})
			}
			continue
		}
		v, ok := val(n)
		if !ok {
			t.Errorf("tcp-session %s has no valueExamples; add one so this cell covers it", name)
			continue
		}
		rows = append(rows, row{
			name:     name,
			braced:   `security { flow { tcp-session { ` + name + v + `; } } }`,
			elided:   `security { flow { tcp-session ` + name + v + `; } }`,
			twoLevel: `security { flow tcp-session ` + name + v + `; }`,
		})
	}
	empty := compileText(t, `security { flow { } }`)
	if empty == nil {
		t.Fatal("empty flow stanza did not compile")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			b := compileText(t, r.braced)
			if b == nil {
				t.Fatalf("braced spelling did not compile: %s", r.braced)
			}
			if reflect.DeepEqual(b.Security.Flow.TCPSession, empty.Security.Flow.TCPSession) {
				t.Fatalf("POSITIVE CONTROL: the braced spelling compiles to the same TCPSession as an empty stanza, so this row cannot observe a drop: %s", r.braced)
			}
			for spelling, text := range map[string]string{"elided": r.elided, "two-level": r.twoLevel} {
				c := compileText(t, text)
				if c == nil {
					t.Errorf("%s spelling did not compile: %s", spelling, text)
					continue
				}
				if !reflect.DeepEqual(b.Security.Flow.TCPSession, c.Security.Flow.TCPSession) {
					t.Errorf("%s spelling compiled a different TCPSession than braced (value dropped):\n  braced: %s -> %+v\n  %s: %s -> %+v",
						spelling, r.braced, b.Security.Flow.TCPSession, spelling, text, c.Security.Flow.TCPSession)
				}
			}
		})
	}
}
