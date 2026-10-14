package config

import (
	"reflect"
	"testing"
)

// #13009 (second half of #12888): the hierarchical parser keeps repeated
// blocks as separate siblings (it does not merge — same root cause as
// #4818/#4820/#4821), and compileSecurity calls compileFlow once per
// `security flow` stanza. Pre-fix compileFlow read tcp-session / aging /
// tcp-mss / traceoptions with a FIRST-ONLY FindChild and RECREATED
// TCPSession / Traceoptions per stanza:
//
//	stanza 1  tcp-session { initial-timeout 30 }  →  InitialTimeout=30
//	stanza 2  tcp-session { no-syn-check }        →  &TCPSessionConfig{} recreation
//	                                               →  InitialTimeout=0  (DROPPED)
//
// and stanza 2's traceoptions wholesale-replaced stanza 1's, discarding its
// flags and packet filters — while the #3566 strict gates validate EVERY
// sibling stanza, so the compiler and the gates read different configs.
func TestSecurityFlowSiblingStanzasMerge13009(t *testing.T) {
	compile := func(t *testing.T, text string) *FlowConfig {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse: %v", perrs)
		}
		c, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return &c.Security.Flow
	}

	// Two `security flow` sibling stanzas, each carrying half of every
	// container knob. Every value below must survive the merge.
	twoStanzas := compile(t, `
security {
    flow {
        tcp-session { initial-timeout 30; }
        aging { early-ageout 10; }
        tcp-mss { all-tcp 1350; }
        traceoptions { flag basic-datapath; packet-filter f1 { source-prefix 10.0.0.0/8; } }
    }
    flow {
        tcp-session { no-syn-check; }
        aging { high-watermark 80; }
        tcp-mss { gre-in 1400; }
        traceoptions { flag session; packet-filter f2 { protocol tcp; } }
    }
}
`)
	if ts := twoStanzas.TCPSession; ts == nil || ts.InitialTimeout != 30 || !ts.NoSynCheck {
		// RED on master: the second stanza's recreation wiped the first's
		// initial-timeout (#8971's half-open window bound).
		t.Fatalf("tcp-session must merge across stanzas, got %+v", twoStanzas.TCPSession)
	}
	if twoStanzas.AgingEarlyAgeout != 10 || twoStanzas.AgingHighWatermark != 80 {
		t.Fatalf("aging must merge across stanzas, got early=%d high=%d",
			twoStanzas.AgingEarlyAgeout, twoStanzas.AgingHighWatermark)
	}
	if twoStanzas.TCPMSSAllTCP != 1350 || twoStanzas.TCPMSSGreIn != 1400 {
		t.Fatalf("tcp-mss must merge across stanzas, got all-tcp=%d gre-in=%d",
			twoStanzas.TCPMSSAllTCP, twoStanzas.TCPMSSGreIn)
	}
	to := twoStanzas.Traceoptions
	if to == nil {
		t.Fatal("traceoptions missing entirely")
	}
	if !reflect.DeepEqual(to.Flags, []string{"basic-datapath", "session"}) {
		// RED on master: the second stanza's traceoptions wholesale-replaced
		// the first's, so only [session] survived.
		t.Fatalf("trace flags must accumulate across stanzas, got %v", to.Flags)
	}
	if len(to.PacketFilters) != 2 ||
		to.PacketFilters[0].Name != "f1" || to.PacketFilters[0].SourcePrefix != "10.0.0.0/8" ||
		to.PacketFilters[1].Name != "f2" || to.PacketFilters[1].Protocol != "tcp" {
		t.Fatalf("packet filters must accumulate across stanzas, got %+v", to.PacketFilters)
	}

	// CONTROL: the same knobs in ONE stanza compile to the same merged
	// picture — the merge must not invent or reorder anything.
	singleStanza := compile(t, `
security {
    flow {
        tcp-session { initial-timeout 30; no-syn-check; }
        aging { early-ageout 10; high-watermark 80; }
        tcp-mss { all-tcp 1350; gre-in 1400; }
        traceoptions { flag basic-datapath; flag session; packet-filter f1 { source-prefix 10.0.0.0/8; } packet-filter f2 { protocol tcp; } }
    }
}
`)
	if !reflect.DeepEqual(twoStanzas, singleStanza) {
		t.Fatalf("two sibling stanzas must equal the single-stanza spelling:\n%+v\n%+v",
			twoStanzas, singleStanza)
	}
}

// #13009, same mechanism one level down: repeated blocks INSIDE one
// `security flow` stanza. A first-only FindChild dropped every later
// tcp-session / tcp-mss / traceoptions block of the stanza.
func TestSecurityFlowDuplicateBlocksMerge13009(t *testing.T) {
	tree, perrs := NewParser(`
security {
    flow {
        tcp-session { initial-timeout 30; }
        tcp-session { no-syn-check; }
        tcp-mss { all-tcp 1350; }
        tcp-mss { gre-in 1400; }
        traceoptions { flag basic-datapath; }
        traceoptions { flag session; }
    }
}
`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	f := c.Security.Flow
	if ts := f.TCPSession; ts == nil || ts.InitialTimeout != 30 || !ts.NoSynCheck {
		t.Fatalf("duplicate tcp-session blocks must merge, got %+v", f.TCPSession)
	}
	if f.TCPMSSAllTCP != 1350 || f.TCPMSSGreIn != 1400 {
		t.Fatalf("duplicate tcp-mss blocks must merge, got all-tcp=%d gre-in=%d",
			f.TCPMSSAllTCP, f.TCPMSSGreIn)
	}
	if !reflect.DeepEqual(f.Traceoptions.Flags, []string{"basic-datapath", "session"}) {
		t.Fatalf("duplicate traceoptions blocks must accumulate flags, got %v",
			f.Traceoptions.Flags)
	}
}

// #13009 scalar doctrine: a value leaf set by two sibling stanzas keeps the
// LAST occurrence — exactly what the last stanza already produced pre-fix,
// so only the drop of the other stanza's distinct values is new behavior.
func TestSecurityFlowSiblingScalarLastWins13009(t *testing.T) {
	tree, perrs := NewParser(`
security {
    flow { aging { early-ageout 10; } }
    flow { aging { early-ageout 20; } }
}
`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := c.Security.Flow.AgingEarlyAgeout; got != 20 {
		t.Fatalf("conflicting scalar must keep the last occurrence, got %d", got)
	}
}

// #13009 traceoptions file merge: a later stanza may rename the file while
// an earlier stanza's rotation bounds survive (each block contributes what
// it carries); the whole merged picture must survive the strict commit gate.
func TestSecurityFlowSiblingTraceFileMerge13009(t *testing.T) {
	tree, perrs := NewParser(`
security {
    flow { traceoptions { file trace1 size 10240 files 3; } }
    flow { traceoptions { file trace2; } }
}
`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	to := c.Security.Flow.Traceoptions
	if to == nil || to.File != "trace2" || to.FileSize != 10240 || to.FileCount != 3 {
		t.Fatalf("file must rename while size/files persist, got %+v", to)
	}
}
