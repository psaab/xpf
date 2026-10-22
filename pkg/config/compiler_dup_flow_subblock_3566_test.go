package config

import (
	"strings"
	"testing"
)

// Tests for #3566: four strict-reject flow-trace / log-stream AST-walk
// validators iterated EVERY top-level `security` node (the #3562 fix) but then
// descended with a first-only FindChild at the SUB-level (flow / traceoptions /
// file), so an offending stanza placed in a SECOND duplicate flow {} /
// traceoptions {} / file / log {} sub-block within one security block bypassed
// the strict reject. parseStatements (parser.go) APPENDS a repeated block as a
// sibling at EVERY level — not just the top level — so the bypass is the
// sub-level sibling of the #3562 duplicate-top-level class. Each validator now
// descends with forEachChild at every container level it walks.
//
// This is reachable via the hierarchical LoadOverride path
// (configstore/store_command.go parses hierarchical input through NewParser),
// so these tests use NewParser — the CORRECT builder for the duplicate-block /
// LoadOverride path (flat-set SetPath would merge the sibling blocks).
//
// Each subtest puts a BENIGN first sub-block and the offending stanza in the
// SECOND duplicate sub-block. Reverting that validator's forEachChild descent
// at the duplicated level back to a first-only FindChild makes strict
// CompileConfig compile the config CLEAN → the assertion goes RED.

// countNamedChildren returns how many children of node have first key == name.
func countNamedChildren(node *Node, name string) int {
	var n int
	for _, c := range node.Children {
		if c.Name() == name {
			n++
		}
	}
	return n
}

// firstSecurity returns the first top-level security node (these configs use a
// single security block with duplicate SUB-blocks).
func firstSecurity(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	for _, c := range tree.Children {
		if c.Name() == "security" {
			return c
		}
	}
	t.Fatalf("no top-level security node")
	return nil
}

// --- validateFlowTraceFileAST (#3420 path-traversal gate) ---

// TestFlowTraceFilePathTraversalRejectedAcrossDuplicateSubBlocks proves the
// file gate descends flow > traceoptions > file with forEachChild at EVERY
// level: the offending non-basename `file` value hides in a duplicate flow /
// traceoptions / file sub-block whose first sibling is benign.
func TestFlowTraceFilePathTraversalRejectedAcrossDuplicateSubBlocks(t *testing.T) {
	cases := []struct {
		name    string
		cfg     string
		dupAt   string // container level whose forEachChild this subtest guards
		dupNode string // parent of the duplicated container
		want    string
	}{
		{
			name: "dup-flow",
			cfg: `
security {
    flow {
        traceoptions {
            file good.log;
        }
    }
    flow {
        traceoptions {
            file ../../tmp/rt-flow-leak;
        }
    }
}`,
			dupAt: "flow",
			want:  "../../tmp/rt-flow-leak",
		},
		{
			name: "dup-traceoptions",
			cfg: `
security {
    flow {
        traceoptions {
            file good.log;
        }
        traceoptions {
            file /tmp/rt-flow-leak;
        }
    }
}`,
			dupAt: "traceoptions",
			want:  "/tmp/rt-flow-leak",
		},
		{
			name: "dup-file",
			cfg: `
security {
    flow {
        traceoptions {
            file good.log;
            file sub/dir/rt-flow-leak;
        }
    }
}`,
			dupAt: "file",
			want:  "sub/dir/rt-flow-leak",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.cfg)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a non-basename flow-trace file in the SECOND duplicate %s sub-block; want a strict reject (#3566 sub-level bypass)", tc.dupAt)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "traceoptions") {
				t.Fatalf("reject error %q does not name the offending file value %q + traceoptions", err.Error(), tc.want)
			}
		})
	}
}

// --- validateFlowTraceFlagsAndFiltersAST (#3422 flag / filter gate) ---

// TestFlowTraceFlagRejectedAcrossDuplicateSubBlocks proves the flag/filter gate
// descends flow > traceoptions with forEachChild: the unknown `flag` hides in a
// duplicate flow / traceoptions sub-block whose first sibling carries only a
// supported flag.
func TestFlowTraceFlagRejectedAcrossDuplicateSubBlocks(t *testing.T) {
	cases := []struct {
		name  string
		cfg   string
		dupAt string
	}{
		{
			name: "dup-flow",
			cfg: `
security {
    flow {
        traceoptions {
            flag basic-datapath;
        }
    }
    flow {
        traceoptions {
            flag sesson;
        }
    }
}`,
			dupAt: "flow",
		},
		{
			name: "dup-traceoptions",
			cfg: `
security {
    flow {
        traceoptions {
            flag basic-datapath;
        }
        traceoptions {
            flag sesson;
        }
    }
}`,
			dupAt: "traceoptions",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.cfg)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted an unknown flow-trace flag in the SECOND duplicate %s sub-block; want a strict reject (#3566 sub-level bypass)", tc.dupAt)
			}
			if !strings.Contains(err.Error(), "sesson") || !strings.Contains(err.Error(), "unknown flow trace flag") {
				t.Fatalf("reject error %q does not name the unknown flag", err.Error())
			}
		})
	}
}

// --- validateFlowTraceSizeFilesAST (#3424 size/files range gate) ---

// TestFlowTraceSizeRejectedAcrossDuplicateSubBlocks proves the size/files gate
// descends flow > traceoptions > file with forEachChild: the out-of-range
// `size` hides in a duplicate flow / traceoptions / file sub-block whose first
// sibling is in range.
func TestFlowTraceSizeRejectedAcrossDuplicateSubBlocks(t *testing.T) {
	cases := []struct {
		name  string
		cfg   string
		dupAt string
	}{
		{
			name: "dup-flow",
			cfg: `
security {
    flow {
        traceoptions {
            file ok.log size 1048576 files 5;
        }
    }
    flow {
        traceoptions {
            file bad.log size 1 files 5;
        }
    }
}`,
			dupAt: "flow",
		},
		{
			name: "dup-traceoptions",
			cfg: `
security {
    flow {
        traceoptions {
            file ok.log size 1048576 files 5;
        }
        traceoptions {
            file bad.log size 1 files 5;
        }
    }
}`,
			dupAt: "traceoptions",
		},
		{
			name: "dup-file",
			cfg: `
security {
    flow {
        traceoptions {
            file ok.log size 1048576 files 5;
            file bad.log size 1 files 5;
        }
    }
}`,
			dupAt: "file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.cfg)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted an out-of-range trace file size in the SECOND duplicate %s sub-block; want a strict reject (#3566 sub-level bypass)", tc.dupAt)
			}
			if !strings.Contains(err.Error(), "invalid trace file size") || !strings.Contains(err.Error(), "traceoptions") {
				t.Fatalf("reject error %q does not name the out-of-range size + traceoptions", err.Error())
			}
		})
	}
}

// --- validateSecurityLogStreamTLSProfileAST (#3350 tls-profile gate) ---

// TestLogStreamTLSProfileRejectedAcrossDuplicateLogBlock proves the tls-profile
// gate descends security > log with forEachChild: the unapplied `tls-profile`
// stream hides in a SECOND duplicate `log {}` block whose first sibling carries
// only a plain `transport protocol tls` stream (a fully-honored config).
// Reverting forEachChild(security.Children, "log", ...) back to
// FindChild("log") makes strict CompileConfig see only the first log block and
// compile clean → this assertion goes RED.
func TestLogStreamTLSProfileRejectedAcrossDuplicateLogBlock(t *testing.T) {
	tree := parseHierText(t, `
security {
    log {
        stream plain {
            transport {
                protocol tls;
            }
        }
    }
    log {
        stream secure {
            transport {
                tls-profile pinned-ca;
            }
        }
    }
}`)
	if got := countNamedChildren(firstSecurity(t, tree), "log"); got < 2 {
		t.Fatalf("expected >=2 log sub-blocks (the #3566 sub-level bypass premise), got %d", got)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a tls-profile stream in the SECOND duplicate log block; want a strict reject (#3566 sub-level bypass)")
	}
	if !strings.Contains(err.Error(), "tls-profile") || !strings.Contains(err.Error(), "pinned-ca") {
		t.Fatalf("reject error %q does not name the unapplied tls-profile", err.Error())
	}
}
