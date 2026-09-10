package policymatch

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9167 — the Go half of the shared policy-verdict corpus differential.
//
// See testdata/policy_verdict_corpus.txt for what the file is and why. The short
// version: `show security match-policies` had no independent oracle, and the
// hand-written mirror of policy.rs's tier walk drifted for 71 commits when #6505
// changed the Rust side and touched no Go at all.
//
// THIS FILE AND userspace-dp/src/policy_verdict_corpus_9167.rs READ THE SAME
// FILE. Neither language calls the other; each drives its own implementation and
// compares to the corpus's authored expectation. A row only one side knows about
// cannot exist.

const policyCorpusPath9167 = "../../testdata/policy_verdict_corpus.txt"

// PolicyCorpusCase is one corpus case: a config and the tuples asserted against
// it. Exported-shaped fields keep the generator in pkg/dataplane/userspace able
// to reuse this reader through the shared parser below.
type policyCorpusCase9167 struct {
	Name     string
	SetLines []string
	Queries  []policyCorpusQuery9167
	Line     int
}

type policyCorpusQuery9167 struct {
	From, To         string
	Src, Dst         string
	Protocol         string
	SrcPort, DstPort int
	WantAction       string // permit | deny | reject
	WantPolicy       string // policy name, or "-" for the default verdict
	Frag             bool   // non-first fragment: Query.NonFirstFragment
	Line             int
}

// parsePolicyCorpus9167 is the ONE reader. Both languages have their own
// (the Rust side re-implements it over the same grammar), but within Go the
// simulator test and the snapshot generator share this one so a corpus the
// generator understood and the asserter did not cannot exist.
func parsePolicyCorpus9167(t *testing.T, path string) []policyCorpusCase9167 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("#9167: the shared corpus is unreadable at %s: %v", path, err)
	}
	defer f.Close()

	var out []policyCorpusCase9167
	var cur *policyCorpusCase9167
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "case "):
			if cur != nil {
				t.Fatalf("%s:%d: `case` inside an unterminated case %q", path, ln, cur.Name)
			}
			cur = &policyCorpusCase9167{Name: strings.TrimSpace(line[5:]), Line: ln}
		case line == "end":
			if cur == nil {
				t.Fatalf("%s:%d: `end` with no open case", path, ln)
			}
			if len(cur.Queries) == 0 {
				t.Fatalf("%s:%d: case %q has NO queries — a case that asserts nothing "+
					"inflates the corpus without measuring anything", path, ln, cur.Name)
			}
			out = append(out, *cur)
			cur = nil
		case strings.HasPrefix(line, "set "):
			if cur == nil {
				t.Fatalf("%s:%d: `set` outside a case", path, ln)
			}
			cur.SetLines = append(cur.SetLines, line)
		case strings.HasPrefix(line, "q "):
			if cur == nil {
				t.Fatalf("%s:%d: `q` outside a case", path, ln)
			}
			fields := strings.Fields(line[2:])
			if len(fields) != 9 && !(len(fields) == 10 && fields[9] == "frag") {
				t.Fatalf("%s:%d: a query needs 9 fields "+
					"(from to src dst proto sport dport action policy [frag]), got %d: %q",
					path, ln, len(fields), line)
			}
			sp, err := strconv.Atoi(fields[5])
			if err != nil {
				t.Fatalf("%s:%d: bad source port %q", path, ln, fields[5])
			}
			dp, err := strconv.Atoi(fields[6])
			if err != nil {
				t.Fatalf("%s:%d: bad dest port %q", path, ln, fields[6])
			}
			switch fields[7] {
			case "permit", "deny", "reject":
			default:
				t.Fatalf("%s:%d: unknown expected action %q (want permit|deny|reject)",
					path, ln, fields[7])
			}
			cur.Queries = append(cur.Queries, policyCorpusQuery9167{
				From: fields[0], To: fields[1], Src: fields[2], Dst: fields[3],
				Protocol: fields[4], SrcPort: sp, DstPort: dp,
				WantAction: fields[7], WantPolicy: fields[8], Frag: len(fields) == 10, Line: ln,
			})
		default:
			t.Fatalf("%s:%d: unrecognized corpus line %q", path, ln, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("#9167: reading %s: %v", path, err)
	}
	if cur != nil {
		t.Fatalf("%s: case %q is never terminated by `end`", path, cur.Name)
	}
	return out
}

func policyCorpusConfig9167(t *testing.T, c policyCorpusCase9167) *config.Config {
	t.Helper()
	tr := &config.ConfigTree{}
	for _, l := range c.SetLines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("case %q: parse %q: %v", c.Name, l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("case %q: setpath %q: %v", c.Name, l, err)
		}
	}
	// The STRICT compiler, deliberately: a corpus case is a config an operator
	// could commit. A case that only compiles leniently would be asserting the
	// tolerant ingress path, which is #9410's subject and a different question.
	cfg, err := config.CompileConfig(tr)
	if err != nil {
		t.Fatalf("case %q (corpus line %d): the config does not COMMIT: %v\n"+
			"Every corpus case must be operator-committable; if this case is meant to "+
			"exercise the tolerant path it belongs in #9410's cells, not here.",
			c.Name, c.Line, err)
	}
	return cfg
}

// TestPolicyVerdictCorpusGoHalf9167 drives pkg/policymatch over the shared
// corpus.
//
// THE CORPUS IS ALSO ASSERTED TO BE NON-TRIVIAL. A differential whose corpus
// emptied would pass in both languages and report nothing, which is the shape
// this issue is about one layer up — so the case and query counts are floored.
func TestPolicyVerdictCorpusGoHalf9167(t *testing.T) {
	cases := parsePolicyCorpus9167(t, policyCorpusPath9167)
	queries := 0
	for _, c := range cases {
		queries += len(c.Queries)
	}
	if len(cases) < 8 || queries < 15 {
		t.Fatalf("#9167: the corpus collapsed to %d case(s) / %d query(ies). A differential "+
			"whose corpus emptied passes in BOTH languages and reports nothing — exactly "+
			"the vacuity this issue exists to remove.", len(cases), queries)
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			cfg := policyCorpusConfig9167(t, c)
			for _, q := range c.Queries {
				res := Match(cfg, Query{
					FromZone: q.From, ToZone: q.To,
					SrcIP: net.ParseIP(q.Src), DstIP: net.ParseIP(q.Dst),
					Protocol: q.Protocol, SrcPort: q.SrcPort, DstPort: q.DstPort,
					NonFirstFragment: q.Frag,
				})
				gotAction := policyActionName9167(res.Action)
				gotPolicy := res.PolicyName
				if !res.Matched {
					gotPolicy = "-"
				}
				if res.ContentRejected {
					t.Errorf("corpus line %d: the config was CONTENT-REJECTED (%v). A corpus "+
						"case must be one the dataplane can represent, or the row asserts "+
						"nothing about the tier walk.", q.Line, res.ContentRejectionReasons)
					continue
				}
				if gotAction != q.WantAction || gotPolicy != q.WantPolicy {
					t.Errorf("corpus line %d: %s %s->%s %s %s:%d->%s:%d\n"+
						"  Go simulator: %s %s\n  corpus       : %s %s\n"+
						"The corpus expectation is authored from the Junos semantics and is "+
						"produced by neither implementation, so a disagreement here is a "+
						"defect in pkg/policymatch (or in the expectation, which is reviewed "+
						"as part of changing it).",
						q.Line, c.Name, q.From, q.To, q.Protocol, q.Src, q.SrcPort, q.Dst, q.DstPort,
						gotAction, gotPolicy, q.WantAction, q.WantPolicy)
				}
			}
		})
	}
}

func policyActionName9167(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return fmt.Sprintf("action(%d)", int(a))
	}
}
