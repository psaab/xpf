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
	Name        string
	Lenient     bool // compile with CompileConfigLenient (#17077 quarantine shapes)
	FeedOverlay map[string][]string
	SetLines    []string
	Queries     []policyCorpusQuery9167
	Line        int
}

type policyCorpusQuery9167 struct {
	From, To   string
	Src, Dst   string
	Protocol   string  // "-" encodes an omitted protocol selector (#17077)
	SrcPort    *uint16 // nil encodes an omitted (`-`) port selector (#17077)
	DstPort    *uint16 // nil encodes an omitted (`-`) port selector (#17077)
	ICMPType   *uint8  // from `icmp=T[/C]`; nil = type not carried by the packet
	ICMPCode   *uint8
	WantAction string // permit | deny | reject | content-rejected
	WantPolicy string // policy name, or "-" for the default verdict
	Frag       bool   // non-first fragment: Query.NonFirstFragment
	Line       int
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
			rest := strings.TrimSpace(line[5:])
			name := rest
			lenient := false
			if f := strings.Fields(rest); len(f) == 2 && f[1] == "lenient" {
				name, lenient = f[0], true
			} else if len(f) != 1 {
				t.Fatalf("%s:%d: bad case header %q (want `case <name> [lenient]`)", path, ln, line)
			}
			cur = &policyCorpusCase9167{Name: name, Lenient: lenient, Line: ln}
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
		case strings.HasPrefix(line, "feed "):
			if cur == nil {
				t.Fatalf("%s:%d: `feed` outside a case", path, ln)
			}
			rest := strings.TrimSpace(line[5:])
			name, rhs, ok := strings.Cut(rest, "=")
			if !ok || name == "" {
				t.Fatalf("%s:%d: bad feed line %q (want feed <name>=<cidr>[,...])", path, ln, line)
			}
			if cur.FeedOverlay == nil {
				cur.FeedOverlay = map[string][]string{}
			}
			var prefixes []string
			if rhs != "" {
				prefixes = strings.Split(rhs, ",")
			}
			cur.FeedOverlay[name] = prefixes
		case strings.HasPrefix(line, "q "):
			if cur == nil {
				t.Fatalf("%s:%d: `q` outside a case", path, ln)
			}
			fields := strings.Fields(line[2:])
			if len(fields) < 9 {
				t.Fatalf("%s:%d: a query needs at least 9 fields "+
					"(from to src dst proto sport dport action policy [frag|icmp=T[/C]]...), got %d: %q",
					path, ln, len(fields), line)
			}
			q := policyCorpusQuery9167{
				From: fields[0], To: fields[1], Src: fields[2], Dst: fields[3],
				Protocol: fields[4], WantAction: fields[7], WantPolicy: fields[8], Line: ln,
			}
			if fields[4] == "-" {
				q.Protocol = ""
				if fields[8] != "-" {
					t.Fatalf("%s:%d: a `-` protocol row must expect the default verdict (policy `-`) — an underspecified tuple cannot vouch for a named policy on the Rust surface (see corpus header)", path, ln)
				}
			}
			for _, sel := range []struct {
				tok string
				dst **uint16
			}{{fields[5], &q.SrcPort}, {fields[6], &q.DstPort}} {
				if sel.tok == "-" {
					continue
				}
				n, err := strconv.Atoi(sel.tok)
				if err != nil || n < 0 || n > 65535 {
					t.Fatalf("%s:%d: bad port %q", path, ln, sel.tok)
				}
				*sel.dst = PortPtr(uint16(n))
			}
			switch fields[7] {
			case "permit", "deny", "reject", "content-rejected":
			default:
				t.Fatalf("%s:%d: unknown expected action %q (want permit|deny|reject|content-rejected)",
					path, ln, fields[7])
			}
			if q.WantAction == "content-rejected" && q.WantPolicy != "-" {
				t.Fatalf("%s:%d: a content-rejected row asserts no matched policy; policy must be `-`", path, ln)
			}
			for _, tok := range fields[9:] {
				switch {
				case tok == "frag":
					if q.Frag {
						t.Fatalf("%s:%d: duplicate `frag` token", path, ln)
					}
					q.Frag = true
				case strings.HasPrefix(tok, "icmp="):
					if q.ICMPType != nil {
						t.Fatalf("%s:%d: duplicate `icmp=` token", path, ln)
					}
					ts, cs, hasCode := strings.Cut(tok[5:], "/")
					tv, err := ParseICMPValue(ts)
					if err != nil {
						t.Fatalf("%s:%d: bad icmp type in %q: %v", path, ln, tok, err)
					}
					q.ICMPType = tv
					if hasCode {
						cv, err := ParseICMPValue(cs)
						if err != nil {
							t.Fatalf("%s:%d: bad icmp code in %q: %v", path, ln, tok, err)
						}
						q.ICMPCode = cv
					}
				default:
					t.Fatalf("%s:%d: unknown query token %q (want frag or icmp=T[/C])", path, ln, tok)
				}
			}
			cur.Queries = append(cur.Queries, q)
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
	// STRICT by default: a corpus case is a config an operator could commit.
	// A `lenient` case (#17077: ZoneID-collision quarantine) compiles with
	// CompileConfigLenient; its generator snapshot is the post-quarantine one
	// the dataplane actually receives, so both halves assert that posture
	// rather than the strict-commit refusal.
	compile := config.CompileConfig
	if c.Lenient {
		compile = config.CompileConfigLenient
	}
	cfg, err := compile(tr)
	if err != nil {
		t.Fatalf("case %q (corpus line %d): the config does not compile (lenient=%v): %v",
			c.Name, c.Line, c.Lenient, err)
	}
	return cfg
}

// policyCorpusPort9167 renders a corpus port for failure messages: `-` is the
// omitted selector (nil), never a numeric port.
func policyCorpusPort9167(p *uint16) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *p)
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
					SrcFamily: config.NATAddrFamily(q.Src), DstFamily: config.NATAddrFamily(q.Dst),
					Protocol: q.Protocol, SrcPort: q.SrcPort, DstPort: q.DstPort,
					ICMPType: q.ICMPType, ICMPCode: q.ICMPCode,
					NonFirstFragment: q.Frag,
					FeedOverlay:      c.FeedOverlay,
				})
				if q.WantAction == "content-rejected" {
					if !res.ContentRejected {
						t.Errorf("corpus line %d: %s want content-rejected, Go simulator: %s %s (ContentRejected=false)",
							q.Line, c.Name, policyActionName9167(res.Action), res.PolicyName)
					}
					continue
				}
				if res.ContentRejected {
					t.Errorf("corpus line %d: the config was CONTENT-REJECTED (%v) but the row wants %s %s",
						q.Line, res.ContentRejectionReasons, q.WantAction, q.WantPolicy)
					continue
				}
				if res.V4MappedCompatIngressDrop {
					if c.Name != "embedded-v4-ipv6-policy-family-10686" {
						t.Errorf("corpus line %d: unexpected ingress-drop verdict outside the #10686 case", q.Line)
					}
					continue
				}
				gotAction := policyActionName9167(res.Action)
				gotPolicy := res.PolicyName
				if !res.Matched {
					gotPolicy = "-"
				}
				if gotAction != q.WantAction || gotPolicy != q.WantPolicy {
					t.Errorf("corpus line %d: %s %s->%s %s %s:%s->%s:%s\n"+
						"  Go simulator: %s %s\n  corpus       : %s %s\n"+
						"The corpus expectation is authored from the Junos semantics and is "+
						"produced by neither implementation, so a disagreement here is a "+
						"defect in pkg/policymatch (or in the expectation, which is reviewed "+
						"as part of changing it).",
						q.Line, c.Name, q.From, q.To, q.Protocol, q.Src, policyCorpusPort9167(q.SrcPort), q.Dst, policyCorpusPort9167(q.DstPort),
						gotAction, gotPolicy, q.WantAction, q.WantPolicy)
				}
			}
		})
	}
}

// TestPolicyVerdictCorpusPinsIcmpUnknownCase10511 pins the #10511 row by NAME:
// the count floors admit silent deletion of any single case (15 cases stay
// above the 8-case floor), so without this the icmp-unknown coverage could be
// removed with both halves green. The Rust half carries the mirror pin;
// symmetric removal reds both.
func TestPolicyVerdictCorpusPinsIcmpUnknownCase10511(t *testing.T) {
	cases := parsePolicyCorpus9167(t, policyCorpusPath9167)
	for _, c := range cases {
		if c.Name != "icmp-unknown-application" {
			continue
		}
		if len(c.Queries) < 2 {
			t.Fatalf("icmp-unknown-application carries %d queries, want at least "+
				"the permit + unknown-application rows", len(c.Queries))
		}
		return
	}
	t.Fatalf("corpus case `icmp-unknown-application` is missing (%d cases present); "+
		"the #10511 icmp-unknown coverage was removed", len(cases))
}

// TestPolicyVerdictCorpusPinsEmbeddedV4IPv6Case10686 makes the mapped/compatible
// policy-core rows non-optional even while the corpus remains above its global
// count floors. The Rust half carries the mirror pin.
func TestPolicyVerdictCorpusPinsEmbeddedV4IPv6Case10686(t *testing.T) {
	cases := parsePolicyCorpus9167(t, policyCorpusPath9167)
	for _, c := range cases {
		if c.Name != "embedded-v4-ipv6-policy-family-10686" {
			continue
		}
		if len(c.Queries) != 5 {
			t.Fatalf("embedded-v4-ipv6-policy-family-10686 carries %d queries, want 5",
				len(c.Queries))
		}
		return
	}
	t.Fatalf("corpus case embedded-v4-ipv6-policy-family-10686 is missing (%d cases present)",
		len(cases))
}

// TestPolicyVerdictCorpusPins17077Cases pins every #17077 case by NAME: the
// count floors admit silent deletion of any single case, so without this the
// new grammar dimensions could be removed with both halves green. The Rust
// half carries the mirror pin; symmetric removal reds both.
func TestPolicyVerdictCorpusPins17077Cases(t *testing.T) {
	want := map[string]int{
		"transit-fragment-reject-13705":        2,
		"unknown-zone-egress-11067":            1,
		"unknown-zone-ingress-8318":            1,
		"unknown-zone-junos-host-global-11369": 2,
		"unknown-zone-junos-host-global-only-11369": 2,
		"icmp-type-code":                       3,
		"omitted-selectors":                    3,
		"feed-overlay-12965":                   2,
		"lenient-quarantine-5649":              2,
		"content-rejected-3727":                1,
	}
	cases := parsePolicyCorpus9167(t, policyCorpusPath9167)
	seen := map[string]int{}
	for _, c := range cases {
		if _, ok := want[c.Name]; ok {
			seen[c.Name] = len(c.Queries)
		}
	}
	for name, queries := range want {
		got, ok := seen[name]
		if !ok {
			t.Errorf("corpus case %q is missing (%d cases present); the #17077 coverage was removed", name, len(cases))
			continue
		}
		if got < queries {
			t.Errorf("corpus case %q carries %d queries, want at least %d", name, got, queries)
		}
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
