package daemon

// daemon_nft_netlink_parity_test.go is the #6387 PR-2 T1 ruleset-parity CI — the
// SECURITY MERGE GATE. It proves the additive pkg/nftables netlink installer is
// bit-for-bit equivalent to the CURRENT exec-`nft` payload builders in
// daemon_nft.go (the ORACLE) for a construct-complete matrix (§9 / §12.1):
//
//   render the oracle `nft -f -` text, load it into a fresh netns, dump
//   `nft list table`; install the NETLINK ruleset into the same fresh netns,
//   dump again; normalize (strip handles, sort set elements — but NEVER reorder
//   rules within a chain) and DIFF. Any diff fails the build.
//
// Because a dropped/widened/weakened rule is a host-inbound fail-open on the
// PRIMARY host path, this gate MUST run (not silently SKIP) wherever `nft` + a
// private netns are available. It self-isolates by re-executing under
// `unshare -rn`, so the forked `nft` and the Go netlink install share ONE
// private network namespace and the host ruleset is never touched. When `nft`
// or `unshare` is absent it SKIPs with an explicit logged reason (memory rule:
// no silent caps) — the parent runs it where `nft` exists.
//
// The converter below (daemon dpuserspace views/programs/terms -> pkg/nftables
// spec) is the field-copy PR-3 will promote to production; here it is test-only.

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

const t1InnerEnv = "XPF_T1_PARITY_INNER"

// TestNftNetlinkParity is the T1 gate. The OUTER invocation re-execs the test
// binary under `unshare -rn` (a private netns) so nft + netlink share one
// namespace; the INNER invocation runs the actual oracle-vs-netlink diffs.
func TestNftNetlinkParity(t *testing.T) {
	if os.Getenv(t1InnerEnv) == "1" {
		runNftNetlinkParityInner(t)
		return
	}
	// #6613: use findNft, not a bare LookPath — nft ships in /usr/sbin on this
	// distro and a non-root PATH omits it, so the bare lookup made THE SECURITY
	// MERGE GATE silently SKIP while still reporting a green `make test`.
	if findNft() == "" {
		t.Skip("T1 ruleset-parity gate SKIPPED: `nft` binary not found in PATH — " +
			"this gate MUST run where nft exists (the parent runs it); it proves the " +
			"netlink installer is bit-equivalent to the exec-nft oracle")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("T1 ruleset-parity gate SKIPPED: `unshare` not found — cannot self-isolate a private netns")
	}
	// Re-exec ONLY this test inside a fresh netns so a forked `nft` shares it and
	// the host ruleset is never touched.
	args := []string{"-rn", os.Args[0], "-test.run", "^TestNftNetlinkParity$", "-test.v"}
	cmd := exec.Command(unshare, args...)
	cmd.Env = append(os.Environ(), t1InnerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("inner T1 output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "unshare:") {
			t.Skipf("T1 gate SKIPPED: cannot create private netns under unshare (%v) — run as root or with CAP_NET_ADMIN", err)
		}
		t.Fatalf("T1 ruleset-parity gate FAILED (netlink build diverged from the exec-nft oracle): %v", err)
	}
}

func runNftNetlinkParityInner(t *testing.T) {
	inst := xnft.NewNetlinkInstaller()
	views, unzonedV4, unzonedV6, programs, wg := parityHostInboundInputs()

	t.Run("host_inbound", func(t *testing.T) {
		oracle := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, programs, wg)
		spec := toNftHostInboundSpec(views, unzonedV4, unzonedV6, programs, wg)
		// parityCheck compares the nft-text dump AND the PER-RULE iifname scope
		// (read byte-for-byte via netlink, since google/nftables v0.3.0 renders
		// anonymous string-set elements empty in `nft list`, so the TEXT cannot
		// carry the iifname scope). The per-rule comparison — not a global union —
		// is what catches a scope move/widen between the narrow IKE/ident exemption
		// and the broad zone deny (#6405 FIX-2).
		parityCheck(t, xnft.HostInboundTableName, oracle, func() error { return inst.InstallHostInbound(spec) })
	})

	t.Run("cold_boot_fence", func(t *testing.T) {
		oracle := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, wg)
		spec := xnft.FenceSpec{Views: toNftViews(views), UnzonedV4: unzonedV4, UnzonedV6: unzonedV6, WGListenPorts: wg}
		parityCheck(t, xnft.HostInboundTableName, oracle, func() error { return inst.InstallColdBootFence(spec) })
	})

	t.Run("lo0_cold_boot_fence", func(t *testing.T) {
		// #6476: the lo0 cold-boot fence is the SAME fence body as the host-inbound
		// fence but in the xpf_lo0 table at priority 0. It shares FenceSpec /
		// buildFenceTablePayload with cold_boot_fence, so this case proves the
		// xpf_lo0 table wrapper (name + priority) composes with the shared fence
		// rules bit-identically to the netlink InstallLo0ColdBootFence.
		oracle := buildLo0FencePayload(views, unzonedV4, unzonedV6, wg)
		spec := xnft.FenceSpec{Views: toNftViews(views), UnzonedV4: unzonedV4, UnzonedV6: unzonedV6, WGListenPorts: wg}
		parityCheck(t, xnft.Lo0TableName, oracle, func() error { return inst.InstallLo0ColdBootFence(spec) })
	})

	t.Run("gap_fence", func(t *testing.T) {
		uncoveredV4 := []string{"10.0.1.1", "10.0.9.1"}
		uncoveredV6 := []string{"2001:db8:1::1"}
		oracle := buildHostInboundGapFencePayload(uncoveredV4, uncoveredV6, wg)
		spec := xnft.GapFenceSpec{UncoveredV4: uncoveredV4, UncoveredV6: uncoveredV6, WGListenPorts: wg}
		parityCheck(t, xnft.HostInboundGapTableName, oracle, func() error { return inst.InstallGapFence(spec) })
	})

	t.Run("lo0_filter", func(t *testing.T) {
		cfg := parityLo0Config()
		oracle := buildLo0FilterPayload(cfg, "lo0f", "lo0f6")
		spec := toNftLo0Spec(cfg, "lo0f", "lo0f6")
		parityCheck(t, xnft.Lo0TableName, oracle, func() error { _, err := inst.InstallLo0(spec); return err })
	})

	// #6804: the flexible-match-range predicate. Before the fix NEITHER renderer
	// carried it — the lo0 netlink spec had no field for it at all — so the term
	// rendered WITHOUT its narrowing on the chain that is the PRIMARY
	// enforcement for host traffic. This case is what makes the two renderers'
	// agreement real rather than asserted: both go through the actual `nft`
	// parser and the actual netlink install, and the installed rulesets are
	// diffed.
	//
	// The widths are chosen to exercise the parts most likely to diverge: a
	// sub-byte bit length (12 -> a 2-byte load narrowed by the mask), a
	// byte-aligned one, and a full 32-bit one.
	t.Run("lo0_flexible_match_range", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			fm   config.FlexMatchConfig
		}{
			{"sub-byte-12-bits", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 6, BitLength: 12, Value: 0x0abc, Mask: 0x0fff}},
			{"byte-aligned-8-bits", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0x11, Mask: 0xff}},
			{"full-32-bits", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 12, BitLength: 32, Value: 0x0a000001, Mask: 0xffffffff}},
			// Zero bit-length: the userspace snapshot builder DEFAULTS it to 4
			// (32-bit). Without this row, an implementation that treated 0 as
			// "no constraint" would render the term with no narrowing at all —
			// the exact widening this issue is about — and every other row would
			// still pass.
			{"zero-bit-length-defaults-to-32", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 12, BitLength: 0, Value: 0x0a000001, Mask: 0xffffffff}},
			// Value carrying bits OUTSIDE the mask. Every row above has the
			// value already inside its mask, so pre-masking is a NO-OP on both
			// sides and a renderer that skipped it would still agree — the
			// fixture varies the right axis but samples only the point where it
			// cannot fail. nft compares the MASKED load, so an unmasked expected
			// value never matches: a silent never-match, which is a different
			// fail direction from the widening but just as quiet.
			{"value-outside-mask-is-pre-masked", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0xff11, Mask: 0x0f}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fm := tc.fm
				cfg := &config.Config{}
				cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
					"flexf": {Terms: []*config.FirewallFilterTerm{
						{Name: "flex", Protocols: []string{"tcp"}, FlexMatch: &fm, Action: "accept"},
						{Name: "deny-rest", Action: "discard"},
					}},
				}
				nftDeleteTableBestEffort(xnft.Lo0TableName)
				oracle := buildLo0FilterPayload(cfg, "flexf", "")
				// Guard the fixture's own premise: an oracle that omitted the
				// predicate would make the diff below pass for the wrong reason.
				if !strings.Contains(oracle, "@nh,") {
					t.Fatalf("the oracle emitted no raw-payload match, so this "+
						"cell cannot detect a dropped predicate:\n%s", oracle)
				}
				spec := toNftLo0Spec(cfg, "flexf", "")
				parityCheck(t, xnft.Lo0TableName, oracle, func() error { _, err := inst.InstallLo0(spec); return err })
			})
		}
	})

	// #6804: an unrepresentable flexible-match-range must make the term match
	// NOTHING on BOTH sides — mirroring the userspace fail-closed, where the
	// term is poisoned to FlexMatchStart::Unsupported and later terms still run.
	// A drop would be wrong: a flex-match has no natural narrowing like
	// tcp-flags' `meta l4proto 6`, so a term whose only predicate was the
	// flex-match would deny ALL host-inbound traffic.
	t.Run("lo0_unrepresentable_flex_match_matches_nothing", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			term *config.FirewallFilterTerm
		}{
			{
				// #5823: more than one named range.
				name: "multi-range",
				term: &config.FirewallFilterTerm{
					Name:                "multi-range",
					Protocols:           []string{"tcp"},
					FlexMatchRangeNames: []string{"r1", "r2"},
					FlexMatch:           &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 6, BitLength: 8, Value: 1, Mask: 0xff},
					Action:              "accept",
				},
			},
			{
				// An unparseable numeric token: strict commit rejects it, the
				// tolerant load only warns (#1960), so it reaches the mirror.
				name: "unknown-token",
				term: &config.FirewallFilterTerm{
					Name:             "unknown-token",
					Protocols:        []string{"tcp"},
					UnknownFlexMatch: []string{"byte-offset=not-a-number"},
					FlexMatch:        &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 6, BitLength: 8, Value: 1, Mask: 0xff},
					Action:           "accept",
				},
			},
			{
				// Width OUTSIDE 1..4 bytes. The commit gate bounds bit-length to
				// 1..32, so 40 bits arrives only on a corrupt / version-drifted
				// tolerant-load snapshot — and CAPPING it to 4 would compare only
				// the truncated window and BROADEN the match (the #3406
				// fail-open), so it must be unrepresentable, not clamped.
				name: "oversized-width",
				term: &config.FirewallFilterTerm{
					Name:      "oversized-width",
					Protocols: []string{"tcp"},
					FlexMatch: &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 6, BitLength: 40, Value: 1, Mask: 0xff},
					Action:    "accept",
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
					"flexbad": {Terms: []*config.FirewallFilterTerm{
						tc.term,
						{Name: "deny-rest", Action: "discard"},
					}},
				}
				nftDeleteTableBestEffort(xnft.Lo0TableName)
				oracle := buildLo0FilterPayload(cfg, "flexbad", "")
				if strings.Contains(oracle, "@nh,") {
					t.Fatalf("an UNREPRESENTABLE flex-match still rendered a "+
						"payload match:\n%s", oracle)
				}
				// The later term must survive: "matches nothing" means the term
				// contributes no enforcement, NOT that the filter is emptied.
				if !strings.Contains(oracle, "drop") {
					t.Fatalf("the following deny term did not render, so the "+
						"unrepresentable term swallowed the rest of the "+
						"filter:\n%s", oracle)
				}
				spec := toNftLo0Spec(cfg, "flexbad", "")
				parityCheck(t, xnft.Lo0TableName, oracle, func() error { _, err := inst.InstallLo0(spec); return err })
			})
		}
	})

	t.Run("lo0_unrepresentable_port_fails_closed", func(t *testing.T) {
		// #6405 FIX-1: a port token nft cannot resolve (not numeric, not a service
		// name). BOTH sides must FAIL CLOSED: the oracle emits the raw token and
		// `nft -f -` REJECTS the whole ruleset (prior ruleset retained); the netlink
		// build must likewise error (InstallLo0 != nil) and leave NO partial table —
		// never drop the predicate and widen the accept to match-all.
		badCfg := &config.Config{}
		badCfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			"badf": {Terms: []*config.FirewallFilterTerm{
				{Name: "bad-port", Protocols: []string{"tcp"}, DestinationPorts: []string{"definitely-not-a-service"}, Action: "accept"},
			}},
		}
		nftDeleteTableBestEffort(xnft.Lo0TableName)

		// Oracle side: nft must REJECT the unresolvable token.
		oracle := buildLo0FilterPayload(badCfg, "badf", "")
		cmd := exec.Command(findNft(), "-f", "-")
		cmd.Stdin = strings.NewReader(oracle)
		if out, err := cmd.CombinedOutput(); err == nil {
			nftDeleteTableBestEffort(xnft.Lo0TableName)
			t.Fatalf("oracle FAIL-CLOSED expected: nft ACCEPTED an unresolvable port token (fail-open):\n%s", oracle)
		} else {
			t.Logf("oracle correctly rejected the unresolvable port: %s", strings.TrimSpace(string(out)))
		}

		// Netlink side: InstallLo0 must ERROR and install nothing.
		spec := toNftLo0Spec(badCfg, "badf", "")
		if _, err := inst.InstallLo0(spec); err == nil {
			nftDeleteTableBestEffort(xnft.Lo0TableName)
			t.Fatal("netlink FAIL-CLOSED expected: InstallLo0 returned nil on an unresolvable port token (fail-open: the accept widened to match-all)")
		}
		if out, err := exec.Command(findNft(), "list", "table", "inet", xnft.Lo0TableName).CombinedOutput(); err == nil {
			nftDeleteTableBestEffort(xnft.Lo0TableName)
			t.Fatalf("netlink left a PARTIAL ruleset after a fail-closed build (should have installed nothing):\n%s", out)
		}
	})

	// Mutation-sensitivity against the REAL oracle: each fail-open class must make
	// the netlink dump DIVERGE from the oracle dump — proving the gate catches a
	// fail-open rather than passing vacuously (§12.1).
	oracle := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, programs, wg)
	mutations := []struct {
		name   string
		mutate func(s *xnft.HostInboundSpec)
	}{
		{"widened_daddr_/32_to_/24", func(s *xnft.HostInboundSpec) { s.Views[0].V4Addrs = []string{"10.0.1.0/24"} }},
		{"dropped_saddr_except_subtraction", func(s *xnft.HostInboundSpec) { s.Programs[0].RulesV4[0].PermitSubtract = nil }},
		{"weakened_verdict_zone_opened_all", func(s *xnft.HostInboundSpec) { s.Views[0].SystemServices = []string{"all"} }},
		{"dropped_unzoned_deny", func(s *xnft.HostInboundSpec) { s.UnzonedV4 = nil; s.UnzonedV6 = nil }},
		// FIX-2: widen the narrow IKE exemption to also cover ge-0-0-2.80 — an
		// interface ALREADY in the broad zone-deny IngressIfnames, so the global
		// iifname UNION is unchanged and the TEXT diff is blind (anonymous ifname
		// sets render empty). Only the PER-RULE iifname comparison catches it. If
		// the parity used a union (the pre-fix blind spot) this mutation would pass
		// vacuously — a real IKE-exemption widening merged undetected.
		{"iifname_ike_exemption_widened", func(s *xnft.HostInboundSpec) {
			s.Programs[0].IKEExemptNetdevs = []string{"ge-0-0-2", "ge-0-0-2.50", "ge-0-0-2.80"}
		}},
	}
	for _, mc := range mutations {
		t.Run("mutation_"+mc.name+"_diverges", func(t *testing.T) {
			nftDeleteTableBestEffort(xnft.HostInboundTableName)
			nftLoad(t, oracle)
			dumpOracle := nftListNormalized(t, xnft.HostInboundTableName)
			iifOracle := iifnameScopeByRule(t, xnft.HostInboundTableName)
			nftDeleteTableBestEffort(xnft.HostInboundTableName)

			mutated := toNftHostInboundSpec(views, unzonedV4, unzonedV6, programs, wg)
			mc.mutate(&mutated)
			if err := inst.InstallHostInbound(mutated); err != nil {
				t.Fatalf("mutated install failed: %v", err)
			}
			dumpMut := nftListNormalized(t, xnft.HostInboundTableName)
			iifMut := iifnameScopeByRule(t, xnft.HostInboundTableName)
			nftDeleteTableBestEffort(xnft.HostInboundTableName)
			// A mutation is DETECTED if EITHER the nft-text dump OR the per-rule
			// iifname scope diverges. The iifname-widening class is text-invisible,
			// so it relies entirely on the per-rule comparison.
			if dumpOracle == dumpMut && iifScopesEqual(iifOracle, iifMut) {
				t.Errorf("mutation %q NOT detected: netlink dump AND per-rule iifname scope identical "+
					"to the oracle — the parity gate is vacuous", mc.name)
			}
		})
	}

	// Dropped-counter mutation (README §"dropped counter"): a rule that silently
	// loses its named deny counter is a metric-blindness fail-open (the #3361
	// scraper stops seeing the deny). It MUST survive normalizeNftDump so the
	// parity gate catches it. Strip ONE `counter name "..."` reference from the
	// oracle payload and assert the normalized dumps DIVERGE — proving the gate's
	// dump+normalize step is counter-sensitive. (The netlink builder's structural
	// counter emission is pinned bit-identically by the host_inbound parity check
	// above and the kernel counter-readback test, so netlink==oracle-with-counter
	// != oracle-without-counter; a netlink build that dropped a counter would fail
	// the gate.)
	t.Run("mutation_dropped_counter_diverges", func(t *testing.T) {
		dropped, ok := stripOneCounterRef(oracle)
		if !ok {
			t.Fatal("expected the host-inbound oracle payload to contain a `counter name` reference to drop")
		}
		nftDeleteTableBestEffort(xnft.HostInboundTableName)
		nftLoad(t, oracle)
		dumpFull := nftListNormalized(t, xnft.HostInboundTableName)
		nftDeleteTableBestEffort(xnft.HostInboundTableName)

		nftLoad(t, dropped)
		dumpDropped := nftListNormalized(t, xnft.HostInboundTableName)
		nftDeleteTableBestEffort(xnft.HostInboundTableName)
		if dumpFull == dumpDropped {
			t.Error("dropped-counter NOT detected: normalizeNftDump collapsed a removed `counter name` — " +
				"the parity gate would miss a metric-blindness fail-open")
		}
	})
}

// stripOneCounterRef removes the FIRST `counter name "<n>"` reference from an nft
// payload (leaving the `counter <n> {}` object declaration and the rule's
// verdict), modeling a rule that silently loses its named deny counter.
func stripOneCounterRef(payload string) (string, bool) {
	loc := counterRefRe.FindStringIndex(payload)
	if loc == nil {
		return payload, false
	}
	return payload[:loc[0]] + payload[loc[1]:], true
}

var counterRefRe = regexp.MustCompile(`counter name "[^"]*" `)

// --- parity mechanics -------------------------------------------------------

func parityCheck(t *testing.T, table, oracleText string, install func() error) {
	t.Helper()
	nftDeleteTableBestEffort(table)
	nftLoad(t, oracleText)
	dumpOracle := nftListNormalized(t, table)
	iifOracle := iifnameScopeByRule(t, table)
	nftDeleteTableBestEffort(table)

	if err := install(); err != nil {
		t.Fatalf("netlink install failed: %v", err)
	}
	dumpNetlink := nftListNormalized(t, table)
	iifNetlink := iifnameScopeByRule(t, table)
	nftDeleteTableBestEffort(table)

	if dumpOracle != dumpNetlink {
		t.Errorf("RULESET PARITY DIFF for %s (netlink diverged from the exec-nft oracle):\n"+
			"--- oracle (nft -f -) ---\n%s\n--- netlink ---\n%s", table, dumpOracle, dumpNetlink)
	}
	// Per-rule iifname scope parity: the nft TEXT renders anonymous ifname-set
	// elements empty (google/nftables v0.3.0), so the byte-level scope is compared
	// PER RULE via netlink — a scope move/widen between two rules (an IKE/ident
	// per-interface exemption vs the broad zone deny) that preserves the global
	// union is caught here, not by the text diff or a union (#6405 FIX-2).
	if !iifScopesEqual(iifOracle, iifNetlink) {
		t.Errorf("IIFNAME PER-RULE SCOPE DIFF for %s (netlink diverged from the exec-nft oracle):\n"+
			"--- oracle per-rule iifname ---\n%v\n--- netlink ---\n%v", table, iifOracle, iifNetlink)
	}
}

func nftLoad(t *testing.T, payload string) {
	t.Helper()
	cmd := exec.Command(findNft(), "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f - failed: %v\npayload:\n%s\noutput: %s", err, payload, out)
	}
}

func nftListNormalized(t *testing.T, table string) string {
	t.Helper()
	out, err := exec.Command(findNft(), "list", "table", "inet", table).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table inet %s failed: %v\n%s", table, err, out)
	}
	return normalizeNftDump(string(out))
}

func nftDeleteTableBestEffort(table string) {
	_ = exec.Command(findNft(), "delete", "table", "inet", table).Run()
}

var handleRe = regexp.MustCompile(`\s*#\s*handle\s+\d+\s*$`)
var wsRe = regexp.MustCompile(`\s+`)
var braceSetRe = regexp.MustCompile(`\{[^{}]*,[^{}]*\}`)

// iifnameSetRe canonicalizes an `iifname { ... }` set away from the text diff
// (both sides): google/nftables v0.3.0 renders such anonymous string sets with
// empty element strings, so the text is unreliable. The actual iifname scope is
// asserted byte-for-byte via assertNetlinkIifnameSet instead.
var iifnameSetRe = regexp.MustCompile(`iifname \{[^{}]*\}`)

// normalizeNftDump canonicalizes an `nft list table` dump for comparison: it
// strips rule handles, collapses whitespace, and SORTS the elements inside each
// inline `{ a, b }` set (the kernel may reorder set elements) — but it NEVER
// reorders rules within a chain, so a precedence-reordering fail-open is still
// caught (§12.1).
func normalizeNftDump(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = handleRe.ReplaceAllString(ln, "")
		ln = strings.TrimSpace(wsRe.ReplaceAllString(ln, " "))
		if ln == "" {
			continue
		}
		ln = iifnameSetRe.ReplaceAllString(ln, "iifname { IFSET }")
		ln = braceSetRe.ReplaceAllStringFunc(ln, sortBraceSet)
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func sortBraceSet(set string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(set, "{"), "}")
	parts := strings.Split(inner, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return "{ " + strings.Join(parts, ", ") + " }"
}

// iifnameScopeByRule reads a table's `input` chain rules IN ORDER and returns,
// for each rule, the sorted set of interface names its `iifname` predicate
// scopes ("" when the rule has no iifname match). Both the single `iifname "x"`
// (Meta+Cmp) and the anonymous `iifname { .. }` (Meta+Lookup) forms are decoded
// byte-for-byte via netlink, because google/nftables v0.3.0 renders anonymous
// string-set ELEMENTS empty in `nft list` — so the nft TEXT cannot carry the
// scope, and a per-rule widen/move between two rules is invisible to both the
// text diff and a global union. Reading the kernel PER RULE turns that widen
// into a per-rule diff (#6405 FIX-2).
func iifnameScopeByRule(t *testing.T, table string) []string {
	t.Helper()
	c, err := gnft.New()
	if err != nil {
		t.Fatalf("nftables conn: %v", err)
	}
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: table}
	setNames := map[string][]string{}
	sets, err := c.GetSets(tbl)
	if err != nil {
		t.Fatalf("GetSets(%s): %v", table, err)
	}
	for _, s := range sets {
		if s.KeyType.Name != "ifname" {
			continue
		}
		els, err := c.GetSetElements(s)
		if err != nil {
			t.Fatalf("GetSetElements: %v", err)
		}
		names := make([]string, 0, len(els))
		for _, e := range els {
			names = append(names, string(bytesTrimRightZero(e.Key)))
		}
		setNames[s.Name] = names
	}
	rules, err := c.GetRules(tbl, &gnft.Chain{Name: "input", Table: tbl})
	if err != nil {
		t.Fatalf("GetRules(%s): %v", table, err)
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleIifnameScope(r, setNames))
	}
	return out
}

// ruleIifnameScope decodes one rule's iifname scope: the name(s) compared right
// after a `meta iifname` load, whether a single Cmp or an anonymous set Lookup.
func ruleIifnameScope(r *gnft.Rule, setNames map[string][]string) string {
	var names []string
	pending := false
	var reg uint32
	for _, e := range r.Exprs {
		switch x := e.(type) {
		case *expr.Meta:
			if x.Key == expr.MetaKeyIIFNAME {
				pending, reg = true, x.Register
				continue
			}
			pending = false
		case *expr.Cmp:
			if pending && x.Register == reg {
				names = append(names, string(bytesTrimRightZero(x.Data)))
			}
			pending = false
		case *expr.Lookup:
			if pending && x.SourceRegister == reg {
				names = append(names, setNames[x.SetName]...)
			}
			pending = false
		default:
			pending = false
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// iifScopesEqual compares two per-rule iifname-scope lists index-by-index (NOT
// as a union) so a scope move/widen between rules that preserves the global
// union is still detected (#6405 FIX-2).
func iifScopesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesTrimRightZero(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == 0 {
		i--
	}
	return b[:i]
}

// The converters (toNftViews / toNftHostInboundSpec / toNftProgram /
// toNftDenyRules / toNftPortRanges / toNftLo0Spec / toNftLo0Term) that map the
// daemon dpuserspace views / junos-host programs / lo0 terms into the pkg/nftables
// input specs were PROMOTED to production in #6387 PR-3 (daemon_nft_netlink.go);
// this test uses those production converters directly (same package).

// --- construct-complete parity inputs ---------------------------------------

func parityHostInboundInputs() (views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, programs []dpuserspace.JunosHostProgram, wg []uint16) {
	views = []dpuserspace.ZoneHostInboundView{
		// #9637: IngressNetdevs on every rendering branch the ingress-zone rules
		// take, so T1 pins them rule-for-rule: a multi-netdev set (trust), the
		// named-service union (mgmt), routing protocols (core), the ident-reset
		// reject (edge), the empty-admit drop (quarantine) and any-service (open).
		{Zone: "trust", SystemServices: []string{"ssh", "https", "ping", "dns"}, V4Addrs: []string{"10.0.1.1", "10.0.1.2"}, V6Addrs: []string{"2001:db8:1::1"}, IngressNetdevs: []string{"ge-0-0-0", "ge-0-0-0.10"}},
		{Zone: "mgmt", SystemServices: []string{"all"}, V4Addrs: []string{"10.0.9.1"}, IngressNetdevs: []string{"ge-0-0-9"}},
		{Zone: "core", Protocols: []string{"all"}, V4Addrs: []string{"10.0.5.1"}, V6Addrs: []string{"2001:db8:5::1"}, IngressNetdevs: []string{"ge-0-0-5"}},
		{Zone: "edge", SystemServices: []string{"ident-reset", "ssh"}, V4Addrs: []string{"10.0.7.1"}, IngressNetdevs: []string{"ge-0-0-7"}},
		{Zone: "quarantine", V4Addrs: []string{"10.0.8.1"}, V6Addrs: []string{"2001:db8:8::1"}, IngressNetdevs: []string{"ge-0-0-8"}},
		{Zone: "open", SystemServices: []string{"any-service"}, V4Addrs: []string{"10.0.6.1"}, IngressNetdevs: []string{"ge-0-0-6"}},
		// A v6-only view with an ingress scope. Its ip (v4) ingress drop is the
		// ONLY reason its v4 deny counter is declared, so a counter pre-pass
		// that ignores ingress drops leaves a rule referencing an undeclared
		// counter. Every other view already declares its v4 counter for its own
		// addresses and cannot show that (mutation M7 of #9637 escaped without
		// this row).
		{Zone: "v6only", SystemServices: []string{"ping"}, V6Addrs: []string{"2001:db8:66::1"}, IngressNetdevs: []string{"ge-0-0-66"}},
	}
	unzonedV4 = []string{"10.0.99.1"}
	unzonedV6 = []string{"2001:db8:99::1"}
	wg = []uint16{51820, 51821}
	programs = []dpuserspace.JunosHostProgram{
		{
			Zone:                  "untrust",
			IngressIfnames:        []string{"ge-0-0-2", "ge-0-0-2.50", "ge-0-0-2.80"},
			HasApplicationAnyDeny: true,
			CoarseAdmitsIKE:       true,
			CoarseIdentResets:     true,
			// IKE exemption is a per-interface SUBSET of the zone deny scope (a
			// 2-member anonymous set). The #6405 FIX-2 mutation widens it to also
			// cover ge-0-0-2.80 — already in IngressIfnames, so the global iifname
			// UNION is unchanged; only the PER-RULE parity check catches the widen.
			IKEExemptNetdevs:  []string{"ge-0-0-2", "ge-0-0-2.50"},
			IdentResetNetdevs: []string{"ge-0-0-2"},
			RulesV4: []config.JunosHostDenyRule{
				{Family: "ip", Src: []string{"192.0.2.0/24", "198.51.100.7"}, PermitSubtract: []string{"192.0.2.10"}, DstAny: true},
				{Family: "ip", SrcExcluded: true, Src: []string{"203.0.113.0/24"}, DstAny: true, L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoTCP, Ports: []config.PortRange{{Lo: 22, Hi: 22}}}}},
				{Family: "ip", SrcAny: true, DstAny: true, L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoICMP, ICMPType: ptrU8(8), ICMPCode: ptrU8(0)}}},
				// #4146 destination slice: a POSITIVE `match destination-address`
				// (multi-element set) and a NEGATED one. Both must render the same
				// `daddr` / `daddr !=` expressions on the netlink path as the oracle,
				// in the same order (after the source predicate) — a dropped daddr
				// predicate here would widen the deny to every firewall address.
				{Family: "ip", Src: []string{"198.51.100.0/24"}, Dst: []string{"10.0.7.1/32", "10.0.8.1/32"},
					L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoTCP, Ports: []config.PortRange{{Lo: 443, Hi: 443}}}}},
				{Family: "ip", SrcAny: true, DstExcluded: true, Dst: []string{"10.0.9.1/32"},
					L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoUDP, Ports: []config.PortRange{{Lo: 161, Hi: 161}}}}},
			},
			RulesV6: []config.JunosHostDenyRule{
				{Family: "ip6", Src: []string{"2001:db8:a::/48"}, DstAny: true, L4: []config.JunosHostDenyL4{{Proto: 47}}},
				{Family: "ip6", SrcAny: true, Dst: []string{"2001:db8:5::1/128"},
					L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoTCP, Ports: []config.PortRange{{Lo: 22, Hi: 22}}}}},
			},
		},
	}
	return views, unzonedV4, unzonedV6, programs, wg
}

func parityLo0Config() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0f": {Terms: []*config.FirewallFilterTerm{
			{Name: "ssh-in", SourceAddresses: []string{"10.0.0.0/8"}, DestAddresses: []string{"10.0.1.1"}, Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Count: "ssh_hits", Action: "accept"},
			// #6405 FIX-1: a NAMED destination port. The oracle emits the raw
			// `th dport ssh`; nft resolves it via /etc/services -> 22. The netlink
			// build must resolve it to the SAME number (config.ResolveFilterPortRange)
			// and produce bit-identical kernel state — never drop the predicate.
			{Name: "named-svc", Protocols: []string{"tcp"}, DestinationPorts: []string{"ssh"}, Action: "accept"},
			{Name: "range-drop", SourcePorts: []string{"1024", "2048"}, DestinationPorts: []string{"33434-33523"}, DSCPs: []string{"ef"}, Log: true, Action: "discard"},
			{Name: "reject-term", DestPortsExcept: []string{"80", "443"}, ICMPTypes: []int{3}, ICMPCodes: []int{4}, IsFragment: true, Action: "reject"},
			{Name: "syn-only", TCPFlags: []string{"syn", "&", "!ack"}, Action: "accept"},
			{Name: "count-only", Count: "audit"},
			{Name: "multi", DestAddresses: []string{"10.0.1.1", "10.0.1.2"}, Protocols: []string{"tcp", "udp"}, Action: "accept"},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"lo0f6": {Terms: []*config.FirewallFilterTerm{
			{Name: "v6-dscp", DestAddresses: []string{"2001:db8::/32"}, DSCPs: []string{"cs1"}, Action: "accept"},
			{Name: "v6-frag", ICMPTypes: []int{1, 2}, IsFragment: true, Action: "discard"},
			{Name: "v6-except", SourceAddresses: []string{"2001:db8:bad::/48"}, DestPortsExcept: []string{"22"}, Action: "accept"},
		}},
	}
	return cfg
}

func ptrU8(v uint8) *uint8 { return &v }

// TestIifnameScopePerRuleVsUnion is the no-kernel parent-RED for #6405 FIX-2: it
// proves the PER-RULE iifname comparison catches a scope widen that a global
// UNION misses. Reverting iifScopesEqual to a union comparison turns this RED.
func TestIifnameScopePerRuleVsUnion(t *testing.T) {
	// rule0 = narrow IKE exemption, rule1 = broad zone deny. The widened variant
	// moves ge-0-0-2.50 into rule0's exemption (a real fail-open) while keeping
	// the GLOBAL union {ge-0-0-2, ge-0-0-2.50} identical — a union check is blind.
	oracle := []string{"ge-0-0-2", "ge-0-0-2,ge-0-0-2.50"}
	widened := []string{"ge-0-0-2,ge-0-0-2.50", "ge-0-0-2,ge-0-0-2.50"}
	if iifScopesEqual(oracle, widened) {
		t.Error("per-rule iifname comparison must DETECT a widen that preserves the global union " +
			"(a union check would pass it vacuously)")
	}
	if !iifScopesEqual(oracle, []string{"ge-0-0-2", "ge-0-0-2,ge-0-0-2.50"}) {
		t.Error("identical per-rule iifname scopes must compare equal")
	}
}
