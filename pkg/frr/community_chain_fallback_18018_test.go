package frr

import (
	"crypto/sha256"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func communityChainFallbackConfig18018(po *config.PolicyOptionsConfig) *FullConfig {
	return &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{
				Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"},
			}},
		},
	}
}

func TestMixedCommunityChainFallbackCountAndGuard18018(t *testing.T) {
	base := func() *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{
			Communities: map[string]*config.CommunityDef{
				"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
			},
		}
	}
	tests := []struct {
		name                         string
		po                           *config.PolicyOptionsConfig
		term                         *config.PolicyTerm
		hasPartialDanglingPrefixList bool
		wantCount                    uint64
	}{
		{
			name: "partially dangling prefix-list family",
			po: func() *config.PolicyOptionsConfig {
				po := base()
				po.PrefixLists = map[string]*config.PrefixList{
					"PL": {Name: "PL", Prefixes: []string{"192.0.2.0/24", "not-a-v6-prefix::"}},
				}
				return po
			}(),
			term: &config.PolicyTerm{
				Name: "partial", FromCommunity: []string{"SH", "SH"}, PrefixList: []string{"PL"}, Action: "reject",
			},
			hasPartialDanglingPrefixList: true,
			wantCount:                    4,
		},
		{
			name: "dangling route-filter family",
			po:   base(),
			term: &config.PolicyTerm{
				Name: "dangling", FromCommunity: []string{"SH", "SH"}, Action: "reject",
				RouteFilters: []*config.RouteFilter{
					{Prefix: "192.0.2.0/24", MatchType: "orlonger"},
					{Prefix: "2001:db8::/32", MatchType: "through"},
				},
			},
			wantCount: 4,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := &config.PolicyStatement{Name: "EXP", Terms: []*config.PolicyTerm{tc.term}}
			if config.CommunityMixedChainTermCanLower16869(tc.po, tc.term, tc.hasPartialDanglingPrefixList) {
				t.Fatal("renderer eligibility predicate unexpectedly allowed chain lowering")
			}
			definitions, body, _ := New().renderPolicyTermSequencesWithDefinitions(tc.po, "P", "P", ps, 10)
			seqs, _ := parseRouteMap17867(t, definitions+body)
			count := config.RouteMapSequenceCount(tc.po, ps)
			if count != tc.wantCount {
				t.Fatalf("admission count = %d, want %d", count, tc.wantCount)
			}
			if uint64(len(seqs)) > count {
				t.Fatalf("admission count %d is below %d emitted fallback sequences", count, len(seqs))
			}
			if len(seqs) != 3 {
				t.Fatalf("fallback emitted %d sequences, want two community variants plus one fail-closed family sequence\n%s", len(seqs), body)
			}
			if strings.Contains(body, "-xpf-com-") || !strings.Contains(body, "match community SH\n") {
				t.Fatalf("fallback did not retain the public community OR matches:\n%s", body)
			}

			tc.po.PolicyStatements = map[string]*config.PolicyStatement{ps.Name: ps}
			guarded := New().buildManagedSection(communityChainFallbackConfig18018(tc.po))
			headers := routeMapHeaders6807(guarded, "EXP")
			if len(headers) < len(seqs) || (len(headers) == 1 && headers[0] == fmt.Sprintf("route-map EXP deny %d", quarantineDenySeq)) {
				t.Fatalf("small fallback should be admitted and guarded with its full output; headers=%v\n%s", headers, guarded)
			}
			if !strings.Contains(guarded, "match community SH\n") {
				t.Fatalf("guarded output lost the fallback community match:\n%s", guarded)
			}
		})
	}
}

func TestMixedCommunityChainFallbackCeiling18018(t *testing.T) {
	const refs = 6553
	communities := make([]string, refs)
	for i := range communities {
		communities[i] = "SH"
	}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
	}
	ps := &config.PolicyStatement{Name: "EXP", Terms: []*config.PolicyTerm{{
		Name: "near-ceiling", FromCommunity: communities, Action: "reject",
		RouteFilters: []*config.RouteFilter{
			{Prefix: "192.0.2.0/24", MatchType: "orlonger"},
			{Prefix: "2001:db8::/32", MatchType: "through"},
		},
	}}}
	po.PolicyStatements = map[string]*config.PolicyStatement{"EXP": ps}
	if config.CommunityMixedChainTermCanLower16869(po, ps.Terms[0], false) {
		t.Fatal("dangling route-filter family must decline chain lowering")
	}
	definitions, body, _ := New().renderPolicyTermSequencesWithDefinitions(po, "P", "P", ps, 10)
	seqs, _ := parseRouteMap17867(t, definitions+body)
	count := config.RouteMapSequenceCount(po, ps)
	if uint64(len(seqs)) != refs+1 {
		t.Fatalf("fallback emitted %d sequences, want %d (community refs plus one dangling-family deny)", len(seqs), refs+1)
	}
	guarded := New().buildManagedSection(communityChainFallbackConfig18018(po))
	headers := routeMapHeaders6807(guarded, "EXP")
	if len(headers) != 1 || headers[0] != fmt.Sprintf("route-map EXP deny %d", quarantineDenySeq) {
		first := ""
		if len(headers) > 0 {
			first = headers[0]
		}
		t.Fatalf("over-ceiling fallback must quarantine: count=%d emitted=%d headers=%d first=%q",
			count, len(seqs), len(headers), first)
	}
	if count < uint64(len(seqs)) || count <= config.MaxRouteMapSequences {
		t.Fatalf("admission count %d must cover %d emitted sequences and exceed max %d", count, len(seqs), config.MaxRouteMapSequences)
	}
}

func TestMixedCommunityChainStillLowersValidTerm18018(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"192.0.2.0/24"}},
		},
	}
	term := &config.PolicyTerm{Name: "valid", FromCommunity: []string{"SH", "SH"}, PrefixList: []string{"PL"}, Action: "reject"}
	ps := &config.PolicyStatement{Name: "P", Terms: []*config.PolicyTerm{term}}
	if !config.CommunityMixedChainTermCanLower16869(po, term, false) {
		t.Fatal("fully renderable mixed term should retain chain lowering")
	}
	definitions, body, _ := New().renderPolicyTermSequencesWithDefinitions(po, "P", "P", ps, 10)
	seqs, _ := parseRouteMap17867(t, definitions+body)
	if got, want := uint64(len(seqs)), config.RouteMapSequenceCount(po, ps); got != want || want != 5 {
		t.Fatalf("chain-lowered render has %d sequences, count=%d, want both 5\n%s", got, want, body)
	}
	if strings.Contains(body, "match community SH\n") || !strings.Contains(body, "-xpf-com-") {
		t.Fatalf("valid mixed term did not use its chain gate:\n%s", body)
	}
}
func continuationStressConfig18018(n int) *config.PolicyOptionsConfig {
	terms := make([]*config.PolicyTerm, n)
	for i := range terms {
		terms[i] = &config.PolicyTerm{
			Name:          fmt.Sprintf("t%d", i),
			FromCommunity: []string{"SH"},
			PrefixList:    []string{"PL"},
			CommunityOp:   "add",
			CommunityAdd:  "65000:900",
		}
	}
	return &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"192.0.2.0/24"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: terms},
		},
	}
}

func continuationStressOutput18018(n int) string {
	return New().generatePolicyOptions(continuationStressConfig18018(n))
}

func continuationStressAllocation18018(n int) uint64 {
	po := continuationStressConfig18018(n)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	output := New().generatePolicyOptions(po)
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(output)
	return after.TotalAlloc - before.TotalAlloc
}

func TestContinuationOutputBytesUnchanged18018(t *testing.T) {
	want := map[int]struct {
		bytes int
		sha   string
	}{
		500:  {bytes: 201578, sha: "5c2a5dfa2a09c5d606bdb84de3a5fcd81e4301ac71b68e6e195e4c2118cbb6d4"},
		1000: {bytes: 404578, sha: "acc33ac83cf51372568f26132eb21532faf2940632a3a01917e0330fc9ecb205"},
		1310: {bytes: 530438, sha: "83a628ef23997bddcb0a8d31fad6c4485aeeb9d7fa2730af71e1c0c4083b5483"},
	}
	for _, n := range []int{500, 1000, 1310} {
		output := continuationStressOutput18018(n)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(output)))
		if len(output) != want[n].bytes || hash != want[n].sha {
			t.Errorf("%d-term output changed: bytes=%d sha256=%s, want bytes=%d sha256=%s",
				n, len(output), hash, want[n].bytes, want[n].sha)
		}
	}
}

func TestContinuationAllocationGrowth18018(t *testing.T) {
	allocated := make([]uint64, 3)
	for i, n := range []int{500, 1000, 1310} {
		allocated[i] = continuationStressAllocation18018(n)
		t.Logf("terms=%d allocated=%d bytes", n, allocated[i])
	}
	if allocated[0] == 0 || allocated[1] > allocated[0]*3 || allocated[2] > allocated[1]*2 {
		t.Fatalf("allocation growth is not roughly linear: 500=%d 1000=%d 1310=%d bytes",
			allocated[0], allocated[1], allocated[2])
	}
}

func BenchmarkRenderPolicyTermSequencesContinuation18018(b *testing.B) {
	for _, n := range []int{500, 1000, 1310} {
		po := continuationStressConfig18018(n)
		b.Run(fmt.Sprintf("terms=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = New().generatePolicyOptions(po)
			}
		})
	}
}

func TestMixedChainMultiVariantContinuation18018(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL1": {Name: "PL1", Prefixes: []string{"192.0.2.0/24"}},
			"PL2": {Name: "PL2", Prefixes: []string{"198.51.100.0/24"}},
		},
	}
	term := &config.PolicyTerm{
		Name: "modify", FromCommunity: []string{"SH"}, PrefixList: []string{"PL1", "PL2"},
		CommunityOp: "add", CommunityAdd: "65000:900",
	}
	ps := &config.PolicyStatement{Name: "P", Terms: []*config.PolicyTerm{term}}
	definitions, body, nextSeq := New().renderPolicyTermSequencesWithDefinitions(po, "P", "P", ps, 10)
	seqs, _ := parseRouteMap17867(t, definitions+body)
	bodyVariants := 0
	for _, seq := range seqs {
		if len(seq.sets) == 0 {
			continue
		}
		bodyVariants++
		if seq.gotoSeq != nextSeq {
			t.Fatalf("modifying body sequence %d continues to %d, want %d\n%s", seq.seq, seq.gotoSeq, nextSeq, body)
		}
	}
	if bodyVariants != 2 {
		t.Fatalf("emitted %d modifying body variants, want 2\n%s", bodyVariants, body)
	}
}

func TestMixedCommunityChainBothInvalidPrefixListStillLowers18018(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"192.0.2.0/not-a-mask", "2001:db8::/not-a-mask"}},
		},
	}
	term := &config.PolicyTerm{Name: "all-dangling", FromCommunity: []string{"SH"}, PrefixList: []string{"PL"}}
	ps := &config.PolicyStatement{Name: "P", Terms: []*config.PolicyTerm{term}}
	definitions, body, _ := New().renderPolicyTermSequencesWithDefinitions(po, "P", "P", ps, 10)
	seqs, _ := parseRouteMap17867(t, definitions+body)
	count := config.RouteMapSequenceCount(po, ps)
	if count != 6 {
		t.Fatalf("both-invalid list count = %d, emitted=%d, want 6 (two family refs plus four chain slots)", count, len(seqs))
	}
	if len(seqs) != 4 || uint64(len(seqs)) > count {
		t.Fatalf("both-invalid list emitted %d sequences, count=%d; want four chain slots covered by count\n%s", len(seqs), count, body)
	}
	if !strings.Contains(body, "-xpf-com-") {
		t.Fatalf("both-invalid family list should not decline the chain:\n%s", body)
	}
}
