package snmp

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestTrapCommunityIgnoresQueryCommunities2989 preserves the #2989
// determinism property under the #15052 semantics: with more than one
// query community configured, the trap community is still deterministic
// — it is now the trap-group name (see traps_community_15052_test.go for
// the wire-level guard). Reverting to a map-range pick over
// cfg.Communities would reintroduce both the #2989 nondeterminism and
// the #15052 query-credential disclosure.
func TestTrapCommunityIgnoresQueryCommunities2989(t *testing.T) {
	cfg := &config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"zulu":   {Name: "zulu", Authorization: "read-write"},
			"alpha":  {Name: "alpha", Authorization: "read-only"},
			"mike":   {Name: "mike", Authorization: "read-only"},
			"bravo":  {Name: "bravo", Authorization: "read-only"},
			"oscar":  {Name: "oscar", Authorization: "read-only"},
			"delta":  {Name: "delta", Authorization: "read-only"},
			"golf":   {Name: "golf", Authorization: "read-only"},
			"hotel":  {Name: "hotel", Authorization: "read-only"},
			"india":  {Name: "india", Authorization: "read-only"},
			"juliet": {Name: "juliet", Authorization: "read-only"},
		},
	}
	tg := &config.SNMPTrapGroup{Name: "trapdest"}
	for range 200 {
		if got := trapCommunityForGroup(tg); got != "trapdest" {
			t.Fatalf("trapCommunityForGroup() = %q, want trap-group name %q", got, "trapdest")
		}
	}
	_ = cfg
}

// TestTrapCommunityReachesLinkTrap2989 proves the trap-group community
// actually reaches the wire-built packet, not just the helper.
func TestTrapCommunityReachesLinkTrap2989(t *testing.T) {
	agent := &Agent{startTime: time.Now()}
	community := trapCommunityForGroup(&config.SNMPTrapGroup{Name: "trapdest"})
	if community != "trapdest" {
		t.Fatalf("community = %q, want trapdest", community)
	}
	pkt := agent.buildLinkTrap(community, true, 1, "ge-0-0-0")
	if !containsBytes(pkt, []byte("trapdest")) {
		t.Fatalf("built trap packet does not carry community %q", community)
	}
	if containsBytes(pkt, []byte("alpha")) {
		t.Fatalf("built trap packet carries a query community")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
