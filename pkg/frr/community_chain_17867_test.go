package frr

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type routeMapSequence17867 struct {
	seq     int
	action  string
	matches []string
	gotoSeq int
	next    bool
}

type communityList17867 struct {
	kind    string
	entries []string
}

func parseRouteMap17867(t *testing.T, rendered string) ([]routeMapSequence17867, map[string]communityList17867) {
	t.Helper()
	var seqs []routeMapSequence17867
	var current *routeMapSequence17867
	lists := make(map[string]communityList17867)
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, "bgp community-list ") {
			fields := strings.Fields(strings.TrimPrefix(line, "bgp community-list "))
			if len(fields) >= 4 && fields[2] == "permit" {
				list := lists[fields[1]]
				list.kind = fields[0]
				list.entries = append(list.entries, strings.Join(fields[3:], " "))
				lists[fields[1]] = list
			}
			continue
		}
		if strings.HasPrefix(line, "route-map P ") {
			fields := strings.Fields(line)
			if len(fields) != 4 {
				t.Fatalf("malformed route-map sequence header %q", line)
			}
			if current != nil {
				seqs = append(seqs, *current)
			}
			n, err := strconv.Atoi(fields[3])
			if err != nil {
				t.Fatalf("malformed sequence number in %q: %v", line, err)
			}
			current = &routeMapSequence17867{seq: n, action: fields[2], gotoSeq: -1}
			continue
		}
		if current == nil {
			continue
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "exit":
			seqs = append(seqs, *current)
			current = nil
		case strings.HasPrefix(line, "match "):
			current.matches = append(current.matches, line)
		case strings.HasPrefix(line, "on-match goto "):
			n, err := strconv.Atoi(strings.TrimPrefix(line, "on-match goto "))
			if err != nil {
				t.Fatalf("malformed goto in %q: %v", line, err)
			}
			current.gotoSeq = n
		case line == "on-match next":
			current.next = true
		}
	}
	if current != nil {
		seqs = append(seqs, *current)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i].seq < seqs[j].seq })
	return seqs, lists
}

func communityListMatches17867(list communityList17867, joined string) bool {
	for _, entry := range list.entries {
		if list.kind == "standard" {
			for _, token := range strings.Fields(joined) {
				if token == entry {
					return true
				}
			}
			continue
		}
		pattern, err := regexp.CompilePOSIX(entry)
		if err == nil && pattern.MatchString(joined) {
			return true
		}
	}
	return false
}

type routeInput17867 struct {
	communities string
	// Non-community matches are keyed by their rendered match clause. This lets
	// each test assert the community semantics while holding sibling dimensions
	// true or false, without reimplementing their FRR match engines.
	otherMatches map[string]bool
}

func evaluateRouteMap17867(seqs []routeMapSequence17867, lists map[string]communityList17867, route routeInput17867) string {
	positions := make(map[int]int, len(seqs))
	for i, seq := range seqs {
		positions[seq.seq] = i
	}
	for i, steps := 0, 0; i < len(seqs); steps++ {
		if steps > len(seqs)*3+3 {
			return "loop"
		}
		seq := seqs[i]
		matched := true
		for _, clause := range seq.matches {
			if strings.HasPrefix(clause, "match community ") {
				name := strings.TrimSpace(strings.TrimPrefix(clause, "match community "))
				if !communityListMatches17867(lists[name], route.communities) {
					matched = false
					break
				}
			} else if !route.otherMatches[clause] {
				matched = false
				break
			}
		}
		if !matched {
			i++
			continue
		}
		if seq.gotoSeq >= 0 {
			if next, ok := positions[seq.gotoSeq]; ok {
				i = next
				continue
			}
			return "fallthrough"
		}
		if seq.next {
			i++
			continue
		}
		return seq.action
	}
	return "fallthrough"
}

func renderPolicy17867(t *testing.T, terms []*config.PolicyTerm) (string, []routeMapSequence17867, map[string]communityList17867) {
	t.Helper()
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}},
		},
		ASPaths: map[string]*config.ASPathDef{
			"AP": {Name: "AP", Regex: "65000"},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: terms, DefaultAction: "accept"},
		},
	}
	got := New().generatePolicyOptions(po)
	seqs, lists := parseRouteMap17867(t, got)
	return got, seqs, lists
}

func allOtherMatches17867(seqs []routeMapSequence17867, match bool) map[string]bool {
	matches := make(map[string]bool)
	for _, seq := range seqs {
		for _, clause := range seq.matches {
			if !strings.HasPrefix(clause, "match community ") {
				matches[clause] = match
			}
		}
	}
	return matches
}

func TestCommunityChainMixedTerms17867(t *testing.T) {
	tests := []struct {
		name string
		term *config.PolicyTerm
	}{
		{"prefix-list", &config.PolicyTerm{Name: "t", FromCommunity: []string{"SH"}, PrefixList: []string{"PL"}, Action: "reject"}},
		{"as-path", &config.PolicyTerm{Name: "t", FromCommunity: []string{"SH"}, FromASPath: []string{"AP"}, Action: "reject"}},
		{"protocol", &config.PolicyTerm{Name: "t", FromCommunity: []string{"SH"}, FromProtocols: []string{"bgp"}, Action: "reject"}},
		{"route-filter", &config.PolicyTerm{Name: "t", FromCommunity: []string{"SH"}, RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "reject"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, seqs, lists := renderPolicy17867(t, []*config.PolicyTerm{
				tc.term,
				{Name: "later-accept", Action: "accept"},
			})
			positive := routeInput17867{communities: "65000:100", otherMatches: allOtherMatches17867(seqs, true)}
			if result := evaluateRouteMap17867(seqs, lists, positive); result != "deny" {
				t.Fatalf("shared-token route with matching %s = %s, want deny\n%s", tc.name, result, got)
			}
			negative := routeInput17867{communities: "65000:100", otherMatches: allOtherMatches17867(seqs, false)}
			if result := evaluateRouteMap17867(seqs, lists, negative); result != "permit" {
				t.Fatalf("shared-token route with non-matching %s = %s, want permit\n%s", tc.name, result, got)
			}
			miss := routeInput17867{communities: "65000:7", otherMatches: allOtherMatches17867(seqs, true)}
			if result := evaluateRouteMap17867(seqs, lists, miss); result != "permit" {
				t.Fatalf("route missing a community member = %s, want permit\n%s", result, got)
			}
		})
	}
}
