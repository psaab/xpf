package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #4921: showTestRouting had no `seen` map, so a repeated known selector key
// (e.g. `dest=a,dest=b` or `instance=blue,instance=prod`) silently LAST-WON in
// the switch below — the diagnostic route lookup answered for a DIFFERENT
// destination/VRF than the operator typed, with no warning. This is the
// sibling of #3709 (showTestPolicy), which rejects a duplicate selector. The
// handler must now report the repeated key instead of silently picking one.
//
// routing is nil here (the default Server), so a non-duplicate selector set
// proceeds to the "Routing manager not available" diagnostic; a duplicate is
// reported first (a client-input error, independent of routing availability).
//
// RED-on-revert: without the `seen` map the duplicate cases emit "Routing
// manager not available" (silently using the last value) instead of naming the
// repeated selector.
func TestShowTestRoutingRejectsDuplicateSelector(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name       string
		topic      string
		wantSubstr string
	}{
		{
			name:       "duplicate dest",
			topic:      "test-routing:dest=10.0.0.0/24,dest=192.0.2.1",
			wantSubstr: `selector "dest" specified more than once`,
		},
		{
			name:       "duplicate instance",
			topic:      "test-routing:dest=192.0.2.1,instance=blue,instance=prod",
			wantSubstr: `selector "instance" specified more than once`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if _, err := s.showTestRouting(&pb.ShowTextRequest{Topic: tc.topic}, nil, &buf); err != nil {
				t.Fatalf("showTestRouting(%q) error = %v", tc.topic, err)
			}
			out := buf.String()
			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("showTestRouting(%q) = %q; want it to contain %q", tc.topic, out, tc.wantSubstr)
			}
			// A duplicate must NOT fall through to the manager/lookup path:
			// it is an input error that fully short-circuits the query.
			if strings.Contains(out, "Routing manager not available") {
				t.Errorf("showTestRouting(%q) fell through to the lookup path: %q", tc.topic, out)
			}
		})
	}
}

// A selector set with each key at most once is NOT flagged as a duplicate;
// with routing nil it falls through to the manager-unavailable diagnostic,
// proving the duplicate guard does not false-positive on distinct keys.
func TestShowTestRoutingDistinctSelectorsNotFlagged(t *testing.T) {
	s := &Server{}
	var buf strings.Builder
	if _, err := s.showTestRouting(&pb.ShowTextRequest{Topic: "test-routing:dest=10.0.0.0/24,instance=dmz"}, nil, &buf); err != nil {
		t.Fatalf("showTestRouting error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "specified more than once") {
		t.Errorf("showTestRouting flagged distinct selectors as duplicate: %q", out)
	}
	if !strings.Contains(out, "Routing manager not available") {
		t.Errorf("showTestRouting(distinct, routing=nil) = %q; want the manager-unavailable diagnostic", out)
	}
}
