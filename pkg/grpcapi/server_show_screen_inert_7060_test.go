package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func compileScreenCfg7060(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

// TestPerProfileRenderersCarryTheDiagnosticBlocks_7060 covers the gap #7060
// names: the per-profile query is the natural next command after seeing a zone
// reference a profile, and it was the one surface that did not answer.
//
// Both narrow renderers are driven, because they are separate functions with
// separate copies of the empty-inventory branch — asserting only one would leave
// the other free to regress, which is how this gap arose in the first place.
func TestPerProfileRenderersCarryTheDiagnosticBlocks_7060(t *testing.T) {
	// A profile that IS defined but enforces nothing: the #7059 middle state,
	// reached through a knob that commits strict-clean.
	cfg := compileScreenCfg7060(t, []string{
		"set security screen ids-option p alarm-without-drop",
		"set security zones security-zone trust screen p",
	})

	for _, tc := range []struct {
		name  string
		topic string
		call  func(*Server, *pb.ShowTextRequest, *config.Config, *strings.Builder) error
	}{
		{
			"ids-option", "screen-ids-option:p",
			func(s *Server, r *pb.ShowTextRequest, c *config.Config, b *strings.Builder) error {
				_, err := s.showScreenIDSOption(r, c, b)
				return err
			},
		},
		{
			"ids-option detail", "screen-ids-option-detail:p",
			func(s *Server, r *pb.ShowTextRequest, c *config.Config, b *strings.Builder) error {
				_, err := s.showScreenIDSOptionDetail(r, c, b)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if err := tc.call(&Server{}, &pb.ShowTextRequest{Topic: tc.topic}, cfg, &buf); err != nil {
				t.Fatalf("render: %v", err)
			}
			out := buf.String()
			if !strings.Contains(out, dpuserspace.ScreenInertDisposition) {
				t.Fatalf("`show security screen ids-option p` must report that zone trust "+
					"is stranded on a profile enforcing nothing. The wide command shows "+
					"it; the narrow one is the natural next command and did not (#7060). "+
					"got:\n%s", out)
			}
			if !strings.Contains(out, "'p'") || !strings.Contains(out, "trust") {
				t.Fatalf("the block must name the profile (quoted) and the zone; got:\n%s", out)
			}
		})
	}
}

// TestPerProfileRendererFiltersToTheQueriedProfile_7060 is the paired cell: the
// block is FILTERED, so querying a healthy profile must not inherit another
// profile's finding. Without this the fix could emit every finding on every
// per-profile query and still pass the test above.
func TestPerProfileRendererFiltersToTheQueriedProfile_7060(t *testing.T) {
	cfg := compileScreenCfg7060(t, []string{
		"set security screen ids-option bad alarm-without-drop",
		"set security zones security-zone trust screen bad",
		"set security screen ids-option good tcp land",
		"set security zones security-zone dmz screen good",
	})
	var buf strings.Builder
	if _, err := (&Server{}).showScreenIDSOption(
		&pb.ShowTextRequest{Topic: "screen-ids-option:good"}, cfg, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, dpuserspace.ScreenInertDisposition) {
		t.Fatalf("querying the HEALTHY profile 'good' reported the finding that belongs "+
			"to profile 'bad'. An unfiltered block trains operators to ignore it; "+
			"got:\n%s", out)
	}
	if strings.Contains(out, "'bad'") {
		t.Fatalf("the other profile's name leaked into this profile's output; got:\n%s", out)
	}

	// Positive control on the SAME config: the bad profile must still report, so
	// this cell cannot pass by the block being broken everywhere.
	var buf2 strings.Builder
	if _, err := (&Server{}).showScreenIDSOption(
		&pb.ShowTextRequest{Topic: "screen-ids-option:bad"}, cfg, &buf2); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf2.String(), dpuserspace.ScreenInertDisposition) {
		t.Fatalf("positive control: querying 'bad' must still report the finding, else "+
			"the filter test above passes because nothing is ever emitted; got:\n%s",
			buf2.String())
	}
}
