// Tests for #13202 (D10-06): the show command surfaces parsed pipe
// modifiers with substring matching (`strings.Contains(rest, "compare")`,
// `strings.Contains(line, "| display json")`, ...). That silently
// accepted garbage and dropped operator intent:
//   - `show system rollback 1 | display json` rendered HIERARCHICAL text
//     instead of honouring or rejecting the modifier;
//   - `show system rollback 1 bogus_compare_token` ran ShowCompare
//     because the token merely CONTAINS "compare";
//   - `show interfaces | compare` in config mode discarded the path and
//     diffed the whole candidate;
//   - trailing garbage after a valid modifier (`| display set bogus`)
//     was silently ignored on every surface.
//
// The fix parses modifiers token-exactly (shared splitShowPipe and
// parseShowDisplay helpers): only `| display <json|set|xml>` on rollback,
// `| display <json|set|xml|inheritance>` on configuration show, and
// `| compare [rollback <N>]` in config mode are accepted. Unsupported
// combinations and trailing tokens error BEFORE any RPC is issued.
//
// RED-on-revert: restoring the substring checks makes the reject cases
// return nil and issue the wrong RPC (asserted zero-call below), while
// `show system rollback 1 | display json` incorrectly renders hierarchy.

package main

import (
	"context"
	"reflect"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

type showPipeRecorderClient struct {
	pb.BpfrxServiceClient

	rollbackCalls int
	rollbackN     int32
	rollbackFmt   pb.ConfigFormat
	compareCalls  int
	compareN      int32
	configCalls   int
	configFmt     pb.ConfigFormat
	configTarget  pb.ConfigTarget
	configPath    []string
}

func (f *showPipeRecorderClient) ShowRollback(
	_ context.Context, in *pb.ShowRollbackRequest, _ ...grpc.CallOption,
) (*pb.ShowRollbackResponse, error) {
	f.rollbackCalls++
	f.rollbackN = in.GetN()
	f.rollbackFmt = in.GetFormat()
	return &pb.ShowRollbackResponse{Output: "stub"}, nil
}

func (f *showPipeRecorderClient) ShowCompare(
	_ context.Context, in *pb.ShowCompareRequest, _ ...grpc.CallOption,
) (*pb.ShowCompareResponse, error) {
	f.compareCalls++
	f.compareN = in.GetRollbackN()
	return &pb.ShowCompareResponse{Output: "stub"}, nil
}

func (f *showPipeRecorderClient) ShowConfig(
	_ context.Context, in *pb.ShowConfigRequest, _ ...grpc.CallOption,
) (*pb.ShowConfigResponse, error) {
	f.configCalls++
	f.configFmt = in.GetFormat()
	f.configTarget = in.GetTarget()
	f.configPath = append([]string(nil), in.GetPath()...)
	return &pb.ShowConfigResponse{Output: "stub"}, nil
}

func (f *showPipeRecorderClient) totalCalls() int {
	return f.rollbackCalls + f.compareCalls + f.configCalls
}

func TestShowPipeModifierRejectsGarbage_13202(t *testing.T) {
	cases := []struct {
		name string
		run  func(c *ctl) error
	}{
		{"rollback display json unsupported", func(c *ctl) error {
			return c.handleShowSystem([]string{"rollback", "1", "|", "display", "json"})
		}},
		{"rollback substring compare token", func(c *ctl) error {
			return c.handleShowSystem([]string{"rollback", "1", "bogus_compare_token"})
		}},
		{"rollback bare bogus token", func(c *ctl) error {
			return c.handleShowSystem([]string{"rollback", "1", "bogus"})
		}},
		{"rollback display without pipe", func(c *ctl) error {
			return c.handleShowSystem([]string{"rollback", "1", "display", "set"})
		}},
		{"rollback duplicate compare", func(c *ctl) error {
			return c.handleShowSystem([]string{"rollback", "1", "|", "compare", "compare"})
		}},
		{"rollback trailing garbage after display", func(c *ctl) error {
			return c.handleShowSystem([]string{"rollback", "1", "|", "display", "set", "bogus"})
		}},
		{"op show configuration trailing garbage", func(c *ctl) error {
			return c.handleShow([]string{"configuration", "|", "display", "set", "bogus"})
		}},
		{"op show configuration unknown display", func(c *ctl) error {
			return c.handleShow([]string{"configuration", "|", "display", "yaml"})
		}},
		{"op show configuration unknown pipe", func(c *ctl) error {
			return c.handleShow([]string{"configuration", "|", "frobnicate"})
		}},
		{"config show path with compare", func(c *ctl) error {
			return c.handleConfigShow([]string{"interfaces", "|", "compare"})
		}},
		{"config show path with compare rollback", func(c *ctl) error {
			return c.handleConfigShow([]string{"interfaces", "|", "compare", "rollback", "1"})
		}},
		{"config show compare bogus", func(c *ctl) error {
			return c.handleConfigShow([]string{"|", "compare", "bogus"})
		}},
		{"config show compare rollback extra", func(c *ctl) error {
			return c.handleConfigShow([]string{"|", "compare", "rollback", "1", "extra"})
		}},
		{"config show trailing garbage after display", func(c *ctl) error {
			return c.handleConfigShow([]string{"interfaces", "|", "display", "set", "bogus"})
		}},
		{"config show unknown display", func(c *ctl) error {
			return c.handleConfigShow([]string{"|", "display", "yaml"})
		}},
		{"config show unknown pipe", func(c *ctl) error {
			return c.handleConfigShow([]string{"|", "frobnicate"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &showPipeRecorderClient{}
			c := configModeCtl(fake)
			if err := tc.run(c); err == nil {
				t.Fatalf("%s returned nil; expected rejection before any RPC", tc.name)
			}
			if fake.totalCalls() != 0 {
				t.Fatalf("%s issued %d RPCs (rollback=%d compare=%d config=%d); expected 0",
					tc.name, fake.totalCalls(), fake.rollbackCalls, fake.compareCalls, fake.configCalls)
			}
		})
	}
}

func TestShowPipeModifierAcceptsExact_13202(t *testing.T) {
	t.Run("rollback plain", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleShowSystem([]string{"rollback", "1"}); err != nil {
			t.Fatal(err)
		}
		if fake.rollbackCalls != 1 || fake.rollbackN != 1 || fake.rollbackFmt != pb.ConfigFormat_HIERARCHICAL {
			t.Fatalf("rollback calls=%d N=%d fmt=%v; want 1/1/HIERARCHICAL", fake.rollbackCalls, fake.rollbackN, fake.rollbackFmt)
		}
	})
	for name, tc := range map[string]struct {
		args []string
		fmt  pb.ConfigFormat
	}{
		"set": {[]string{"rollback", "1", "|", "display", "set"}, pb.ConfigFormat_SET},
		"xml": {[]string{"rollback", "1", "|", "display", "xml"}, pb.ConfigFormat_XML},
	} {
		t.Run("rollback display "+name, func(t *testing.T) {
			fake := &showPipeRecorderClient{}
			if err := configModeCtl(fake).handleShowSystem(tc.args); err != nil {
				t.Fatal(err)
			}
			if fake.rollbackCalls != 1 || fake.rollbackFmt != tc.fmt {
				t.Fatalf("rollback calls=%d fmt=%v; want 1/%v", fake.rollbackCalls, fake.rollbackFmt, tc.fmt)
			}
		})
	}
	t.Run("rollback pipe compare", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleShowSystem([]string{"rollback", "1", "|", "compare"}); err != nil {
			t.Fatal(err)
		}
		if fake.compareCalls != 1 || fake.compareN != 1 {
			t.Fatalf("compare calls=%d N=%d; want 1/1", fake.compareCalls, fake.compareN)
		}
	})
	t.Run("op show configuration display json with path", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleShow([]string{"configuration", "interfaces", "|", "display", "json"}); err != nil {
			t.Fatal(err)
		}
		if fake.configCalls != 1 || fake.configFmt != pb.ConfigFormat_JSON || fake.configTarget != pb.ConfigTarget_ACTIVE ||
			!reflect.DeepEqual(fake.configPath, []string{"interfaces"}) {
			t.Fatalf("config calls=%d fmt=%v target=%v path=%v", fake.configCalls, fake.configFmt, fake.configTarget, fake.configPath)
		}
	})
	t.Run("config show plain path", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleConfigShow([]string{"interfaces"}); err != nil {
			t.Fatal(err)
		}
		if fake.configCalls != 1 || fake.configTarget != pb.ConfigTarget_CANDIDATE ||
			!reflect.DeepEqual(fake.configPath, []string{"interfaces"}) {
			t.Fatalf("config calls=%d target=%v path=%v", fake.configCalls, fake.configTarget, fake.configPath)
		}
	})
	t.Run("config show display set with path", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleConfigShow([]string{"interfaces", "|", "display", "set"}); err != nil {
			t.Fatal(err)
		}
		if fake.configCalls != 1 || fake.configFmt != pb.ConfigFormat_SET ||
			!reflect.DeepEqual(fake.configPath, []string{"interfaces"}) {
			t.Fatalf("config calls=%d fmt=%v path=%v", fake.configCalls, fake.configFmt, fake.configPath)
		}
	})
	t.Run("config show compare", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleConfigShow([]string{"|", "compare"}); err != nil {
			t.Fatal(err)
		}
		if fake.compareCalls != 1 || fake.compareN != 0 {
			t.Fatalf("compare calls=%d N=%d; want 1/0", fake.compareCalls, fake.compareN)
		}
	})
	t.Run("config show compare rollback", func(t *testing.T) {
		fake := &showPipeRecorderClient{}
		if err := configModeCtl(fake).handleConfigShow([]string{"|", "compare", "rollback", "2"}); err != nil {
			t.Fatal(err)
		}
		if fake.compareCalls != 1 || fake.compareN != 2 {
			t.Fatalf("compare calls=%d N=%d; want 1/2", fake.compareCalls, fake.compareN)
		}
	})
}
