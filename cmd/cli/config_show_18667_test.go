// Tests for #18667: remote config-mode `show` accepted a `|` glued to
// adjacent text (`show interfaces|display set` reached ShowConfig as a
// SET render instead of refusing the malformed pipe), and every scoped
// `configuration path not found` answer returned nil, so `cli -c` exited
// 0 for a path that does not exist.
//
// Glued forms: a TokenPipe with non-whitespace on either side of the raw
// line is not the pipe operator. Spaced bare pipes stay valid (the #16790
// and #13202 controls pin that). Not-found forms: operational
// `show configuration <path>`, config-mode `show <path>`, and scoped
// `show system rollback <N> <path> | display ...` must return an error
// when the server renders nothing for a non-empty path, so the -c exit
// status is 1. Unscoped empty renders stay successful (an empty rollback
// or configuration is a legitimate answer, not a miss).
//
// RED-on-revert: without the adjacency check the glued rows issue the
// display RPC and return nil; without the error returns the not-found
// rows return nil.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

type configShow18667Client struct {
	pb.BpfrxServiceClient

	configCalls   int
	configPath    []string
	configFormat  pb.ConfigFormat
	compareCalls  int
	rollbackCalls int
	rollbackPath  []string
}

func (f *configShow18667Client) ShowCompare(
	_ context.Context, _ *pb.ShowCompareRequest, _ ...grpc.CallOption,
) (*pb.ShowCompareResponse, error) {
	f.compareCalls++
	return &pb.ShowCompareResponse{Output: ""}, nil
}

func (f *configShow18667Client) totalCalls() int {
	return f.configCalls + f.compareCalls + f.rollbackCalls
}

func (f *configShow18667Client) ShowConfig(
	_ context.Context, in *pb.ShowConfigRequest, _ ...grpc.CallOption,
) (*pb.ShowConfigResponse, error) {
	f.configCalls++
	f.configPath = append([]string(nil), in.GetPath()...)
	f.configFormat = in.GetFormat()
	return &pb.ShowConfigResponse{Output: ""}, nil
}

func (f *configShow18667Client) ShowRollback(
	_ context.Context, in *pb.ShowRollbackRequest, _ ...grpc.CallOption,
) (*pb.ShowRollbackResponse, error) {
	f.rollbackCalls++
	f.rollbackPath = append([]string(nil), in.GetPath()...)
	return &pb.ShowRollbackResponse{Output: ""}, nil
}

func TestConfigShowGluedPipeRefused18667(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"glued after path", `show interfaces|display set`},
		{"glued before pipe word", `show interfaces |display set`},
		{"glued both sides of pipe", `show interfaces| display set`},
		{"glued compare", `show interfaces|compare`},
		{"glued to quoted path", `show "lan in"|display set`},
		{"comment-glued pipe", `show interfaces /*x*/|display set`},
		{"comment-glued pipe with spaced modifier", `show interfaces /*x*/| display set`},
	}
	t.Run("hint preserves quoted whitespace", func(t *testing.T) {
		fake := &configShow18667Client{}
		err := configModeCtl(fake).dispatchConfig(`show "lan  in"|display set`)
		if err == nil || !strings.Contains(err.Error(), "separate the pipe with spaces") {
			t.Fatalf("dispatchConfig returned err = %v; want glued-pipe hint (#18667)", err)
		}
		if !strings.Contains(err.Error(), "lan  in") || strings.Contains(err.Error(), "lan in") {
			t.Fatalf("hint lost quoted whitespace: %v", err)
		}
		if fake.totalCalls() != 0 {
			t.Fatalf("glued pipe issued %d RPC calls; want 0 (#18667)", fake.totalCalls())
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &configShow18667Client{}
			c := configModeCtl(fake)
			err := c.dispatchConfig(tc.line)
			if err == nil {
				t.Fatalf("dispatchConfig(%q) returned nil; want glued-pipe refusal before any RPC (#18667)", tc.line)
			}
			if !strings.Contains(err.Error(), "separate the pipe with spaces") {
				t.Fatalf("dispatchConfig(%q) err = %v; want the glued-pipe hint (#18667)", tc.line, err)
			}
			if fake.totalCalls() != 0 {
				t.Fatalf("dispatchConfig(%q) issued %d RPC calls; want 0 (#18667)", tc.line, fake.totalCalls())
			}
		})
	}
}

func TestScopedConfigShowNotFoundErrors18667(t *testing.T) {
	t.Run("config mode scoped path", func(t *testing.T) {
		fake := &configShow18667Client{}
		c := configModeCtl(fake)
		err := c.handleConfigShow([]string{"system", "ntp"}, nil)
		if err == nil {
			t.Fatal("scoped config show with empty render returned nil; want not-found error (#18667)")
		}
		if !strings.Contains(err.Error(), "configuration path not found: system ntp") {
			t.Fatalf("err = %v; want configuration path not found (#18667)", err)
		}
		if fake.configCalls != 1 {
			t.Fatalf("config calls = %d; want 1 (#18667)", fake.configCalls)
		}
	})

	t.Run("operational scoped path", func(t *testing.T) {
		fake := &configShow18667Client{}
		c := configModeCtl(fake)
		err := c.handleShow([]string{"configuration", "system", "ntp"})
		if err == nil {
			t.Fatal("scoped operational show configuration with empty render returned nil; want not-found error (#18667)")
		}
		if !strings.Contains(err.Error(), "configuration path not found: system ntp") {
			t.Fatalf("err = %v; want configuration path not found (#18667)", err)
		}
	})

	t.Run("scoped rollback path", func(t *testing.T) {
		fake := &configShow18667Client{}
		c := configModeCtl(fake)
		err := c.handleShowSystem([]string{"rollback", "1", "system", "ntp", "|", "display", "set"})
		if err == nil {
			t.Fatal("scoped rollback show with empty render returned nil; want not-found error (#18667)")
		}
		if !strings.Contains(err.Error(), "configuration path not found: system ntp") {
			t.Fatalf("err = %v; want configuration path not found (#18667)", err)
		}
		if fake.rollbackCalls != 1 {
			t.Fatalf("rollback calls = %d; want 1 (#18667)", fake.rollbackCalls)
		}
	})

	// Unscoped empty renders are legitimate answers, not misses.
	t.Run("config mode unscoped empty stays nil", func(t *testing.T) {
		fake := &configShow18667Client{}
		c := configModeCtl(fake)
		if err := c.handleConfigShow(nil, nil); err != nil {
			t.Fatalf("unscoped config show err = %v; want nil (#18667)", err)
		}
	})
	t.Run("operational unscoped empty stays nil", func(t *testing.T) {
		fake := &configShow18667Client{}
		c := configModeCtl(fake)
		if err := c.handleShow([]string{"configuration"}); err != nil {
			t.Fatalf("unscoped operational show configuration err = %v; want nil (#18667)", err)
		}
	})
	t.Run("unscoped rollback empty stays nil", func(t *testing.T) {
		fake := &configShow18667Client{}
		c := configModeCtl(fake)
		if err := c.handleShowSystem([]string{"rollback", "1"}); err != nil {
			t.Fatalf("unscoped rollback err = %v; want nil (#18667)", err)
		}
	})
}
