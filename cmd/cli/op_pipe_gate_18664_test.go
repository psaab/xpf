package main

// #18664: operational `show configuration | display set` was refused by the
// remote cli as `unknown show configuration command: |`.
//
// The #16798 keyword-only gate ran cmdtree.ValidateOperationalLine over the
// WHOLE line. `show configuration` is a keyword-only node, so the bare `|` was
// judged as an unknown trailing keyword under it and refused before
// handleShow's `configuration` arm, which parses the pipe itself, could run.
// Output filters were unaffected because dispatch peels them with
// cliterm.SplitPipe first; the handler-level `| display <fmt>` pipe was not.
//
// Fix: validateOperationalLine judges only the words before the first bare
// `|` (showPipeIndex, the handlers' own token rule). A pipe directly under a
// keyword-only node is admitted only for an operationalPipeConsumers command,
// so #16798's refusal of help-printing / pipe-dropping handlers stays.
//
// Every cell drives c.dispatch, the full entry path (SplitPipe filter peel ->
// dispatchOperational -> gate -> handler). The pre-existing #13202 cells call
// handleShow directly, below the gate, which is why they stayed green while
// the gate refused every operator-typed line.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

const cfgOut18664 = "set system host-name fw0\nset interfaces ge-0/0/0 unit 0\n"

// Junos supports operational `show configuration | compare [rollback <N>]`;
// xpf does not, so the refusal must say that rather than call `compare` an
// unknown pipe command.
const opCompareUnsupported18664 = "syntax error: `| compare` is not supported on " +
	"operational `show configuration`; use configuration mode " +
	"(`configure`, then `show | compare [rollback <N>]`)"

// rec18664 records the RPCs a dispatched line issues. Any RPC it does not
// override nil-panics, which fails the cell: a refusal must happen before the
// wire, and an accepted line must issue only the RPC its cell expects.
type rec18664 struct {
	pb.BpfrxServiceClient
	config   []*pb.ShowConfigRequest
	rollback []*pb.ShowRollbackRequest
	text     []string
}

func (f *rec18664) ShowConfig(_ context.Context, in *pb.ShowConfigRequest, _ ...grpc.CallOption) (*pb.ShowConfigResponse, error) {
	f.config = append(f.config, in)
	return &pb.ShowConfigResponse{Output: cfgOut18664}, nil
}

func (f *rec18664) ShowRollback(_ context.Context, in *pb.ShowRollbackRequest, _ ...grpc.CallOption) (*pb.ShowRollbackResponse, error) {
	f.rollback = append(f.rollback, in)
	return &pb.ShowRollbackResponse{Output: "rollback\n"}, nil
}

func (f *rec18664) ShowText(_ context.Context, in *pb.ShowTextRequest, _ ...grpc.CallOption) (*pb.ShowTextResponse, error) {
	f.text = append(f.text, in.GetTopic())
	return &pb.ShowTextResponse{Output: "node0 primary\nnode1 secondary\nother line\n"}, nil
}

func (f *rec18664) calls() int { return len(f.config) + len(f.rollback) + len(f.text) }

func dispatch18664(t *testing.T, line string, configMode bool) (*rec18664, string, error) {
	t.Helper()
	f := &rec18664{}
	c := &ctl{client: f}
	c.configMode.Store(configMode)
	var err error
	out := captureStdout(t, func() { err = c.dispatch(line) })
	return f, out, err
}

// Defect cells: the handler-parsed display pipe on operational `show
// configuration` reaches ShowConfig(ACTIVE) with the requested format. Each
// one is refused pre-fix with `unknown show configuration command: |`.
func TestOpShowConfigurationDisplayPipe18664(t *testing.T) {
	for _, tc := range []struct {
		line       string
		configMode bool
		format     pb.ConfigFormat
		wantOut    string
	}{
		{"show configuration | display set", false, pb.ConfigFormat_SET, cfgOut18664},
		{"show configuration | display json", false, pb.ConfigFormat_JSON, cfgOut18664},
		{"show configuration | display xml", false, pb.ConfigFormat_XML, cfgOut18664},
		{"show configuration | display inheritance", false, pb.ConfigFormat_INHERITANCE, cfgOut18664},
		// Chained: dispatch peels the trailing filter, the display pipe
		// reaches the gate. The filter must still be applied.
		{"show configuration | display set | match host", false, pb.ConfigFormat_SET, "set system host-name fw0\n"},
		{"show configuration | display json | count", false, pb.ConfigFormat_JSON, "Count: 2 lines\n"},
		// Config mode `run` re-enters dispatchOperational.
		{"run show configuration | display set", true, pb.ConfigFormat_SET, cfgOut18664},
	} {
		t.Run(tc.line, func(t *testing.T) {
			f, out, err := dispatch18664(t, tc.line, tc.configMode)
			if err != nil {
				t.Fatalf("dispatch(%q) = %v; want ShowConfig(%v)", tc.line, err, tc.format)
			}
			if len(f.config) != 1 || f.calls() != 1 {
				t.Fatalf("dispatch(%q) issued config=%d total=%d RPCs; want exactly one ShowConfig", tc.line, len(f.config), f.calls())
			}
			req := f.config[0]
			if req.GetFormat() != tc.format || req.GetTarget() != pb.ConfigTarget_ACTIVE || len(req.GetPath()) != 0 {
				t.Fatalf("dispatch(%q) ShowConfig format=%v target=%v path=%v; want %v/ACTIVE/[]",
					tc.line, req.GetFormat(), req.GetTarget(), req.GetPath(), tc.format)
			}
			if out != tc.wantOut {
				t.Fatalf("dispatch(%q) output %q; want %q", tc.line, out, tc.wantOut)
			}
		})
	}
}

// Pipes on other commands. The filter and AcceptsArgs rows are CONTROLS: they
// were never refused (dispatch peels a trailing filter before the gate, and
// the gate does not judge a pipe after an AcceptsArgs tail), so they cannot
// fail on revert. They pin that the pipe-aware gate does not break them. The
// keyword-only `| display json` rows are revert-sensitive by message: still
// refused, but naming the modifier instead of `unknown ... command: |`.
func TestOpPipeOnOtherCommands18664(t *testing.T) {
	t.Run("show chassis cluster status | match node", func(t *testing.T) {
		f, out, err := dispatch18664(t, "show chassis cluster status | match node", false)
		if err != nil || !reflect.DeepEqual(f.text, []string{"chassis-cluster-status"}) {
			t.Fatalf("err=%v topics=%v; want ShowText(chassis-cluster-status)", err, f.text)
		}
		if out != "node0 primary\nnode1 secondary\n" {
			t.Fatalf("output %q; want only the matching lines", out)
		}
	})
	t.Run("show route | count", func(t *testing.T) {
		f, out, err := dispatch18664(t, "show route | count", false)
		if err != nil || !reflect.DeepEqual(f.text, []string{"route-all"}) {
			t.Fatalf("err=%v topics=%v; want ShowText(route-all)", err, f.text)
		}
		if out != "Count: 3 lines\n" {
			t.Fatalf("output %q; want Count: 3 lines", out)
		}
	})
	t.Run("show configuration | match host", func(t *testing.T) {
		f, out, err := dispatch18664(t, "show configuration | match host", false)
		if err != nil || len(f.config) != 1 || f.config[0].GetFormat() != pb.ConfigFormat_HIERARCHICAL {
			t.Fatalf("err=%v config=%v; want one HIERARCHICAL ShowConfig", err, f.config)
		}
		if out != "set system host-name fw0\n" {
			t.Fatalf("output %q; want the matching line", out)
		}
	})
	t.Run("show configuration interfaces | display json", func(t *testing.T) {
		f, _, err := dispatch18664(t, "show configuration interfaces | display json", false)
		if err != nil || len(f.config) != 1 || f.config[0].GetFormat() != pb.ConfigFormat_JSON ||
			!reflect.DeepEqual(f.config[0].GetPath(), []string{"interfaces"}) {
			t.Fatalf("err=%v config=%v; want ShowConfig(JSON, [interfaces])", err, f.config)
		}
	})
	t.Run("show system rollback 1 | display json", func(t *testing.T) {
		f, _, err := dispatch18664(t, "show system rollback 1 | display json", false)
		if err != nil || len(f.rollback) != 1 || f.rollback[0].GetFormat() != pb.ConfigFormat_JSON || f.rollback[0].GetN() != 1 {
			t.Fatalf("err=%v rollback=%v; want ShowRollback(1, JSON)", err, f.rollback)
		}
	})
	for _, tc := range []struct{ line, want string }{
		{"show chassis cluster | display json", `syntax error: "show chassis cluster" does not accept the output modifier "| display json"`},
		{"show security policies | display json", `syntax error: "show security policies" does not accept the output modifier "| display json"`},
	} {
		t.Run(tc.line, func(t *testing.T) {
			f, _, err := dispatch18664(t, tc.line, false)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if f.calls() != 0 {
				t.Fatalf("dispatch(%q) issued %d RPCs; want refusal before the wire", tc.line, f.calls())
			}
		})
	}
}

// #16798 protection kept: an unknown token BEFORE the pipe refuses exactly as
// the pipe-less line does, and a pipe directly under a keyword-only node whose
// handler does not parse pipes still refuses. On master those pipe rows were
// already refused (exit 1, `unknown <path> command: |`); only the message
// changed. Admitting them would hand the pipe to a handler that prints help or
// runs the bare command and drops the modifier, exiting 0. These are the cells
// that kill a fix which simply skips the gate when a pipe is present, or which
// validates only the pre-pipe words.
func TestOpPipeKeepsKeywordOnlyRefusal18664(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"show configuration bogus | display set", "unknown show configuration command: bogus"},
		{"clear security ike | display set", "unknown clear security command: ike"},
		{"request system software add | display set", "unknown request system software command: add"},
		{"show chassis bogus | match x", "unknown show chassis command: bogus"},
		{"clear security | display set", `syntax error: "clear security" does not accept the output modifier "| display set"`},
		{"request chassis cluster | display set", `syntax error: "request chassis cluster" does not accept the output modifier "| display set"`},
		{"show chassis | display set", `syntax error: "show chassis" does not accept the output modifier "| display set"`},
		{"show security | display set", `syntax error: "show security" does not accept the output modifier "| display set"`},
		{"show | display set", `syntax error: "show" does not accept the output modifier "| display set"`},
	} {
		t.Run(tc.line, func(t *testing.T) {
			f, _, err := dispatch18664(t, tc.line, false)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if f.calls() != 0 {
				t.Fatalf("dispatch(%q) issued %d RPCs; want refusal before the wire", tc.line, f.calls())
			}
		})
	}
	// The pipe-less twin of the first row refuses with the same error.
	if _, _, err := dispatch18664(t, "show configuration bogus", false); err == nil ||
		err.Error() != "unknown show configuration command: bogus" {
		t.Fatalf("pipe-less twin = %v", err)
	}
}

// An invalid pipe after `show configuration` reaches the handler and fails
// there, naming what is wrong, never as `unknown show configuration command`.
func TestOpShowConfigurationBadPipe18664(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"show configuration | frobnicate", `syntax error: unknown pipe command "frobnicate"`},
		{"show configuration | compare", opCompareUnsupported18664},
		{"show configuration | compare rollback 1", opCompareUnsupported18664},
		{"show configuration interfaces | compare", opCompareUnsupported18664},
		{"show configuration | display yaml", `unknown display format "yaml"`},
		{"show configuration | display set bogus", "usage: | display <supported-format>"},
		{"show configuration |", "syntax error: missing pipe modifier"},
		{"show configuration | match a | display set", "syntax error: only one pipe modifier is allowed"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			f, _, err := dispatch18664(t, tc.line, false)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if f.calls() != 0 {
				t.Fatalf("dispatch(%q) issued %d RPCs; want refusal before the wire", tc.line, f.calls())
			}
		})
	}
}

// A `|` glued to a word is not the pipe operator on any surface (showPipeIndex,
// cliterm.SplitPipe, pkg/cli splitAtPipe all need a bare `|` word), so the
// glued token is an unknown command word. It must refuse with no RPC, and the
// message says how to write the pipe.
func TestOpGluedPipeRefusedWithHint18664(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"show configuration |display set", `unknown show configuration command: |display (separate the pipe with spaces: "| display")`},
		{"show configuration|display set", `unknown show command: configuration|display (separate the pipe with spaces: "configuration | display")`},
	} {
		t.Run(tc.line, func(t *testing.T) {
			f, _, err := dispatch18664(t, tc.line, false)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if f.calls() != 0 {
				t.Fatalf("dispatch(%q) issued %d RPCs; want refusal before the wire", tc.line, f.calls())
			}
		})
	}
}

// Every operationalPipeConsumers entry must really reach an RPC with the
// display format applied. A stale entry would admit a pipe whose handler
// drops it.
func TestOperationalPipeConsumers18664(t *testing.T) {
	if len(operationalPipeConsumers) == 0 {
		t.Fatal("operationalPipeConsumers is empty; `show configuration` must be listed")
	}
	for path := range operationalPipeConsumers {
		line := path + " | display set"
		f, _, err := dispatch18664(t, line, false)
		if err != nil {
			t.Fatalf("consumer %q: dispatch(%q) = %v", path, line, err)
		}
		gotSet := false
		for _, r := range f.config {
			gotSet = gotSet || r.GetFormat() == pb.ConfigFormat_SET
		}
		for _, r := range f.rollback {
			gotSet = gotSet || r.GetFormat() == pb.ConfigFormat_SET
		}
		if !gotSet || strings.TrimSpace(path) == "" {
			t.Fatalf("consumer %q: no RPC carried the SET format (config=%v rollback=%v)", path, f.config, f.rollback)
		}
	}
}
