package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

type testRoutingRecorder12077 struct {
	pb.BpfrxServiceClient
	topics []string
}

func (f *testRoutingRecorder12077) ShowText(
	_ context.Context, in *pb.ShowTextRequest, _ ...grpc.CallOption,
) (*pb.ShowTextResponse, error) {
	f.topics = append(f.topics, in.GetTopic())
	return &pb.ShowTextResponse{Output: "lookup happened"}, nil
}

func TestRemoteTestRoutingRejectsMalformedSelectors12077(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"misspelled instance", []string{"destination", "10.1.2.3", "instnace", "dmz"}, "unknown selector \"instnace\""},
		{"unknown selector", []string{"destination", "10.1.2.3", "bogus"}, "unknown selector \"bogus\" (want \"destination <ip-or-prefix> [instance <name>]\")"},
		{"missing instance value", []string{"destination", "10.1.2.3", "instance"}, "selector \"instance\" requires a value"},
		{"missing destination value", []string{"destination"}, "selector \"destination\" requires a value"},
		{"empty instance value", []string{"destination", "10.1.2.3", "instance", ""}, "selector \"instance\" requires a value"},
		{"empty destination value", []string{"destination", ""}, "selector \"destination\" requires a value"},
		{"whitespace-only destination value", []string{"destination", " \t "}, "selector \"destination\" requires a value"},
		{"whitespace-only instance value", []string{"destination", "10.1.2.3", "instance", "  "}, "selector \"instance\" requires a value"},
		{"repeated destination", []string{"destination", "10.1.2.3", "destination", "10.9.9.9"}, "duplicate selector \"destination\""},
		{"repeated instance", []string{"destination", "10.1.2.3", "instance", "a", "instance", "b"}, "duplicate selector \"instance\""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &testRoutingRecorder12077{}
			c := &ctl{client: fake}
			err := c.testRouting(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("testRouting(%v) error = %v, want diagnostic containing %q", tc.args, err, tc.want)
			}
			if len(fake.topics) != 0 {
				t.Fatalf("testRouting(%v) issued lookup RPCs before rejecting input: %v", tc.args, fake.topics)
			}
		})
	}
}

func TestRemoteTestRoutingBuildsValidTopic12077(t *testing.T) {
	fake := &testRoutingRecorder12077{}
	c := &ctl{client: fake}
	if err := c.testRouting([]string{"destination", "10.1.2.3", "instance", "dmz"}); err != nil {
		t.Fatalf("testRouting valid instance query: %v", err)
	}
	if len(fake.topics) != 1 || fake.topics[0] != "test-routing:dest=10.1.2.3,instance=dmz" {
		t.Fatalf("topics = %v, want [test-routing:dest=10.1.2.3,instance=dmz]", fake.topics)
	}
}
