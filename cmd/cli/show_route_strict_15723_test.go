package main

import (
	"strings"
	"testing"
)

// #15723: the remote dispatcher must reject dangling selectors, unknown
// subcommands and unrecognised trailing filters in `show route` instead of
// widening to the full-table dump (route-all via showRoutes) or silently
// dropping trailing tokens. No ShowText RPC may be issued for a rejected
// form.
//
// RED on base: handleShow(["route","table"]) returned showRoutes()
// (topic "route-all"); ["route","terse","junk"] issued "route-terse";
// ["route","10.0.0.0/24","bogus"] issued "route-prefix:10.0.0.0/24".

func TestRemoteShowRouteRejectsDanglingAndUnknown15723(t *testing.T) {
	cases := [][]string{
		{"route", "table"},
		{"route", "instance"},
		{"route", "protocol"},
		{"route", "bogusword"},
		{"route", "terse", "junk"},
		{"route", "summary", "junk"},
		{"route", "detail", "junk"},
		{"route", "fib", "junk"},
		{"route", "table", "inet.0", "junk"},
		{"route", "table", "inet.0", "protocol", "bgp"},
		{"route", "instance", "blue", "junk"},
		{"route", "protocol", "static", "junk"},
		{"route", "10.0.0.0/24", "bogus"},
		{"route", "10.0.0.0/24", "exact", "junk"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := &requestParityRecorder{}
			c := &ctl{client: fake}
			err := c.handleShow(args)
			if err == nil {
				t.Fatalf("handleShow(%v) must error, got nil; topics=%v", args, fake.showTopics)
			}
			if !strings.Contains(err.Error(), "usage: show route") {
				t.Errorf("error must carry usage, got: %v", err)
			}
			if len(fake.showTopics) != 0 {
				t.Errorf("rejected form must not issue ShowText, got topics %v", fake.showTopics)
			}
		})
	}
}

func TestRemoteShowRouteValidFormsStillRender15723(t *testing.T) {
	valid := []struct {
		args []string
		want string // expected topic, or "route-instance:blue" for filtered form
	}{
		{[]string{"route"}, "route-all"},
		{[]string{"route", "terse"}, "route-terse"},
		{[]string{"route", "detail"}, "route-detail"},
		{[]string{"route", "summary"}, "route-summary"},
		{[]string{"route", "fib"}, "route-fib"},
		{[]string{"route", "table", "inet.0"}, "route-table:inet.0"},
		{[]string{"route", "protocol", "static"}, "route-protocol:static"},
		{[]string{"route", "10.1.0.0/24"}, "route-prefix:10.1.0.0/24"},
		{[]string{"route", "10.1.0.0/24", "exact"}, "route-prefix:10.1.0.0/24 exact"},
		{[]string{"route", "10.0.0.0/8", "longer"}, "route-prefix:10.0.0.0/8 longer"},
		{[]string{"route", "10.0.0.0/8", "orlonger"}, "route-prefix:10.0.0.0/8 orlonger"},
	}
	for _, tc := range valid {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			fake := &requestParityRecorder{}
			c := &ctl{client: fake}
			if err := c.handleShow(tc.args); err != nil {
				t.Fatalf("handleShow(%v): %v", tc.args, err)
			}
			if len(fake.showTopics) != 1 || fake.showTopics[0] != tc.want {
				t.Errorf("handleShow(%v) topics = %v, want [%s]", tc.args, fake.showTopics, tc.want)
			}
		})
	}
	// instance carries its value in the Filter field, not the topic.
	fake := &requestParityRecorder{}
	c := &ctl{client: fake}
	if err := c.handleShow([]string{"route", "instance", "blue"}); err != nil {
		t.Fatalf("handleShow(route instance blue): %v", err)
	}
	if len(fake.showTopics) != 1 || fake.showTopics[0] != "route-instance" {
		t.Errorf("instance topics = %v, want [route-instance]", fake.showTopics)
	}
}
