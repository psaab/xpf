package main

import (
	"testing"
)

func TestRemoteShowRouteFibRequestsHelperTopic11370(t *testing.T) {
	fake := &requestParityRecorder{}
	c := &ctl{client: fake}
	if err := c.handleShow([]string{"route", "fib"}); err != nil {
		t.Fatalf("show route fib: %v", err)
	}
	if len(fake.showTopics) != 1 || fake.showTopics[0] != "route-fib" {
		t.Fatalf("ShowText topics = %v, want exactly [route-fib]", fake.showTopics)
	}
}
