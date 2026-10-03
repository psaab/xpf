package main

import (
	"strings"
	"testing"
)

// #6848/#6858: remote-CLI topic encoding for `show class-of-service
// classifier|rewrite-rule`.
//
// The GRAMMAR and the round-trip property are tested once, in pkg/cmdtree
// (TestParseCoSNameTypeArgs6848 / TestCoSNameTypeTopicRoundTrip6858). This file
// asserts the WIRING: that the remote dispatcher's topic builder really routes
// through cmdtree rather than carrying a private copy of the grammar, which is
// what it did before #6858 — and that copy had already drifted from the local
// one.
func TestCoSNameTypeTopic6848(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"empty", nil, "cos-rewrite-rule"},
		{"bare name", []string{"rw-dscp"}, "cos-rewrite-rule:name=rw-dscp"},
		{"keyword name", []string{"name", "rw-dscp"}, "cos-rewrite-rule:name=rw-dscp"},
		{"keyword type", []string{"type", "dscp"}, "cos-rewrite-rule:type=dscp"},
		{"both keywords", []string{"name", "rw-pcp", "type", "ieee-802.1"},
			"cos-rewrite-rule:name=rw-pcp,type=ieee-802.1"},
		{"bare name then type", []string{"rw-pcp", "type", "ieee-802.1"},
			"cos-rewrite-rule:name=rw-pcp,type=ieee-802.1"},
		{"keyword overrides bare", []string{"rw-dscp", "name", "rw-pcp"},
			"cos-rewrite-rule:name=rw-pcp"},
		{"comma in name", []string{"rw,x"}, "cos-rewrite-rule:name=rw%2Cx"},
		{"comma in name with type", []string{"name", "rw,x", "type", "dscp"},
			"cos-rewrite-rule:name=rw%2Cx,type=dscp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cosNameTypeTopic("cos-rewrite-rule", tc.args)
			if err != nil {
				t.Fatalf("cosNameTypeTopic(%q) error = %v", tc.args, err)
			}
			if got != tc.want {
				t.Errorf("cosNameTypeTopic(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}

	// The builder is shared with the classifier command; the prefix is the only
	// difference. #6858 fixed the encoding for BOTH — the classifier command
	// carried the same truncation since #4228, and they share one decoder.
	if got, err := cosNameTypeTopic("cos-classifier", []string{"type", "dscp"}); err != nil || got != "cos-classifier:type=dscp" {
		t.Errorf("classifier prefix = (%q, %v), want cos-classifier:type=dscp", got, err)
	}
	if got, err := cosNameTypeTopic("cos-classifier", []string{"c,1"}); err != nil || got != "cos-classifier:name=c%2C1" {
		t.Errorf("classifier comma name = (%q, %v), want cos-classifier:name=c%%2C1", got, err)
	}
}

func TestCoSNameTypeTopicRejectsUnknownAndDangling11834(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown token", []string{"name", "rw-dscp", "naem"}, `unknown argument "naem"`},
		{"dangling name", []string{"name"}, `missing value for "name"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			topic, err := cosNameTypeTopic("cos-rewrite-rule", tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("cosNameTypeTopic(%q) = (%q, %v), want error containing %q",
					tc.args, topic, err, tc.want)
			}
		})
	}
}

func TestRemoteShowCoSFiltersFailClosed11834(t *testing.T) {
	c := &ctl{}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"rewrite-rule unknown", []string{"class-of-service", "rewrite-rule", "name", "rw-dscp", "naem"}, `unknown argument "naem"`},
		{"rewrite-rule dangling", []string{"class-of-service", "rewrite-rule", "name"}, `missing value for "name"`},
		{"classifier unknown", []string{"class-of-service", "classifier", "name", "cl", "naem"}, `unknown argument "naem"`},
		{"classifier dangling", []string{"class-of-service", "classifier", "name"}, `missing value for "name"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.handleShow(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("handleShow(%q) error = %v, want containing %q", tc.args, err, tc.want)
			}
		})
	}
}
