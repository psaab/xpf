package main

import (
	"strings"
	"testing"
)

func TestRequestDynamicAddressShrinkAckRejectsMalformedGrammar11059(t *testing.T) {
	valid := []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "41", "reason", "reviewed"}
	cases := []struct {
		name string
		args []string
	}{
		{name: "missing feed", args: []string{"security", "dynamic-address", "acknowledge-shrink", "candidate-id", "41", "reason", "reviewed"}},
		{name: "wrong candidate keyword", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate", "41", "reason", "reviewed"}},
		{name: "non-numeric ID", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "nope", "reason", "reviewed"}},
		{name: "zero ID", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "0", "reason", "reviewed"}},
		{name: "signed ID", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "+41", "reason", "reviewed"}},
		{name: "overflow ID", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "18446744073709551616", "reason", "reviewed"}},
		{name: "wrong reason keyword", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "41", "because", "reviewed"}},
		{name: "missing reason", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "41", "reason"}},
		{name: "empty reason", args: []string{"security", "dynamic-address", "acknowledge-shrink", "threats", "candidate-id", "41", "reason", "  "}},
		{name: "overlong reason", args: append(append([]string(nil), valid[:7]...), strings.Repeat("x", 513))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &ctl{}
			if err := c.handleRequest(tc.args); err == nil {
				t.Fatalf("handleRequest(%v) accepted malformed acknowledgement", tc.args)
			}
		})
	}
}
