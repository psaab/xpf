// #3439 H5: the remote `show security flow session` parser must reject
// malformed/unknown filter tokens instead of silently dropping them.
// The historical loop used `if v, err := strconv.Parse...; err == nil`
// with no else (a bad numeric value left the field zero = wildcard,
// silently WIDENING the inspected traffic set) and had no default case
// (an unknown token fell through and was ignored). parseFlowSessionArgs
// now mirrors the strict local parser in pkg/cli/session_filter.go.
//
// FAIL-ON-REVERT: restoring the silent-drop loop makes the want-error
// cases below return nil and the assertions go RED.
//
// #9065 SPLIT THE `zone` ROW OUT, and the distinction matters. This table's
// claim — "a malformed value or an unknown token must not be silently dropped,
// because a dropped value leaves the field zero, which is the WILDCARD, and
// silently WIDENS the inspected set" — is unchanged and still true of every
// row that remains. What was folded into it was a second, separate claim
// carried only by `{"zone", "notanumber"}`: its inline reason read *"remote
// Zone is a numeric id"*, and that premise is wrong. pkg/cmdtree offers zone
// NAMES as the completion set for this exact path, the local console resolves
// the name, and the SAME binary's `clear security flow session zone` takes a
// string — so `zone trust` was rejected as malformed and the tree offered a
// completion this binary refused.
//
// The protected BEHAVIOUR did not move: a zone that cannot be resolved still
// refuses, and still issues no request, so it still cannot widen to the
// wildcard. Only the LAYER moved, from parse time to resolve time, because
// resolution needs a GetZones round trip a pure parser must not make. That
// half is asserted in TestFlowSessionUnknownZoneDoesNotWiden9065 and
// TestFlowSessionZoneWithNoRuntimeIDRefused9065 — three states (valid name,
// unknown name, name with no runtime id) needing three signals, which a single
// parse-time row could not carry.
package main

import "testing"

func TestParseFlowSessionArgsRejectsMalformed(t *testing.T) {
	wantErr := [][]string{
		{"destination-port", "abc"}, // unparseable numeric → was wildcard
		{"source-port", "abc"},
		{"source-port", "0"}, // out of 1-65535
		{"destination-port", "70000"},
		{"protocol", "tcpip"},                  // unknown protocol token
		{"protocol", "+6"},                     // signed numerics are non-canonical
		{"protocol", " 6"},                     // whitespace-padded numerics are non-canonical
		{"limit", "0"},                         // non-positive limit
		{"bogus-token"},                        // unknown filter keyword
		{"destination-port"},                   // missing value
		{"summary", "destination-port", "abc"}, // malformed after a terminal subcmd
		// A filter combined with a global aggregation (summary/sort-by)
		// was parsed and then silently ignored — reject it instead
		// (#3439 Codex MAJOR fold).
		{"summary", "protocol", "tcp"},
		{"protocol", "tcp", "summary"},
		{"sort-by", "bytes", "destination-port", "443"},
		{"zone", "1", "sort-by", "packets"},
	}
	for _, args := range wantErr {
		if _, err := parseFlowSessionArgs(args); err == nil {
			t.Errorf("parseFlowSessionArgs(%v) = nil error; want a rejection", args)
		}
	}

	// `ipv6` is a protocol the system DISPLAYS (proto 41); it must be
	// accepted as a filter, not rejected (#3439 / Refs #3393 regression).
	if p, err := parseFlowSessionArgs([]string{"protocol", "ipv6"}); err != nil {
		t.Errorf("parseFlowSessionArgs(protocol ipv6) = %v; want accepted", err)
	} else if p.req.Protocol != "IPV6" {
		t.Errorf("protocol ipv6: req.Protocol = %q; want IPV6", p.req.Protocol)
	}

	for _, tc := range []struct {
		token string
		want  string
	}{
		{"007", "007"},
		{" tcp ", " TCP "},
	} {
		p, err := parseFlowSessionArgs([]string{"protocol", tc.token})
		if err != nil {
			t.Errorf("parseFlowSessionArgs(protocol %q) = %v; want accepted", tc.token, err)
		} else if p.req.Protocol != tc.want {
			t.Errorf("protocol %q: req.Protocol = %q; want %q", tc.token, p.req.Protocol, tc.want)
		}
	}

	// summary / sort-by WITHOUT a filter still work (brief is a display
	// modifier, not a filter, so it may accompany them).
	if _, err := parseFlowSessionArgs([]string{"summary", "brief"}); err != nil {
		t.Errorf("summary brief: unexpected error %v", err)
	}

	// Valid filters parse and populate the request.
	p, err := parseFlowSessionArgs([]string{
		"destination-port", "80", "protocol", "tcp", "source-port", "1024",
	})
	if err != nil {
		t.Fatalf("valid filter rejected: %v", err)
	}
	if p.req.DestinationPort != 80 || p.req.SourcePort != 1024 {
		t.Errorf("ports = src %d dst %d; want 1024/80", p.req.SourcePort, p.req.DestinationPort)
	}
	if p.req.Protocol != "TCP" {
		t.Errorf("protocol = %q; want TCP", p.req.Protocol)
	}
	if p.action != flowSessionList {
		t.Errorf("action = %v; want flowSessionList", p.action)
	}

	// Terminal subcommands are recognized.
	sum, err := parseFlowSessionArgs([]string{"summary"})
	if err != nil || sum.action != flowSessionSummary {
		t.Errorf("summary: action %v err %v; want flowSessionSummary", sum.action, err)
	}
	sort, err := parseFlowSessionArgs([]string{"sort-by", "bytes"})
	if err != nil || sort.action != flowSessionSortBy || sort.sortKey != "bytes" {
		t.Errorf("sort-by: action %v key %q err %v", sort.action, sort.sortKey, err)
	}
}
