package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestGroupWantsCategory is the pure-logic guard for the #5522 trap-group
// category filter. A group with no categories receives every category (the
// Junos default); a scoped group receives only its listed categories, matched
// case-insensitively.
func TestGroupWantsCategory(t *testing.T) {
	cases := []struct {
		name       string
		categories []string
		cat        string
		want       bool
	}{
		{"nil = all", nil, snmpCategoryLink, true},
		{"empty = all", []string{}, snmpCategoryLink, true},
		{"exact match", []string{"link"}, snmpCategoryLink, true},
		{"case-insensitive", []string{"LINK"}, snmpCategoryLink, true},
		{"whitespace trimmed", []string{" link "}, snmpCategoryLink, true},
		{"one of several", []string{"configuration", "link"}, snmpCategoryLink, true},
		{"excluded", []string{"configuration"}, snmpCategoryLink, false},
		{"excluded multi", []string{"configuration", "routing"}, snmpCategoryLink, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tg := &config.SNMPTrapGroup{Name: "g", Categories: tc.categories}
			if got := groupWantsCategory(tg, tc.cat); got != tc.want {
				t.Fatalf("groupWantsCategory(%v, %q) = %v, want %v", tc.categories, tc.cat, got, tc.want)
			}
		})
	}
	if groupWantsCategory(nil, snmpCategoryLink) {
		t.Fatal("groupWantsCategory(nil, ...) = true, want false for a nil group")
	}
}

// linkTrapDelivered sets up a single trap group scoped to categories, fires a
// linkDown, and reports whether the group's UDP target actually received a
// trap within a short window. It is the end-to-end seam for the #5522 dispatch
// gate: the group is skipped BEFORE the async enqueue, so an excluded category
// yields a read timeout (no packet), while an included/empty scope delivers.
func linkTrapDelivered(t *testing.T, categories []string) bool {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()

	a := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only"},
			},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"g": {Name: "g", Targets: []string{addr}, Categories: categories},
			},
		},
		startTime: time.Now().Add(-10 * time.Second),
	}
	a.NotifyLinkDown(3, "ge-0-0-1", true)

	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	_, _, err = pc.ReadFrom(buf)
	return err == nil
}

// TestSendLinkTraps_CategoryFilter is the config->emit RED-on-revert guard for
// #5522. A trap-group scoped to categories that EXCLUDE link must receive NO
// linkUp/linkDown trap; a group scoped to include link (or with no categories =
// all, the Junos default) must receive it. Before the fix the compiler
// discarded `categories` and sendLinkTraps had no category guard, so the
// excluded group still received every link trap — reverting either the
// Categories retention or the groupWantsCategory gate delivers a trap to the
// "excluded" case and fails it.
func TestSendLinkTraps_CategoryFilter(t *testing.T) {
	cases := []struct {
		name       string
		categories []string
		want       bool
	}{
		// Positive controls prove the harness delivers within the window, so
		// the negative assertion below is meaningful (not a flaky timeout).
		{"no categories = all (Junos default)", nil, true},
		{"scoped to link", []string{"link"}, true},
		{"link among several", []string{"configuration", "link"}, true},
		{"case-insensitive link", []string{"LINK"}, true},
		// The bypass: a group scoped to exclude link must NOT receive it.
		{"scoped to exclude link", []string{"configuration"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := linkTrapDelivered(t, tc.categories); got != tc.want {
				t.Fatalf("link trap delivered=%v for categories=%v, want %v", got, tc.categories, tc.want)
			}
		})
	}
}
