package config

import (
	"strings"
	"testing"
)

// #14143: the payload scan ran over the TYPED fragment only, while the outer
// path was adjudicated on the RESOLVED path. Inside an edit cursor at
// `... then change-configuration` the typed `set commands "…"` carries no
// `change-configuration` token, so a payload the planting class is denied
// planted unadjudicated; fire-time revalidation was the only gate.
// The decisive check from the issue, plus its neighbours: every cursor depth
// that supplies part of the `change-configuration commands` pair must be
// adjudicated, and an allowed payload from the same cursor must still plant.
func TestEditCursorRelativePayloadIsAdjudicated14143(t *testing.T) {
	cfg := evtCfgFor9939(t)
	cc := []string{"event-options", "policy", "p", "then", "change-configuration"}
	for name, tc := range map[string]struct {
		editPath []string
		line     string
	}{
		"cursor at change-configuration, quoted":   {cc, `set commands "delete security policies guard"`},
		"cursor at change-configuration, unquoted": {cc, `set commands delete security policies guard`},
		"cursor at then":                    {cc[:4], `set change-configuration commands "delete security policies guard"`},
		"cursor at policy":                  {cc[:3], `set then change-configuration commands "delete security policies guard"`},
		"cursor at policy, set op":          {cc[:3], `set then change-configuration commands "set security policies guard match source-address any"`},
		"cursor inside stanza, delete verb": {cc, `delete commands "delete security policies guard"`},
	} {
		t.Run(name, func(t *testing.T) {
			err := AuthorizeConfigMutation(cfg, "planter", tc.editPath, tc.line)
			if err == nil {
				t.Fatalf("a class denied `security policies` planted a payload targeting it from "+
					"edit cursor %v; the typed line carries no `change-configuration` token (#14143)\n  %s",
					tc.editPath, tc.line)
			}
			if !strings.Contains(err.Error(), "#9939") {
				t.Errorf("the refusal does not say WHY a line about event-options was refused for a "+
					"path that is not under it: %v", err)
			}
		})
	}
	// POSITIVE CONTROL: an allowed payload from inside the stanza still
	// plants, and a non-payload relative set under the same cursor is
	// untouched — the fix must locate the payload, not refuse the cursor.
	for _, tc := range []struct {
		editPath []string
		line     string
	}{
		{cc, `set commands "set system host-name evented"`},
		{cc[:3], `set then change-configuration commands "set system host-name evented"`},
		{cc[:3], `set events e1`},
	} {
		if err := AuthorizeConfigMutation(cfg, "planter", tc.editPath, tc.line); err != nil {
			t.Errorf("cursor %v + %q touches no denied path but was refused: %v", tc.editPath, tc.line, err)
		}
	}
}

// #14143 decisive-check variant with the issue's exact class shape: allowed
// `event-options`, denied `system`, payload targeting `system`.
func TestEditCursorPayloadDeniedSystem14143(t *testing.T) {
	cfg := classWithConfigRegex9154(t, "", "^system")
	err := AuthorizeConfigMutation(cfg, "limited",
		[]string{"event-options", "policy", "p", "then", "change-configuration"},
		`set commands "set system root-authentication plain-text-password x"`)
	if err == nil {
		t.Fatal("edit-cursor-relative `set commands \"set system …\"` was ALLOWED for a class " +
			"denied `^system`; the payload scan never saw the cursor's `change-configuration` " +
			"ancestor (#14143 decisive check)")
	}
	if !strings.Contains(err.Error(), "#9939") {
		t.Errorf("the refusal does not name the planted payload as the reason: %v", err)
	}
	// Same cursor, allowed target: must still plant.
	if err := AuthorizeConfigMutation(cfg, "limited",
		[]string{"event-options", "policy", "p", "then", "change-configuration"},
		`set commands "set event-options policy q events e1"`); err != nil {
		t.Errorf("an allowed payload from the same cursor was refused: %v", err)
	}
}

// #14143 rename/copy arm: a rename/copy line carries no payload text — the
// embedded commands already exist under the source subtree, both endpoints
// are adjudicated as resolved paths by configMutationPaths, the moved
// subtree is re-stamped to the mover's class (StampChangedEventPlantClasses),
// and every command is re-adjudicated against that class at fire time
// (eventengine.validatePlantClass). This cell pins the planting-time half
// that IS decidable from the line: a rename/copy whose destination lands on
// the `change-configuration commands` node is still only an endpoint
// mutation (allowed when neither endpoint is denied), while a rename/copy
// touching a denied endpoint is refused. It must NOT invent a payload from
// endpoint names.
func TestRenameCopyIntoChangeConfigurationHasNoPayloadText14143(t *testing.T) {
	cfg := evtCfgFor9939(t)
	if err := AuthorizeConfigMutation(cfg, "planter", nil,
		`rename event-options policy p then other to event-options policy p then change-configuration`); err != nil {
		t.Errorf("rename into change-configuration with no denied endpoint was refused: %v", err)
	}
	if err := AuthorizeConfigMutation(cfg, "planter", nil,
		`rename security policies guard to event-options policy p then change-configuration commands`); err == nil {
		t.Error("rename from a denied source endpoint was ALLOWED (#14143)")
	}
	if err := AuthorizeConfigMutation(cfg, "planter", nil,
		`copy security policies guard to event-options policy p then change-configuration commands`); err == nil {
		t.Error("copy from a denied source endpoint was ALLOWED (#14143)")
	}
}
