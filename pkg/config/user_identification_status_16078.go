package config

import (
	"fmt"
	"io"
	"sort"
)

// #16078 (FA-02): user-identification stanzas (AD / JIMS / local table under
// `services user-identification` or `security user-identification`, plus the
// direct `security <stanza>` spelling) commit wholly inert — no
// user-identification engine consumes them — while their credentials
// (client-secret / shared-secret / bind password) are stored for a
// non-feature. The accepted-only warning (#10947) fires at commit, but
// before this change no `show`/`status` surface carried an inert marker, so
// `show configuration` displayed the stanza as ordinary (apparently live)
// configuration and an operator could believe identity-based policy was
// enforced when nothing enforces it.
//
// This file is the single authority for that marker: the compiled record of
// which stanzas are configured, and the shared renderer every operator
// surface (local CLI, gRPC ShowText, REST show-text) calls — the same shape
// as alg_status_7423.go, so the three surfaces cannot disagree about whether
// user-identification is functional.

// UserIdentificationStatusInert is the operator-facing status word for a
// configured user-identification stanza. It deliberately never reads
// "enabled"/"active": nothing consumes the stanza.
const UserIdentificationStatusInert = "INERT (accepted-only; no runtime effect)"

// userIdentificationStanzasIn returns the deduplicated, config-order list of
// user-identification sub-stanzas present under node (a `services` or
// `security` root), or nil when no user-identification stanza is present.
// It is the detection half of userIdentificationWarnings, shared so the
// warning and the compiled record can never disagree about which stanzas a
// config carries.
// userIdentificationPresent reports whether any user-identification stanza
// (named or bare) is present under node. A bare `security
// user-identification;` yields no named stanza but must still warn.
func userIdentificationPresent(node *Node) (stanzas []string, present bool) {
	if node == nil {
		return nil, false
	}
	stanzas = userIdentificationStanzasIn(node)
	if stanzas != nil {
		return stanzas, true
	}
	// Bare forms: packed `security user-identification` on the root keys,
	// or a childless `user-identification` / direct-stanza child.
	for _, k := range node.Keys {
		if k == "user-identification" {
			return nil, true
		}
	}
	for _, child := range node.Children {
		if child.Name() == "user-identification" || userIdentificationStanzas[child.Name()] {
			return nil, true
		}
	}
	return nil, false
}

func userIdentificationStanzasIn(node *Node) []string {
	if node == nil {
		return nil
	}
	var stanzas []string
	seen := make(map[string]bool)
	sawUserID := false
	add := func(name string) {
		if userIdentificationStanzas[name] && !seen[name] {
			seen[name] = true
			stanzas = append(stanzas, name)
		}
	}
	// Packed root: a flat single-line spelling (`services
	// user-identification authentication-source ...;` or the elided
	// `security authentication-source { ... }`) packs the stanza path
	// onto the ROOT node's own Keys with no children. Scan those keys
	// so every spelling is recorded identically (#16296: the child-only
	// walk missed exactly this shape).
	if len(node.Children) == 0 && len(node.Keys) > 1 {
		for i, k := range node.Keys {
			if k == "user-identification" {
				sawUserID = true
				if i+1 < len(node.Keys) {
					add(node.Keys[i+1])
				}
			} else if i > 0 && userIdentificationStanzas[k] && node.Keys[0] != "user-identification" {
				// Direct stanza packed on the root line:
				// `security authentication-source { ... }`.
				sawUserID = true
				add(k)
			}
		}
	}
	var walk func(n *Node)
	walk = func(n *Node) {
		for _, child := range n.Children {
			switch child.Name() {
			case "user-identification":
				sawUserID = true
				if len(child.Keys) > 1 {
					add(child.Keys[1])
				}
				for _, sub := range child.Children {
					add(sub.Name())
					// Deeper flat tails: `user-identification { authentication-source ... }`
					if len(sub.Keys) > 1 {
						add(sub.Keys[1])
					}
				}
			default:
				if userIdentificationStanzas[child.Name()] {
					sawUserID = true
					add(child.Name())
				}
			}
		}
	}
	walk(node)
	if !sawUserID {
		return nil
	}
	return stanzas
}

// recordUserIdentification notes the user-identification stanzas under one
// root node ("services" or "security") on cfg, deduplicated across roots in
// first-seen order. Called from the section dispatch for both spellings.
func (cfg *Config) recordUserIdentification(node *Node) {
	for _, s := range userIdentificationStanzasIn(node) {
		dup := false
		for _, have := range cfg.userIdentificationStanzas {
			if have == s {
				dup = true
				break
			}
		}
		if !dup {
			cfg.userIdentificationStanzas = append(cfg.userIdentificationStanzas, s)
		}
	}
}

// UserIdentificationConfigured returns the user-identification sub-stanzas
// an operator configured (either spelling), deduplicated in first-seen
// order, or nil when none are configured. Every name returned is inert:
// xpf implements no user-identification engine (#10947/#16078).
func (cfg *Config) UserIdentificationConfigured() []string {
	if cfg == nil || len(cfg.userIdentificationStanzas) == 0 {
		return nil
	}
	out := make([]string, len(cfg.userIdentificationStanzas))
	copy(out, cfg.userIdentificationStanzas)
	return out
}

// RenderUserIdentificationStatus writes the `show services
// user-identification status` / `show security user-identification status`
// body. Single source of truth so the local CLI, gRPC and REST surfaces
// cannot drift on whether user-identification is functional (#16078).
func RenderUserIdentificationStatus(w io.Writer, cfg *Config) {
	if cfg == nil {
		fmt.Fprintln(w, "No active configuration")
		return
	}
	fmt.Fprintln(w, "User identification status:")
	stanzas := cfg.UserIdentificationConfigured()
	if len(stanzas) == 0 {
		fmt.Fprintln(w, "  No user-identification configured")
		return
	}
	// Deterministic order for display; UserIdentificationConfigured keeps
	// first-seen order for callers that need config order.
	sorted := make([]string, len(stanzas))
	copy(sorted, stanzas)
	sort.Strings(sorted)
	for _, s := range sorted {
		fmt.Fprintf(w, "  %s: %s\n", s, UserIdentificationStatusInert)
	}
	fmt.Fprintln(w, "  xpf does not implement user-identification (AD/JIMS/local table);")
	fmt.Fprintln(w, "  no identity-based policy is enforced and stored credentials are unused (#16078).")
}
