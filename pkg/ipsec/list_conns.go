package ipsec

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/termsafe"
)

// LoadedConn is one connection strongSwan has LOADED, as `swanctl --list-conns --raw`
// reports it (#9641): its loaded child section names and its endpoint address lists.
// LocalAddrs is the discriminator a name set lacks. A gateway moved to a reth in another
// redundancy group keeps every connection and child name but renders, and loads, a
// different local address.
type LoadedConn struct {
	Children    []string
	LocalAddrs  []string
	RemoteAddrs []string
}

// LoadedConns maps each loaded connection name to what charon reports for it. It
// describes charon's configuration, not its SAs: a loaded connection appears whether or
// not a tunnel is up.
type LoadedConns map[string]*LoadedConn

// SANames returns every connection and child name in c, the same kind of names
// BuildSANameIndex keys. A multi-selector VPN contributes its connection name and each
// `<vpn>-<selector>` child; a no-selector VPN contributes its name once.
func (c LoadedConns) SANames() map[string]bool {
	names := make(map[string]bool, len(c))
	for conn, lc := range c {
		names[conn] = true
		if lc == nil {
			continue
		}
		for _, child := range lc.Children {
			names[child] = true
		}
	}
	return names
}

// ListLoadedConns asks charon which connections it has loaded (#9641), through the
// stdout-only swanctl seam and under swanctlTimeout like every other swanctl call. An
// error means charon could not be asked (not running, vici socket down); that is routine
// at startup, and the caller must keep its own fallback rather than treat it as "nothing
// loaded".
func (m *Manager) ListLoadedConns() (LoadedConns, error) {
	out, errOut, err := m.scSplit("--list-conns", "--raw")
	if err != nil {
		return nil, fmt.Errorf("swanctl --list-conns --raw: %w: %s", err, termsafe.SanitizeForDisplay(string(errOut)))
	}
	return parseListConnsRaw(string(out))
}

// parseListConnsRaw parses `swanctl --list-conns --raw`, which prints one vici event per
// loaded connection and then the reply:
//
//	list-conn event {<conn> {local_addrs=[a b] remote_addrs=[c] ... local-1 {...} children {<child> {...} ...}}}
//	list-conns reply {}
//
// The dump is a nested-section format, not whitespace-delimited: values are printed
// unquoted and may contain spaces (`class=pre-shared key`), and a section's opening
// brace is glued to its first member (`local-1 {class=...`). So braces and brackets are
// split out as their own tokens, and a section's name is the bare token (no `=`)
// immediately before its `{`. A connection is a section directly inside an `event`
// section; a child is a section directly inside that connection's `children` section.
// `local_addrs=[...]` and `remote_addrs=[...]` are read only at the connection's own
// level, so the auth subsections' lists (`groups=[]`, `certs=[]`) are never taken for
// addresses. Values never open a section, so a space inside a value cannot be mistaken
// for one.
func parseListConnsRaw(out string) (LoadedConns, error) {
	r := strings.NewReplacer("{", " { ", "}", " } ", "[", " [ ", "]", " ] ")
	toks := strings.Fields(r.Replace(out))
	conns := LoadedConns{}
	var stack []string
	listDepth := 0
	listKey := ""
	for i, tok := range toks {
		switch tok {
		case "[":
			listDepth++
			listKey = ""
			if listDepth == 1 && i > 0 && len(stack) == 2 && stack[0] == "event" {
				switch toks[i-1] {
				case "local_addrs=", "remote_addrs=":
					listKey = toks[i-1]
				}
			}
		case "]":
			if listDepth > 0 {
				listDepth--
			}
			listKey = ""
		case "{":
			if listDepth > 0 {
				return nil, fmt.Errorf("list-conns raw output: section opened inside a list at token %d", i)
			}
			name := ""
			if i > 0 && !strings.Contains(toks[i-1], "=") && toks[i-1] != "}" && toks[i-1] != "]" {
				name = toks[i-1]
			}
			stack = append(stack, name)
			switch {
			case len(stack) == 2 && stack[0] == "event" && name != "":
				if conns[name] == nil {
					conns[name] = &LoadedConn{}
				}
			case len(stack) == 4 && stack[0] == "event" && stack[2] == "children" && name != "":
				if lc := conns[stack[1]]; lc != nil {
					lc.Children = append(lc.Children, name)
				}
			}
		case "}":
			if listDepth > 0 {
				return nil, fmt.Errorf("list-conns raw output: section closed inside a list at token %d", i)
			}
			if len(stack) == 0 {
				return nil, fmt.Errorf("list-conns raw output: unbalanced '}' at token %d", i)
			}
			stack = stack[:len(stack)-1]
		default:
			if listKey != "" && len(stack) == 2 {
				if lc := conns[stack[1]]; lc != nil {
					if listKey == "local_addrs=" {
						lc.LocalAddrs = append(lc.LocalAddrs, tok)
					} else {
						lc.RemoteAddrs = append(lc.RemoteAddrs, tok)
					}
				}
			}
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("list-conns raw output: %d unclosed section(s)", len(stack))
	}
	return conns, nil
}

// parseListPoolsRaw parses `swanctl --list-pools --raw`. strongSwan 6.0.5 prints ONE
// reply message holding every loaded pool (not one event per pool, unlike list-conns):
//
//	get-pools reply {xpf-gen-<digest> {base=192.0.2.1 size=1 online=0 offline=0}}
//
// It returns each loaded pool's name mapped to its base address. #9641 reads the
// generation marker from it: an UNREFERENCED pool named for the applied config's
// digest. Sections are tokenised exactly as parseListConnsRaw does. A pool is a section
// directly inside the `reply` section, and its base is the `base=` value inside it.
func parseListPoolsRaw(out string) (map[string]string, error) {
	r := strings.NewReplacer("{", " { ", "}", " } ", "[", " [ ", "]", " ] ")
	toks := strings.Fields(r.Replace(out))
	pools := map[string]string{}
	var stack []string
	listDepth := 0
	for i, tok := range toks {
		switch tok {
		case "[":
			listDepth++
		case "]":
			if listDepth > 0 {
				listDepth--
			}
		case "{":
			if listDepth > 0 {
				return nil, fmt.Errorf("list-pools raw output: section opened inside a list at token %d", i)
			}
			name := ""
			if i > 0 && !strings.Contains(toks[i-1], "=") && toks[i-1] != "}" && toks[i-1] != "]" {
				name = toks[i-1]
			}
			stack = append(stack, name)
			if len(stack) == 2 && stack[0] == "reply" && name != "" {
				if _, ok := pools[name]; !ok {
					pools[name] = ""
				}
			}
		case "}":
			if len(stack) == 0 {
				return nil, fmt.Errorf("list-pools raw output: unbalanced '}' at token %d", i)
			}
			stack = stack[:len(stack)-1]
		default:
			if len(stack) == 2 && stack[0] == "reply" && listDepth == 0 && strings.HasPrefix(tok, "base=") {
				pools[stack[1]] = strings.TrimPrefix(tok, "base=")
			}
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("list-pools raw output: %d unclosed section(s)", len(stack))
	}
	return pools, nil
}
