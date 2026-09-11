package ipsec

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/termsafe"
)

// GENERATION MARKER (#9641).
//
// HA IPsec re-initiation attributes each SA name the peer advertises against the xpf
// config generation charon RUNS. The daemon's own record of that (#9511) is empty after
// an xpfd restart until the first successful load, and it is cleared in the
// failed-reload window, where charon's own start or reload can load the file that xpfd's
// reload did not. So every swanctl config xpf WRITES names its generation inside charon,
// as an unreferenced address pool `xpf-gen-<generation>`, and LoadedGeneration reads it
// back.
//
// INERT. No connection references the pool (no `pools =` is ever rendered), so no IKE SA
// can lease from it, and a pool is not a connection: charon cannot initiate or respond
// with it. Its one address, 192.0.2.1, is TEST-NET-1 (RFC 5737). strongSwan 6.0.5 loads
// and lists such a pool (testdata/swanctl_list_pools_*_9641.*).
//
// IDENTITY, NOT PROOF. `swanctl --load-all` runs separate loaders, not one transaction,
// so an interrupted or partial load can leave the pool and the connections at different
// generations. A caller must validate the named generation against the loaded
// connections (ExpectedLoadedConns, LoadedConns.Equal) before trusting it.

const (
	generationMarkerPrefix = "xpf-gen-"
	generationMarkerAddrs  = "192.0.2.1/32"

	// UnknownGeneration is the generation a written config names when its writer could
	// not name one: a plain Apply, or a config that is not the store's active config. It
	// never matches a retained generation, so attribution always falls back for it.
	UnknownGeneration = "unknown"
)

// generationDigest matches what the daemon names a generation by: the configstore
// config-text digest, hex SHA-256.
var generationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// generationToken returns gen when it is a generation digest, and UnknownGeneration
// otherwise. The token becomes an unquoted swanctl section name, so nothing else is ever
// written there, and a marker read back from charon is held to the same shape.
func generationToken(gen string) string {
	if generationDigest.MatchString(gen) {
		return gen
	}
	return UnknownGeneration
}

// renderGenerationMarker renders the marker pool section naming gen.
func renderGenerationMarker(gen string) string {
	return fmt.Sprintf("pools {\n  %s%s {\n    addrs = %s\n  }\n}\n",
		generationMarkerPrefix, generationToken(gen), generationMarkerAddrs)
}

var (
	// ErrNoGenerationMarker means charon lists no xpf generation marker: it loaded no xpf
	// config, or one written by an xpf that predates the marker.
	ErrNoGenerationMarker = errors.New("charon lists no xpf generation marker")
	// ErrAmbiguousGenerationMarker means charon lists more than one marker, so it cannot
	// name one generation.
	ErrAmbiguousGenerationMarker = errors.New("charon lists more than one xpf generation marker")
	// ErrGenerationUnvalidatable means a rendered connection's local address was resolved
	// at apply time from the kernel or through DNS, which cannot be replayed for a stored
	// generation.
	ErrGenerationUnvalidatable = errors.New("the generation's local addresses depend on apply-time resolution")
)

// LoadedGeneration asks charon which generation marker it has loaded (#9641), through the
// stdout-only swanctl seam and under swanctlTimeout like every other swanctl call. It
// returns the marker's generation token (UnknownGeneration for a marker that does not
// name a digest). An error means charon could not be asked, or does not name exactly one
// generation. Both are routine (charon not running, a file written by an older xpf), and
// the caller keeps its fallback.
func (m *Manager) LoadedGeneration() (string, error) {
	out, errOut, err := m.scSplit("--list-pools", "--raw")
	if err != nil {
		return "", fmt.Errorf("swanctl --list-pools --raw: %w: %s", err, termsafe.SanitizeForDisplay(string(errOut)))
	}
	pools, err := parseListPoolsRaw(string(out))
	if err != nil {
		return "", err
	}
	var gens []string
	for name := range pools {
		if gen, ok := strings.CutPrefix(name, generationMarkerPrefix); ok {
			gens = append(gens, generationToken(gen))
		}
	}
	switch len(gens) {
	case 0:
		return "", ErrNoGenerationMarker
	case 1:
		return gens[0], nil
	}
	sort.Strings(gens)
	return "", fmt.Errorf("%w: %s", ErrAmbiguousGenerationMarker, strings.Join(gens, ","))
}

// ExpectedLoadedConns returns what `swanctl --list-conns --raw` reports once charon has
// loaded cfg's IPsec section COMPLETELY, as xpf renders it (#9641): every rendered
// connection with its children and its endpoint address lists. Comparing it with
// ListLoadedConns through LoadedConns.Equal is the validation a generation marker needs.
//
// It works from the configuration alone (prepareConfigFromConfig), because a stored
// generation's apply-time resolution cannot be replayed. When a rendered connection's
// local address came from the kernel or from a DNS-derived family hint, the result is
// ErrGenerationUnvalidatable. The candidate is rendered as a whole, the way Apply renders
// it: a hard render error means that generation's production render failed, so charon
// cannot have loaded any of it, and the error is returned. A VPN the renderer skips is
// excluded. This deliberately differs from BuildSANameIndex, which keeps a render-error
// VPN's names because for attribution an extra candidate only makes ownership stricter;
// here the question is equality with what charon holds.
func ExpectedLoadedConns(cfg *config.Config) (LoadedConns, error) {
	if cfg == nil {
		return LoadedConns{}, nil
	}
	ipsecCfg, runtime := prepareConfigFromConfig(cfg)
	return expectedLoadedConns(ipsecCfg, runtime)
}

// expectedLoadedConns is ExpectedLoadedConns over a prepared IPsec section. runtime names
// the gateways whose local address could not be resolved from the configuration.
func expectedLoadedConns(ipsecCfg *config.IPsecConfig, runtime map[string]bool) (LoadedConns, error) {
	conns := LoadedConns{}
	if ipsecCfg == nil {
		return conns, nil
	}
	_, rendered, err := (&Manager{}).renderConfig(ipsecCfg)
	if err != nil {
		return nil, err
	}
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		conn := sanitizeSwanctlValue(name)
		if !rendered[conn] {
			continue
		}
		vpn := ipsecCfg.VPNs[name]
		if vpn.LocalAddr == "" && runtime[vpn.Gateway] {
			return nil, fmt.Errorf("%w: vpn %q, gateway %q", ErrGenerationUnvalidatable, name, vpn.Gateway)
		}
		remote, local, _, _ := resolveRemoteAddr(ipsecCfg, vpn)
		lc := &LoadedConn{
			LocalAddrs:  swanctlAddrList(local),
			RemoteAddrs: swanctlAddrList(remote),
		}
		for _, child := range effectiveTrafficSelectors(name, vpn) {
			lc.Children = append(lc.Children, sanitizeSwanctlValue(child.Name))
		}
		conns[conn] = lc
	}
	return conns, nil
}

// swanctlAddrList is how charon lists a rendered local_addrs or remote_addrs value: its
// comma-separated entries, or %any (strongSwan's default) when the line is not rendered.
func swanctlAddrList(v string) []string {
	var out []string
	for _, a := range strings.Split(sanitizeSwanctlValue(v), ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return []string{"%any"}
	}
	return out
}

// Equal reports whether c and o describe the same loaded connections: the same connection
// names and, for each, the same children, local addresses and remote addresses. Each list
// is compared as a multiset, because charon's listing order is not a contract.
func (c LoadedConns) Equal(o LoadedConns) bool {
	if len(c) != len(o) {
		return false
	}
	for name, a := range c {
		b, ok := o[name]
		if !ok {
			return false
		}
		if a == nil {
			a = &LoadedConn{}
		}
		if b == nil {
			b = &LoadedConn{}
		}
		if !sameStrings(a.Children, b.Children) ||
			!sameStrings(a.LocalAddrs, b.LocalAddrs) ||
			!sameStrings(a.RemoteAddrs, b.RemoteAddrs) {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
