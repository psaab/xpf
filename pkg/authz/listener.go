package authz

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
)

// listener.go answers "who owns the LISTENING socket at this local address"
// (#14581).
//
// # Why this exists
//
// #8233 made a persistent EADDRINUSE on the management port fatal on the
// theory that the holder is another xpfd. That theory was unchecked: any
// local process that can bind a port above ip_unprivileged_port_start —
// an SSH remote forward (`ssh -R 127.0.0.1:50051:...`), a compromised
// service UID such as frr or chrony, any unprivileged local process —
// holds 127.0.0.1:50051 exactly as well as a second xpfd does, and the
// daemon exited fatally into a Restart=on-failure loop while the holder
// impersonated the management server to the CLI. The holder's UID is
// the kernel fact that separates "another xpfd" (uid 0 / our own uid,
// which the daemon runs as) from "someone else squatting" — and the
// kernel publishes it in the same /proc/net/tcp{,6} tables peer.go
// already reads for ESTABLISHED peers.
//
// # What a LISTEN row proves, and what it does not
//
// A row in state 0A (TCP_LISTEN) whose local address is the bind target
// names the UID that bound the listening socket. That is the holder.
// Unlike the ESTABLISHED case there is no TIME_WAIT-style aliasing to
// fear: a listening socket is a live, owned object, and its UID column
// is the owner's real UID (the kernel does not synthesize uid 0 for
// listen sockets; that quirk is specific to TIME_WAIT mini-sockets).
//
// The match is on the LOCAL address, with a bounded fallback: an exact
// host:port row wins; otherwise a wildcard row (0.0.0.0:port /
// [::]:port) that would also block the bind is reported. Both are real
// holders of the port. A row for a DIFFERENT specific address on the
// same port (e.g. 127.0.0.2:50051 when we want 127.0.0.1:50051) does
// NOT block our bind and is not reported — claiming it did would make
// an innocent neighbour privileged.
//
// # The three-state answer
//
// As in peer.go, "not found" must never be confused with "found and
// privileged", and a broken observation must never be read as either:
//
//	found  privileged  meaning
//	-----  ----------  --------------------------------------------
//	true   true        holder is uid 0 or our own uid → the #8233
//	                   duplicate-xpfd case; fatal is sound.
//	true   false       holder is some other local uid → squatter;
//	                   NOT a duplicate xpfd. Fatal would hand that
//	                   uid a persistent kill switch.
//	false  —           no LISTEN row could be attributed. Either the
//	                   tables were unreadable (err != nil) or the
//	                   holder vanished / lives in another netns. The
//	                   caller must NOT treat this as privileged: an
//	                   unattributed holder is not evidence of another
//	                   xpfd. It also must not treat it as proven
//	                   benign — the caller keeps alarming.
//
// This mirrors LookupPeer's fail-closed shape, inverted for the fatal
// decision: peer.go denies unless attribution succeeds; here the
// daemon goes fatal only when attribution succeeds AND names a
// privileged holder.

// tcpListen is TCP_LISTEN from include/net/tcp_states.h, the value
// /proc/net/tcp{,6} reports in its state column for a listening socket.
const tcpListen = 10

// ListenerOwner is the attribution of the socket listening at a local
// address. See the file comment for the three-state contract.
type ListenerOwner struct {
	// UID is the holder's UID. Meaningful only when Found is true.
	UID uint32
	// Found reports whether a LISTEN row for the address was observed.
	Found bool
	// Detail explains a non-attribution or a wildcard attribution, for
	// operator logs. Never carries authority by itself.
	Detail string
}

// Privileged reports whether the attributed holder is one whose holding
// the port means "another xpfd": uid 0, or this process's own uid. An
// unattributed holder is NOT privileged (see file comment).
func (o ListenerOwner) Privileged(selfUID uint32) bool {
	return o.Found && (o.UID == 0 || o.UID == selfUID)
}

// lookupListenerOwnerFn is the production listener-owner lookup, a
// variable so the grpcapi supervisor's tests can drive the attributed /
// unattributed / non-privileged branches without depending on who
// happens to hold a port on the machine running the suite. Production
// never changes it.
var lookupListenerOwnerFn = LookupListenerOwner

// SetLookupListenerOwnerForTest replaces the listener-owner lookup the
// grpcapi supervisor consults and restores the previous value through
// the returned function. Test-only.
func SetLookupListenerOwnerForTest(fn func(addr string) (ListenerOwner, error)) (restore func()) {
	prev := lookupListenerOwnerFn
	lookupListenerOwnerFn = fn
	return func() { lookupListenerOwnerFn = prev }
}

// LookupListenerOwnerForSupervisor is the entry point the grpcapi
// primary-listener supervisor calls at the #8233 fatal decision. It
// goes through the replaceable seam above so the supervisor's policy
// (fatal only for a privileged holder) is testable as a property.
func LookupListenerOwnerForSupervisor(addr string) (ListenerOwner, error) {
	return lookupListenerOwnerFn(addr)
}

// listenTableKey identifies one wanted local-address key in one table file.
type listenTableKey struct{ path, local string }

// LookupListenerOwner attributes the listening socket at addr
// (host:port, as passed to net.Listen) from /proc/net/tcp{,6}.
//
// It never fabricates a holder: a table that cannot be read returns an
// error (and Found=false), and a readable table with no matching LISTEN
// row returns Found=false with no error.
func LookupListenerOwner(addr string) (ListenerOwner, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return ListenerOwner{Detail: fmt.Sprintf("cannot split listen address %q: %v", addr, err)},
			fmt.Errorf("split listen address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return ListenerOwner{Detail: fmt.Sprintf("bad port in listen address %q", addr)},
			fmt.Errorf("bad port in listen address %q", addr)
	}
	// Resolve a hostname bind ("localhost") to the loopback it denotes so
	// the table key can be rendered. An unresolvable host is reported
	// unattributed rather than guessed.
	targetIP := net.ParseIP(host)
	if targetIP == nil && host != "" {
		if resolved, rerr := net.ResolveIPAddr("ip", host); rerr == nil && resolved != nil && resolved.IP != nil {
			targetIP = resolved.IP
		} else {
			return ListenerOwner{Detail: fmt.Sprintf("cannot resolve listen host %q", host)}, nil
		}
	}

	type tableKey = listenTableKey
	var exact, wildcard []tableKey
	target := &net.TCPAddr{IP: targetIP, Port: port}
	if k, ok := procAddr4(target); ok {
		exact = append(exact, tableKey{procNetTCPPath, k})
	}
	if k, ok := procAddr6(target); ok {
		exact = append(exact, tableKey{procNetTCP6Path, k})
	}
	// Wildcard rows that would block this bind: 0.0.0.0:port and [::]:port.
	if k, ok := procAddr4(&net.TCPAddr{IP: net.IPv4zero, Port: port}); ok {
		wildcard = append(wildcard, tableKey{procNetTCPPath, k})
	}
	if k, ok := procAddr6(&net.TCPAddr{IP: net.IPv6zero, Port: port}); ok {
		wildcard = append(wildcard, tableKey{procNetTCP6Path, k})
	}
	// A wildcard target is blocked by ANY specific row on the port; there
	// are too many to enumerate as keys, so scanListenFile additionally
	// matches on the port suffix in that case.
	anySpecific := targetIP == nil || targetIP.IsUnspecified()

	owner, found, readErr := scanListenTables(exact, wildcard, anySpecific, port)
	if readErr != nil {
		return ListenerOwner{Detail: "socket table unreadable: " + readErr.Error()}, readErr
	}
	if !found {
		return ListenerOwner{Detail: fmt.Sprintf("no listening socket found for %s", addr)}, nil
	}
	return owner, nil
}

// scanListenTables reads each distinct table file once looking for
// LISTEN rows. An exact-address match in any table wins over a wildcard
// match in any other: the exact row is the socket our bind collided
// with. readErr is non-nil only when NO table could be read at all (an
// absent tcp6 alongside a readable tcp is not an error — the same rule
// as peer.go's scanBatch).
func scanListenTables(exact, wildcard []listenTableKey, anySpecific bool, port int) (ListenerOwner, bool, error) {
	type want struct{ exact, wild map[string]bool }
	byPath := map[string]*want{}
	add := func(k listenTableKey, dst func(*want) map[string]bool) {
		w := byPath[k.path]
		if w == nil {
			w = &want{exact: map[string]bool{}, wild: map[string]bool{}}
			byPath[k.path] = w
		}
		dst(w)[k.local] = true
	}
	for _, k := range exact {
		add(k, func(w *want) map[string]bool { return w.exact })
	}
	for _, k := range wildcard {
		add(k, func(w *want) map[string]bool { return w.wild })
	}

	var exactHit, wildHit *ListenerOwner
	readAny := false
	var firstErr error
	for path, w := range byPath {
		hit, wild, absent, err := scanListenFile(path, w.exact, w.wild, anySpecific, port)
		if absent {
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		readAny = true
		if hit != nil && exactHit == nil {
			h := *hit
			exactHit = &h
		}
		if wild != nil && wildHit == nil {
			h := *wild
			wildHit = &h
		}
	}
	if exactHit != nil {
		return *exactHit, true, nil
	}
	if wildHit != nil {
		return *wildHit, true, nil
	}
	if !readAny && firstErr != nil {
		return ListenerOwner{}, false, firstErr
	}
	if !readAny {
		return ListenerOwner{}, false, errors.New("no socket table could be read")
	}
	return ListenerOwner{}, false, nil
}

// scanListenFile scans one /proc/net/tcp{,6} file for LISTEN rows whose
// local address is an exact want, a wildcard want, or (when anySpecific)
// any address on the target port. Exact and wildcard hits are returned
// separately so the caller can prefer the exact one across files.
//
// A matching row whose uid column will not parse fails the file read:
// guessing uid 0 for garbage would make an unparseable row "privileged"
// and reinstate the fatal kill switch this file exists to remove.
func scanListenFile(path string, exact, wild map[string]bool, anySpecific bool, port int) (exactHit, wildHit *ListenerOwner, absent bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.Is(err, fs.ErrNotExist), err
	}
	defer f.Close()

	portSuffix := fmt.Sprintf(":%04X", port)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Columns: sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		st, sterr := strconv.ParseUint(fields[3], 16, 8)
		if sterr != nil || st != tcpListen {
			continue
		}
		local := normalizeHexColumn(fields[1])
		isExact := exact[local]
		isWild := wild[local]
		if !isExact && !isWild {
			if !anySpecific || !strings.HasSuffix(local, portSuffix) {
				continue
			}
			isWild = true // any specific row blocks a wildcard bind
		}
		uid, uiderr := strconv.ParseUint(fields[7], 10, 32)
		if uiderr != nil {
			return nil, nil, false, fmt.Errorf("listening row for %s has unparsable uid %q", local, fields[7])
		}
		hit := &ListenerOwner{UID: uint32(uid), Found: true}
		if isExact && exactHit == nil {
			exactHit = hit
		}
		if isWild && wildHit == nil {
			hit.Detail = "wildcard listener holds the port"
			wildHit = hit
		}
		if exactHit != nil && wildHit != nil {
			// Both classes found in this file; nothing more to learn here.
			// (Do not break: a truncated-read error must still surface —
			// but Scanner only reports it after Scan returns false, so
			// keep scanning cheaply is wrong; break and check Err.)
			break
		}
	}
	if sc.Err() != nil {
		return nil, nil, false, sc.Err()
	}
	return exactHit, wildHit, false, nil
}
