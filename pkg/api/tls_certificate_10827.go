package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const managementTLSCertificateCheckInterval = time.Hour

const (
	managementTLSCertificateGenerated = "system-generated"
	managementTLSCertificateCustom    = "custom"
)

type managementTLSCertificateFiles struct {
	certificate string
	privateKey  string
}

func (f *managementTLSCertificateFiles) custom() bool {
	return f != nil && (f.certificate != "" || f.privateKey != "")
}

type managementTLSCertificateState struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
	chain       []*x509.Certificate
	fingerprint [32]byte
	bindHost    string
	source      string
	invalid     bool
	reason      string
}

// managementTLSCertificateSlot is the fallback certificate selector for a
// leg whose *http.Server carries no per-leg selector — hand-built test
// fixtures and the never-completed boot path. It is the narrowed survivor
// of the former server-shared s.tlsCertificate (#14984 D36-04): every
// production leg carries its OWN state (see managementTLSGetCertificateFor)
// so a dual-stack build order cannot overwrite one family's certificate
// with the other's. The fallback survives only for legs that never went
// through buildHTTPSServer; without it ReconcileTLSCertificate's
// post-refresh reads, the periodic monitor's invalid badge, and the
// managementTLSCertificateForServer fallback for GetCertificate-less
// fixtures would have nothing to read. Production handshakes never take
// it: buildHTTPSServer installs a per-leg closure.
type managementTLSCertificateSlot struct {
	state atomic.Pointer[managementTLSCertificateState]
}

var managementTLSCertificateInvalidEvents atomic.Uint64

func managementTLSCertificateLeaf(cert tls.Certificate) (tls.Certificate, *x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert, cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return cert, nil, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	cert.Leaf = leaf
	return cert, leaf, nil
}

// managementTLSCertificateChain parses every DER entry in cert. When
// cert.Leaf is already set it is used as the first entry (it is the
// parsed form of Certificate[0] for every loader in this package) and
// the remaining entries are parsed from Certificate[1:]; a Leaf that
// does not match Certificate[0], or a chain where Leaf is set but
// Certificate is empty, is rejected so callers can trust chain[0] ==
// leaf. Every entry must parse — an unparseable intermediate is a
// preflight failure, not a handshake-time surprise.
func managementTLSCertificateChain(cert tls.Certificate) (tls.Certificate, *x509.Certificate, []*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return cert, nil, nil, fmt.Errorf("certificate chain is empty")
	}
	var leaf *x509.Certificate
	if cert.Leaf != nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return cert, nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		if !parsed.Equal(cert.Leaf) {
			return cert, nil, nil, fmt.Errorf("certificate Leaf does not match Certificate[0]")
		}
		leaf = cert.Leaf
	} else {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return cert, nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		leaf = parsed
		cert.Leaf = leaf
	}
	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	chain = append(chain, leaf)
	for i, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return cert, nil, nil, fmt.Errorf("parse certificate chain entry %d: %w", i+1, err)
		}
		chain = append(chain, c)
	}
	return cert, leaf, chain, nil
}

func managementTLSCertificateValidityErrorFor(parsed *x509.Certificate, role string, now time.Time) error {
	if parsed == nil {
		return fmt.Errorf("certificate has no parsed %s", role)
	}
	if now.Before(parsed.NotBefore) {
		if role == "leaf" {
			return fmt.Errorf("certificate is not valid yet: now %s is before NotBefore %s",
				now.UTC().Format(time.RFC3339), parsed.NotBefore.UTC().Format(time.RFC3339))
		}
		return fmt.Errorf("certificate chain %s is not valid yet: now %s is before NotBefore %s (subject %q)",
			role, now.UTC().Format(time.RFC3339), parsed.NotBefore.UTC().Format(time.RFC3339), parsed.Subject.String())
	}
	if now.After(parsed.NotAfter) {
		if role == "leaf" {
			return fmt.Errorf("certificate has expired: now %s is after NotAfter %s",
				now.UTC().Format(time.RFC3339), parsed.NotAfter.UTC().Format(time.RFC3339))
		}
		return fmt.Errorf("certificate chain %s has expired: now %s is after NotAfter %s (subject %q)",
			role, now.UTC().Format(time.RFC3339), parsed.NotAfter.UTC().Format(time.RFC3339), parsed.Subject.String())
	}
	return nil
}

func managementTLSCertificateChainValidityError(chain []*x509.Certificate, now time.Time) error {
	if len(chain) == 0 || chain[0] == nil {
		return fmt.Errorf("certificate has no parsed leaf")
	}
	if err := managementTLSCertificateValidityErrorFor(chain[0], "leaf", now); err != nil {
		return err
	}
	for i, c := range chain[1:] {
		if err := managementTLSCertificateValidityErrorFor(c, fmt.Sprintf("intermediate %d", i+1), now); err != nil {
			return err
		}
	}
	return nil
}

// managementTLSCertificatePreflightError is the full #15667 preflight:
// every chain entry inside its validity window, leaf is not a CA and
// carries ServerAuth (an absent ExtKeyUsage list means any usage and is
// accepted, matching x509 semantics), every non-leaf entry is a CA
// allowed to sign certificates, and every adjacent signature link
// verifies (chain[i] was signed by chain[i+1]; the final entry, when
// self-signed, must also verify against itself). Trust to a root is
// deliberately NOT required: management clients pin/self-sign.
func managementTLSCertificatePreflightError(chain []*x509.Certificate, now time.Time) error {
	if err := managementTLSCertificateChainValidityError(chain, now); err != nil {
		return err
	}
	leaf := chain[0]
	if leaf.IsCA {
		return fmt.Errorf("leaf certificate is a CA certificate (BasicConstraints CA=true); a CA certificate must not be served as the management TLS leaf")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("leaf certificate does not allow ServerAuth extended key usage (ExtKeyUsage %v)", leaf.ExtKeyUsage)
		}
	}
	for i, c := range chain[1:] {
		role := fmt.Sprintf("intermediate %d", i+1)
		if !c.IsCA || !c.BasicConstraintsValid {
			return fmt.Errorf("certificate chain %s is not a CA certificate (subject %q)", role, c.Subject.String())
		}
		if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("certificate chain %s does not allow certificate signing (subject %q, KeyUsage %v)", role, c.Subject.String(), c.KeyUsage)
		}
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("certificate chain signature link %d->%d does not verify: %w", i, i+1, err)
		}
	}
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		if err := last.CheckSignatureFrom(last); err == nil {
			// Self-signed final entry verified against itself; nothing more.
		} else if len(chain) == 1 {
			// A single self-signed leaf failing its own check has a
			// corrupted signature (CheckSignatureFrom also enforces the
			// parent IsCA constraint, which a non-CA leaf fails for an
			// unrelated reason, so only report when it is a signature
			// failure on a CA-shaped leaf).
			if last.IsCA {
				return fmt.Errorf("certificate chain signature link 0->0 does not verify: %w", err)
			}
		}
		// A non-self-signed final root/intermediate is not an error:
		// its issuer is simply not in the presented chain (normal for
		// chains that omit the root).
	}
	// A non-CA leaf whose key usage is signing-only is rejected even
	// though IsCA is false.
	if !leaf.IsCA && leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageCertSign != 0 &&
		leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 && len(leaf.ExtKeyUsage) == 0 {
		return fmt.Errorf("leaf certificate key usage is restricted to certificate signing")
	}
	return nil
}

// managementTLSSANDiagnostic returns a human-readable SAN summary for
// logs, or the no-SAN marker when the leaf carries no SANs at all.
func managementTLSSANDiagnostic(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 && len(leaf.URIs) == 0 && len(leaf.EmailAddresses) == 0 {
		return "no subjectAltName (covers nothing for modern clients)"
	}
	ips := make([]string, 0, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	return fmt.Sprintf("dns=%v ip=%v", leaf.DNSNames, ips)
}

func managementTLSCertificateFingerprint(cert tls.Certificate) [32]byte {
	hash := sha256.New()
	for _, der := range cert.Certificate {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(der)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(der)
	}
	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(fingerprint[:0]))
	return fingerprint
}

func managementTLSCertificateValidityError(leaf *x509.Certificate, now time.Time) error {
	return managementTLSCertificateValidityErrorFor(leaf, "leaf", now)
}

func newManagementTLSCertificateState(cert tls.Certificate, source, bindHost string) (*managementTLSCertificateState, error) {
	cert, leaf, chain, err := managementTLSCertificateChain(cert)
	if err != nil {
		return nil, err
	}
	return &managementTLSCertificateState{
		certificate: cert,
		leaf:        leaf,
		chain:       chain,
		fingerprint: managementTLSCertificateFingerprint(cert),
		bindHost:    bindHost,
		source:      source,
	}, nil
}

func (s *Server) managementTLSNow() time.Time {
	if s.tlsNow != nil {
		return s.tlsNow()
	}
	return time.Now()
}

func (s *Server) managementTLSFiles() *managementTLSCertificateFiles {
	files := s.tlsCertificateFiles.Load()
	if files == nil {
		return &managementTLSCertificateFiles{}
	}
	return files
}

func managementTLSBindHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// bindHostsForCertGen returns the host set a cert mint/load must cover
// (#14984 D36-04, #15228 A44-04): the union of the server's configured
// HTTPS bind hosts AND the live/requested legs' hosts, so a reconcile
// that grows the set (single-stack construction -> dual-stack reconcile)
// mints a fresh cert covering every leg, not only the construction set.
// Ordering is deterministic: configured hosts first, then bindHost,
// then any serving/requested leg hosts not already present.
func bindHostsForCertGen(s *Server, bindHost string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(h string) {
		if h == "" {
			return
		}
		if _, dup := seen[h]; dup {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	if s != nil && s.httpsBindHosts != nil {
		for _, h := range s.httpsBindHosts() {
			add(h)
		}
	}
	add(bindHost)
	if s != nil {
		// Live legs (requested srv.Addr) — covers reconciles that have
		// already installed/queued a leg for a new host before its cert
		// is (re)built, and SetTLSCertDirForTest reloads.
		for _, leg := range s.httpsLegs {
			if leg != nil && leg.srv != nil {
				if h, _, err := net.SplitHostPort(leg.srv.Addr); err == nil {
					add(h)
				}
			}
		}
		for _, srv := range s.httpsServers {
			if srv != nil {
				if h, _, err := net.SplitHostPort(srv.Addr); err == nil {
					add(h)
				}
			}
		}
	}
	return out
}

// loadManagementTLSCertificate locks tlsCertificateMu (buildHTTPSServer
// calls loadManagementTLSCertificateLocked directly to also install the
// per-leg slot atomically, #14984).
func (s *Server) loadManagementTLSCertificate(addr string) (*managementTLSCertificateState, error) {
	s.tlsCertificateMu.Lock()
	defer s.tlsCertificateMu.Unlock()
	return s.loadManagementTLSCertificateWithGen(s.certGen, addr)
}

func (s *Server) loadManagementTLSCertificateLocked(addr string) (*managementTLSCertificateState, error) {
	return s.loadManagementTLSCertificateWithGen(s.certGen, addr)
}

func (s *Server) loadManagementTLSCertificateWithGen(gen func(bindHosts []string) (tls.Certificate, *x509.Certificate, error), addr string) (*managementTLSCertificateState, error) {
	files := s.managementTLSFiles()
	bindHost := managementTLSBindHost(addr)
	now := s.managementTLSNow()
	if files.custom() {
		if files.certificate == "" || files.privateKey == "" {
			err := fmt.Errorf("custom management TLS requires both certificate and private-key paths")
			s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, nil, err, now)
			return nil, err
		}
		cert, err := tls.LoadX509KeyPair(files.certificate, files.privateKey)
		if err != nil {
			err = fmt.Errorf("load custom management TLS certificate/key pair: %w", err)
			s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, nil, err, now)
			return nil, err
		}
		state, err := newManagementTLSCertificateState(cert, managementTLSCertificateCustom, bindHost)
		if err != nil {
			s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, nil, err, now)
			return nil, err
		}
		if err := managementTLSCertificatePreflightError(state.chain, now); err != nil {
			s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, state.leaf, err, now)
			return nil, err
		}
		slog.Info("custom management TLS certificate loaded", "source", managementTLSCertificateCustom, "bind_host", bindHost, "leaf_subject", state.leaf.Subject.String(), "sans", managementTLSSANDiagnostic(state.leaf), "chain_length", len(state.chain))
		return state, nil
	}

	// #14984: mint/load with EVERY bind host this server's HTTPS legs are
	// configured for, so the durable pair's SAN set unions both families
	// (fall back to this addr's host when the configured set is empty).
	genHosts := bindHostsForCertGen(s, bindHost)
	cert, invalidLoadedLeaf, err := gen(genHosts)
	if invalidLoadedLeaf != nil && err == nil {
		s.reportManagementTLSCertificateRemint(invalidLoadedLeaf, bindHost, now)
	}
	if err != nil {
		err = fmt.Errorf("generate system management TLS certificate: %w", err)
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, invalidLoadedLeaf, err, now)
		return nil, err
	}
	state, err := newManagementTLSCertificateState(cert, managementTLSCertificateGenerated, bindHost)
	if err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, nil, err, now)
		return nil, err
	}
	if err := managementTLSCertificatePreflightError(state.chain, now); err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, state.leaf, err, now)
		return nil, err
	}
	return state, nil
}

// installManagementTLSCertificate writes ONLY the fallback slot (#14984
// D36-04: it used to also store into the shared atomic every leg's
// handshake read, so the second-built dual-stack leg overwrote the
// first family's bind-host SANs; the per-leg closures installed by
// buildHTTPSServer now serve their own state held by the callers).
func (s *Server) installManagementTLSCertificate(state *managementTLSCertificateState) {
	s.tlsCertificateSlot.state.Store(state)
	s.tlsCertificateInvalid.Store(false)
	if s.tlsDesiredConfigured.Load() {
		s.tlsDesired.Store(true)
	}
}

func (s *Server) failManagementTLSCertificate(source, bindHost string, leaf *x509.Certificate, err error, now time.Time) {
	state := &managementTLSCertificateState{
		leaf:     leaf,
		bindHost: bindHost,
		source:   source,
		invalid:  true,
		reason:   err.Error(),
	}
	if leaf != nil {
		state.fingerprint = sha256.Sum256(leaf.Raw)
	}
	s.tlsCertificateSlot.state.Store(state)
	if s.tlsCertificateInvalid.CompareAndSwap(false, true) {
		managementTLSCertificateInvalidEvents.Add(1)
		slog.Error("management TLS certificate is outside its validity window or unusable",
			"source", source, "bind_host", bindHost, "not_before", certificateTime(leaf, true),
			"not_after", certificateTime(leaf, false), "now", now.UTC().Format(time.RFC3339), "sans", managementTLSSANDiagnostic(leaf), "err", err)
	}
}

func (s *Server) reportManagementTLSCertificateRemint(leaf *x509.Certificate, bindHost string, now time.Time) {
	managementTLSCertificateInvalidEvents.Add(1)
	slog.Error("loaded system-generated management TLS certificate is outside its validity window; re-minted",
		"bind_host", bindHost, "not_before", certificateTime(leaf, true),
		"not_after", certificateTime(leaf, false), "now", now.UTC().Format(time.RFC3339))
}

func certificateTime(leaf *x509.Certificate, notBefore bool) string {
	if leaf == nil {
		return ""
	}
	if notBefore {
		return leaf.NotBefore.UTC().Format(time.RFC3339)
	}
	return leaf.NotAfter.UTC().Format(time.RFC3339)
}

// managementTLSGetCertificate serves the FALLBACK slot (#14984 D36-04).
// Production handshakes use managementTLSGetCertificateFor, whose state is
// owned by the leg's own closure.
func (s *Server) managementTLSGetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.managementTLSGetCertificateFromSlot(&s.tlsCertificateSlot)
}

func (s *Server) managementTLSGetCertificateFor(slot *managementTLSCertificateSlot) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return s.managementTLSGetCertificateFromSlot(slot)
	}
}

func (s *Server) managementTLSGetCertificateFromSlot(slot *managementTLSCertificateSlot) (*tls.Certificate, error) {
	if slot == nil {
		return nil, fmt.Errorf("management TLS certificate is unavailable")
	}
	state := slot.state.Load()
	if state == nil {
		return nil, fmt.Errorf("management TLS certificate is unavailable")
	}
	if state.invalid {
		return nil, fmt.Errorf("management TLS certificate is unavailable: %s", state.reason)
	}
	now := s.managementTLSNow()
	if err := managementTLSCertificatePreflightError(state.chain, now); err != nil {
		// Mark THIS slot invalid: a stale leg must not poison a live
		// sibling's state (the pre-#14984 shared-store failure). The
		// fallback likewise records the incident so the monitor and
		// ReconcileTLSCertificate still see an expired serving plane.
		iv := &managementTLSCertificateState{leaf: state.leaf, chain: state.chain, bindHost: state.bindHost, source: state.source, invalid: true, reason: err.Error()}
		if state.leaf != nil {
			iv.fingerprint = sha256.Sum256(state.leaf.Raw)
		}
		slot.state.Store(iv)
		if slot == &s.tlsCertificateSlot {
			if s.tlsCertificateInvalid.CompareAndSwap(false, true) {
				managementTLSCertificateInvalidEvents.Add(1)
				slog.Error("management TLS certificate is outside its validity window or unusable",
					"source", state.source, "bind_host", state.bindHost,
					"not_before", certificateTime(state.leaf, true),
					"not_after", certificateTime(state.leaf, false),
					"now", now.UTC().Format(time.RFC3339), "err", err)
			}
		} else if s.tlsCertificateInvalid.CompareAndSwap(false, true) {
			managementTLSCertificateInvalidEvents.Add(1)
			slog.Error("management TLS certificate is outside its validity window or unusable",
				"source", state.source, "bind_host", state.bindHost,
				"not_before", certificateTime(state.leaf, true),
				"not_after", certificateTime(state.leaf, false),
				"now", now.UTC().Format(time.RFC3339), "err", err)
			s.tlsCertificateSlot.state.Store(iv)
		}
		return nil, err
	}
	return &state.certificate, nil
}

func (s *Server) refreshManagementTLSCertificate() {
	s.tlsCertificateMu.Lock()
	defer s.tlsCertificateMu.Unlock()
	s.refreshManagementTLSCertificateLocked()
}

func (s *Server) refreshManagementTLSCertificateLocked() {
	if !s.tlsDesired.Load() && !s.tlsDesiredConfigured.Load() {
		return
	}
	files := s.managementTLSFiles()
	current := s.tlsCertificateSlot.state.Load()
	now := s.managementTLSNow()
	if files.custom() {
		s.refreshCustomManagementTLSCertificate(files, current, now)
		return
	}

	invalidAlreadyCounted := current != nil && current.invalid
	if current != nil && current.source == managementTLSCertificateGenerated && !current.invalid {
		if err := managementTLSCertificatePreflightError(current.chain, now); err == nil {
			return
		} else {
			s.failManagementTLSCertificate(current.source, current.bindHost, current.leaf, err, now)
			invalidAlreadyCounted = true
		}
	}
	bindHost := ""
	if current != nil {
		bindHost = current.bindHost
	}
	// The fallback slot has no leg of its own (#14984 D36-04): when it has
	// never been installed, mint against ONE dual-stack-wide state covering
	// every configured HTTPS bind host (second-awareness: several entries
	// must not re-collapse to the first), not one family's leftover.
	if bindHost == "" && s.httpsBindHosts != nil {
		if hosts := s.httpsBindHosts(); len(hosts) > 0 {
			bindHost = hosts[0]
		}
	}
	cert, invalidLoadedLeaf, err := s.certGen(bindHostsForCertGen(s, bindHost))
	if invalidLoadedLeaf != nil && err == nil && !invalidAlreadyCounted {
		s.reportManagementTLSCertificateRemint(invalidLoadedLeaf, bindHost, now)
	}
	if err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, invalidLoadedLeaf, err, now)
		return
	}
	state, err := newManagementTLSCertificateState(cert, managementTLSCertificateGenerated, bindHost)
	if err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, nil, err, now)
		return
	}
	if err := managementTLSCertificatePreflightError(state.chain, now); err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, state.leaf, err, now)
		return
	}
	s.installManagementTLSCertificate(state)
	s.publishManagementTLSCertificateToLiveLegs(state)
	s.recoverHTTPSLegsIfNeededLocked()
}

// publishManagementTLSCertificateToLiveLegs mirrors state into every live
// HTTPS leg's registered slot (#14984 D36-04). The monitor-driven refresh
// path publishes the same rotated pair to all families; per-buildFamily
// first mints stay in the per-leg slot built by buildHTTPSServer.
// Callers hold tlsCertificateMu.
func (s *Server) publishManagementTLSCertificateToLiveLegs(state *managementTLSCertificateState) {
	httpServerTLSState.Range(func(_, v any) bool {
		if cs, ok := v.(*managementTLSCertificateSlot); ok {
			cs.state.Store(state)
		}
		return true
	})
}

// recoverHTTPSLegsIfNeededLocked creates HTTPS legs that were never
// built because the initial certificate load failed (#15667). The
// periodic monitor calls it (via refresh) after a successful reload
// when no leg is serving but TLS is configured-desired and the server
// has a root context and configured HTTPS templates. It is a no-op
// when any template leg is already serving, when there are no
// templates (ReconcileHTTPSAddrs-built servers), or when no root
// context exists (Run/serveBound path). Callers hold tlsCertificateMu;
// it takes lifeMu — the only place that nests lifeMu inside
// tlsCertificateMu (buildHTTPSServer never runs under this call: legs
// are built directly from the already-validated state).
func (s *Server) recoverHTTPSLegsIfNeededLocked() {
	// tlsDesired is armed by installManagementTLSCertificate just
	// before this runs, so it cannot gate recovery; the configured
	// desire plus the absence of a serving leg is the gate.
	if !s.tlsDesiredConfigured.Load() {
		return
	}
	if len(s.httpsDesiredAddrs) == 0 || s.rootCtx == nil {
		return
	}
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if len(s.httpsLegs) > 0 {
		for _, leg := range s.httpsLegs {
			if leg.serving() {
				return
			}
		}
	}
	state := s.tlsCertificateSlot.state.Load()
	if state == nil || state.invalid {
		return
	}
	// Templates may be missing entirely (the boot failure shape:
	// NewServer breaks before appending any httpsServer), so fall back
	// to the recorded desired addresses and build fresh legs.
	addrs := make([]string, len(s.httpsDesiredAddrs))
	copy(addrs, s.httpsDesiredAddrs)
	var legs []*listenerLeg
	var servers []*http.Server
	var slots []*authSlot
	for i, addr := range addrs {
		var srv *http.Server
		if i < len(s.httpsServers) && s.httpsServers[i] != nil {
			srv = s.httpsServers[i]
		}
		ln, err := s.listen("tcp", addr)
		if err != nil {
			slog.Error("api: HTTPS listener bind failed during certificate recovery; HTTPS disabled until the next reconcile", "addr", addr, "err", err)
			legs = append(legs, nil)
			servers = append(servers, srv)
			slots = append(slots, nil)
			continue
		}
		if srv == nil {
			slot := s.newAuthSlot()
			legSlot := &managementTLSCertificateSlot{}
			legSlot.state.Store(state)
			srv = trackHijackedConns(&http.Server{
				Addr: addr, Handler: s.listenerHandler(addr, slot),
				ReadHeaderTimeout: apiReadHeaderTimeout, ReadTimeout: apiReadTimeout,
				IdleTimeout: apiIdleTimeout, MaxHeaderBytes: apiMaxHeaderBytes,
				ConnContext: s.connContextForAuthSlot(slot),
				TLSConfig:   &tls.Config{GetCertificate: s.managementTLSGetCertificateFor(legSlot), MinVersion: tls.VersionTLS12},
			})
			RegisterHTTPServerTLSState(srv, legSlot)
			legs = append(legs, s.serveLegLocked(legPlan{srv: srv, slot: slot}, ln, true))
			servers = append(servers, srv)
			slots = append(slots, slot)
		} else {
			legSlot := &managementTLSCertificateSlot{}
			legSlot.state.Store(state)
			if srv.TLSConfig != nil {
				srv.TLSConfig.GetCertificate = s.managementTLSGetCertificateFor(legSlot)
			}
			RegisterHTTPServerTLSState(srv, legSlot)
			plan := s.httpsLegPlanAt(i)
			legs = append(legs, s.serveLegLocked(plan, ln, true))
			servers = append(servers, srv)
			slots = append(slots, plan.slot)
		}
		slog.Info("HTTPS API server listening (recovered after certificate load)", "addr", addr)
	}
	s.httpsLegs = legs
	s.httpsServers = servers
	s.httpsSlots = slots
}

// ReconcileTLSCertificate installs new operator-provided paths from a committed
// web-management configuration. When HTTPS is serving, the new pair is loaded
// and validated before this method returns; an invalid custom pair marks the
// shared selector unavailable, so existing TLS listeners fail closed.
func (s *Server) ReconcileTLSCertificate(certificate, privateKey string) error {
	next := &managementTLSCertificateFiles{certificate: certificate, privateKey: privateKey}
	if !customTLSPathsEqual(s.managementTLSFiles(), next) {
		s.tlsCertificateFiles.Store(next)
	}
	if !s.tlsDesired.Load() {
		return nil
	}
	// #14984: holding tlsCertificateMu makes refreshManagementTLSCertificateLocked
	// atomic with the fallback read-back; refreshManagementTLSCertificate would
	// self-deadlock if re-locked here.
	s.tlsCertificateMu.Lock()
	s.refreshManagementTLSCertificateLocked()
	state := s.tlsCertificateSlot.state.Load()
	s.tlsCertificateMu.Unlock()
	if state == nil || state.invalid {
		if state != nil {
			return fmt.Errorf("management TLS certificate is unavailable: %s", state.reason)
		}
		return fmt.Errorf("management TLS certificate is unavailable")
	}
	return nil
}

func (s *Server) managementTLSCertificateForServer(srv *http.Server) *tls.Certificate {
	if srv == nil || srv.TLSConfig == nil {
		return nil
	}
	if srv.TLSConfig.GetCertificate == nil {
		if len(srv.TLSConfig.Certificates) == 0 {
			return nil
		}
		return &srv.TLSConfig.Certificates[0]
	}
	// Per-leg selector (#14984 D36-04): the leg's own closure carries its
	// bind-host SANs; the shared fallback slot would return whichever legs'
	// state was written last. A hand-built srv whose closure was swapped
	// to the plain managementTLSGetCertificate method value still resolves
	// to the fallback slot by construction.
	if st := managementTLSStateForServer(srv); st != nil {
		if st.invalid {
			return nil
		}
		return &st.certificate
	}
	state := s.tlsCertificateSlot.state.Load()
	if state == nil || state.invalid {
		return nil
	}
	return &state.certificate
}

func managementTLSStateForServer(srv *http.Server) *managementTLSCertificateState {
	if srv == nil || srv.TLSConfig == nil || srv.TLSConfig.GetCertificate == nil {
		return nil
	}
	if st, ok := httpServerTLSState.Load(srv); ok && st != nil {
		if slot, ok2 := st.(*managementTLSCertificateSlot); ok2 {
			return slot.state.Load()
		}
	}
	return nil
}

func (s *Server) refreshCustomManagementTLSCertificate(files *managementTLSCertificateFiles, current *managementTLSCertificateState, now time.Time) {
	bindHost := ""
	if current != nil {
		bindHost = current.bindHost
	}
	if files.certificate == "" || files.privateKey == "" {
		s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, nil,
			fmt.Errorf("custom management TLS requires both certificate and private-key paths"), now)
		return
	}
	cert, err := tls.LoadX509KeyPair(files.certificate, files.privateKey)
	if err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, nil,
			fmt.Errorf("load custom management TLS certificate/key pair: %w", err), now)
		return
	}
	state, err := newManagementTLSCertificateState(cert, managementTLSCertificateCustom, bindHost)
	if err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, nil, err, now)
		return
	}
	if err := managementTLSCertificatePreflightError(state.chain, now); err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, state.leaf, err, now)
		return
	}
	if current != nil && current.source == managementTLSCertificateCustom &&
		current.fingerprint == state.fingerprint && !current.invalid {
		return
	}
	s.installManagementTLSCertificate(state)
	s.publishManagementTLSCertificateToLiveLegs(state)
	s.recoverHTTPSLegsIfNeededLocked()
	if current != nil && current.fingerprint != state.fingerprint {
		slog.Info("custom management TLS certificate rotated", "not_after", state.leaf.NotAfter.UTC().Format(time.RFC3339), "sans", managementTLSSANDiagnostic(state.leaf))
	}
}

func (s *Server) startManagementTLSCertificateMonitor(ctx context.Context) {
	if ctx == nil {
		return
	}
	s.tlsMonitorOnce.Do(func() {
		monitorCtx, cancel := context.WithCancel(ctx)
		s.tlsMonitorCancel = cancel
		interval := s.tlsCheckInterval
		if interval <= 0 {
			interval = managementTLSCertificateCheckInterval
		}
		s.tlsMonitorWG.Add(1)
		go func() {
			defer s.tlsMonitorWG.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-monitorCtx.Done():
					return
				case <-ticker.C:
					s.refreshManagementTLSCertificate()
				}
			}
		}()
	})
}

func customTLSPathsEqual(a, b *managementTLSCertificateFiles) bool {
	if a == nil {
		a = &managementTLSCertificateFiles{}
	}
	if b == nil {
		b = &managementTLSCertificateFiles{}
	}
	return a.certificate == b.certificate && a.privateKey == b.privateKey
}

// httpServerTLSState maps a per-leg *http.Server to its certificate slot
// (#14984 D36-04). The registry exists because tls.Config.GetCertificate is
// an opaque func value: the leg's closure is bound to its slot inside
// buildHTTPSServer and this map is how managementTLSCertificateForServer
// finds that slot for WarnStale/HTTPSCertForTest reads. It is keyed by the
// *http.Server pointer (not Addr) so two legs that survive each other
// never alias. Rate: bounded by the live leg set's size (one entry per
// bound HTTPS address); entries are deleted when a leg retires so the
// map does not grow across reconciles.
var httpServerTLSState sync.Map // *http.Server -> *managementTLSCertificateSlot

func RegisterHTTPServerTLSState(srv *http.Server, slot *managementTLSCertificateSlot) {
	if srv != nil && slot != nil {
		httpServerTLSState.Store(srv, slot)
	}
}

func unregisterHTTPServerTLSState(srv *http.Server) {
	if srv != nil {
		httpServerTLSState.Delete(srv)
	}
}
