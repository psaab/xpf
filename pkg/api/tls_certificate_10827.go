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
	fingerprint [32]byte
	bindHost    string
	source      string
	invalid     bool
	reason      string
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
	if leaf == nil {
		return fmt.Errorf("certificate has no parsed leaf")
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("certificate is not valid yet: now %s is before NotBefore %s",
			now.UTC().Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate has expired: now %s is after NotAfter %s",
			now.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func newManagementTLSCertificateState(cert tls.Certificate, source, bindHost string) (*managementTLSCertificateState, error) {
	cert, leaf, err := managementTLSCertificateLeaf(cert)
	if err != nil {
		return nil, err
	}
	return &managementTLSCertificateState{
		certificate: cert,
		leaf:        leaf,
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

func (s *Server) loadManagementTLSCertificate(addr string) (*managementTLSCertificateState, error) {
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
		if err := managementTLSCertificateValidityError(state.leaf, now); err != nil {
			s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, state.leaf, err, now)
			return nil, err
		}
		return state, nil
	}

	cert, invalidLoadedLeaf, err := s.certGen(bindHost)
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
	if err := managementTLSCertificateValidityError(state.leaf, now); err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, state.leaf, err, now)
		return nil, err
	}
	return state, nil
}

func (s *Server) installManagementTLSCertificate(state *managementTLSCertificateState) {
	s.tlsCertificate.Store(state)
	s.tlsCertificateInvalid.Store(false)
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
	s.tlsCertificate.Store(state)
	if s.tlsCertificateInvalid.CompareAndSwap(false, true) {
		managementTLSCertificateInvalidEvents.Add(1)
		slog.Error("management TLS certificate is outside its validity window or unusable",
			"source", source, "bind_host", bindHost, "not_before", certificateTime(leaf, true),
			"not_after", certificateTime(leaf, false), "now", now.UTC().Format(time.RFC3339), "err", err)
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

func (s *Server) managementTLSGetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	state := s.tlsCertificate.Load()
	if state == nil {
		return nil, fmt.Errorf("management TLS certificate is unavailable")
	}
	if state.invalid {
		return nil, fmt.Errorf("management TLS certificate is unavailable: %s", state.reason)
	}
	now := s.managementTLSNow()
	if err := managementTLSCertificateValidityError(state.leaf, now); err != nil {
		s.failManagementTLSCertificate(state.source, state.bindHost, state.leaf, err, now)
		return nil, err
	}
	return &state.certificate, nil
}

func (s *Server) refreshManagementTLSCertificate() {
	s.tlsCertificateMu.Lock()
	defer s.tlsCertificateMu.Unlock()
	if !s.tlsDesired.Load() {
		return
	}
	files := s.managementTLSFiles()
	current := s.tlsCertificate.Load()
	now := s.managementTLSNow()
	if files.custom() {
		s.refreshCustomManagementTLSCertificate(files, current, now)
		return
	}

	invalidAlreadyCounted := current != nil && current.invalid
	if current != nil && current.source == managementTLSCertificateGenerated && !current.invalid {
		if err := managementTLSCertificateValidityError(current.leaf, now); err == nil {
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
	cert, invalidLoadedLeaf, err := s.certGen(bindHost)
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
	if err := managementTLSCertificateValidityError(state.leaf, now); err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateGenerated, bindHost, state.leaf, err, now)
		return
	}
	s.installManagementTLSCertificate(state)
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
	s.refreshManagementTLSCertificate()
	state := s.tlsCertificate.Load()
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
	state := s.tlsCertificate.Load()
	if state == nil || state.invalid {
		return nil
	}
	return &state.certificate
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
	if err := managementTLSCertificateValidityError(state.leaf, now); err != nil {
		s.failManagementTLSCertificate(managementTLSCertificateCustom, bindHost, state.leaf, err, now)
		return
	}
	if current != nil && current.source == managementTLSCertificateCustom &&
		current.fingerprint == state.fingerprint && !current.invalid {
		return
	}
	s.installManagementTLSCertificate(state)
	if current != nil && current.fingerprint != state.fingerprint {
		slog.Info("custom management TLS certificate rotated", "not_after", state.leaf.NotAfter.UTC().Format(time.RFC3339))
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
