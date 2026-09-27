package ddns

import (
	"context"
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// WithdrawForReset removes records owned by the DHCP-lease DDNS surface before
// a factory reset can erase its durable cleanup authority. Every delete uses
// only a live backend whose BackendFingerprint matches the stored record; an
// unknown, changed, or unreachable endpoint leaves ownership intact and fails
// the reset closed.
func (m *Manager) WithdrawForReset(ctx context.Context, cfg *config.DHCPServerConfig) error {
	if m == nil {
		return nil
	}
	var ddns4, ddns6 *config.DHCPDynamicDNSConfig
	if cfg != nil {
		ddns4, ddns6 = cfg.DynamicDNS, cfg.DynamicDNSv6
	}
	if ddns4 == nil && ddns6 != nil {
		ddns4 = ddns6
	} else if ddns6 == nil && ddns4 != nil {
		ddns6 = ddns4
	}
	policies := [2]ddnsPolicy{policyFromConfig(ddns4), policyFromConfig(ddns6)}
	configs := [2]*config.DHCPDynamicDNSConfig{ddns4, ddns6}

	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.rebuildWireRRClaimsLocked()
	if m.degraded {
		return fmt.Errorf("ddns: cannot withdraw for factory reset while ownership state is degraded: %s", m.degradedReason)
	}

	var errs []error
	for _, owned := range m.state.all() {
		if owned.BackendFingerprint == "" {
			errs = append(errs, fmt.Errorf("ddns: cannot prove the publish backend for %s during factory reset", owned.FQDN))
			continue
		}
		idx := famIdx(owned.Family)
		var updater DNSUpdater
		currentFP := dhcpBackendFingerprint(policies[idx], configs[idx])
		if currentFP != "" && currentFP == owned.BackendFingerprint && m.newUpdater != nil {
			updater, _ = m.newUpdater(policies[idx], configs[idx])
		}
		// The live, in-process anchor is safe only when its saved identity proves
		// it is the endpoint that published this record. This also supports a
		// disabled/changed current config without ever routing a delete to its
		// different endpoint.
		if updater == nil || isNopUpdater(updater) {
			anchor := m.lastLiveUpdater[idx]
			if anchor != nil && !isNopUpdater(anchor) && m.lastLiveFP[idx] == owned.BackendFingerprint {
				updater = anchor
			}
		}
		if updater == nil || isNopUpdater(updater) {
			errs = append(errs, fmt.Errorf("ddns: cannot safely withdraw %s for factory reset: no live backend matches its stored fingerprint", owned.FQDN))
			continue
		}
		if err := m.deleteOwnedLocked(ctx, updater, owned); err != nil {
			errs = append(errs, fmt.Errorf("ddns: factory-reset withdrawal for %s: %w", owned.FQDN, err))
		}
	}
	if err := m.state.save(); err != nil {
		errs = append(errs, fmt.Errorf("ddns: persist factory-reset withdrawals: %w", err))
	}
	if remaining := m.state.all(); len(remaining) != 0 && len(errs) == 0 {
		errs = append(errs, fmt.Errorf("ddns: %d published record(s) remain after factory-reset withdrawal", len(remaining)))
	}
	return errors.Join(errs...)
}

// WithdrawForReset removes Surface A records through exactly the provider
// endpoint their stored BackendFingerprint identifies. Changed, missing, or
// unknown providers leave ownership intact and fail reset closed.
func (m *SurfaceAManager) WithdrawForReset(ctx context.Context, catalog map[string]*config.DDNSProvider) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.rebuildWireRRClaimsLocked()
	if m.degraded {
		return fmt.Errorf("ddns surface-a: cannot withdraw for factory reset while ownership state is degraded: %s", m.degradedReason)
	}

	var errs []error
	for _, owned := range m.state.all() {
		if targets := m.withdrawTargets(owned); len(targets) == 0 {
			errs = append(errs, fmt.Errorf("ddns surface-a: cannot safely withdraw %s for factory reset: no parseable published address is recorded", owned.FQDN))
			continue
		}
		if owned.BackendFingerprint == "" {
			errs = append(errs, fmt.Errorf("ddns surface-a: cannot prove the publish backend for %s during factory reset", owned.FQDN))
			continue
		}
		provider := catalog[owned.scopeOf().PolicyID]
		if provider == nil {
			errs = append(errs, fmt.Errorf("ddns surface-a: cannot safely withdraw %s for factory reset: provider %q is unavailable", owned.FQDN, owned.scopeOf().PolicyID))
			continue
		}
		if currentFP := backendFingerprint(provider); currentFP == "" || currentFP != owned.BackendFingerprint {
			errs = append(errs, fmt.Errorf("ddns surface-a: cannot safely withdraw %s for factory reset: provider fingerprint does not match stored ownership", owned.FQDN))
			continue
		}
		if m.newBackend == nil {
			errs = append(errs, fmt.Errorf("ddns surface-a: cannot safely withdraw %s for factory reset: no provider backend factory", owned.FQDN))
			continue
		}
		backend, err := m.newBackend(provider, owned.FQDN, owned.TTL)
		if err != nil || backend == nil || isNopUpdater(backend) {
			if err == nil {
				err = errors.New("provider resolved to no live backend")
			}
			errs = append(errs, fmt.Errorf("ddns surface-a: resolve factory-reset backend for %s: %w", owned.FQDN, err))
			continue
		}
		if err := m.withdrawOwnedLocked(ctx, owned, backend); err != nil {
			errs = append(errs, fmt.Errorf("ddns surface-a: factory-reset withdrawal for %s: %w", owned.FQDN, err))
		}
	}
	if err := m.state.save(); err != nil {
		errs = append(errs, fmt.Errorf("ddns surface-a: persist factory-reset withdrawals: %w", err))
	}
	if remaining := m.state.all(); len(remaining) != 0 && len(errs) == 0 {
		errs = append(errs, fmt.Errorf("ddns surface-a: %d published record(s) remain after factory-reset withdrawal", len(remaining)))
	}
	return errors.Join(errs...)
}
