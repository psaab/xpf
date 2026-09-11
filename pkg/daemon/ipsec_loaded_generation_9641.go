package daemon

// ipsec_loaded_generation_9641.go — HA IPsec attribution reads the generation charon
// itself says it loaded when this process holds no record of one (#9641).
//
// The record (ipsecLoadedCfg, #9511) is set only by a successful load in THIS process
// and cleared as soon as a new swanctl file is written. Two states leave it empty while
// charon runs a definite generation:
//
//   - after an xpfd restart whose boot IPsec apply failed, charon still runs the
//     generation the previous xpfd process loaded;
//   - in the failed-reload window, charon runs the previous generation until its own
//     next start or reload loads the new file (strongswan.service ExecStartPost and
//     ExecReload run `swanctl --load-all`).
//
// Before #9641 both fell back to the promoted config, which in each case can be a
// generation charon is not running. Now every file xpf writes names its generation in
// charon (ipsec.ApplyGeneration, an inert marker pool), and this file reads it back.
//
// The marker is IDENTITY, not proof: `swanctl --load-all` is not a transaction, so a
// partial load can leave the marker and the connections at different generations. The
// named generation is used only when charon's loaded connections are exactly what that
// generation renders (ipsec.ExpectedLoadedConns). Every other outcome (charon cannot be
// asked, no marker or an unknown one, a generation this node no longer retains, one
// whose local addresses cannot be replayed, or a mismatch) falls back to the promoted
// config, which is exactly what attribution did before.
//
// RESIDUAL. A generation change that renders IDENTICAL connections (an RG move that
// keeps an explicit local address) combined with a partial load that loaded the pools
// but not the connections: validation cannot tell the two generations apart. It needs
// both a partial load and a render-identical change.

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// ipsecGenerationCache pairs a generation marker token with the compiled config the
// store resolved it to.
type ipsecGenerationCache struct {
	gen string
	cfg *config.Config
}

// ipsecApplyGeneration names the generation an IPsec apply of cfg writes into charon:
// the store's digest of its active config when cfg IS that config, and
// ipsec.UnknownGeneration otherwise (which always falls back).
func (d *Daemon) ipsecApplyGeneration(cfg *config.Config) string {
	if d.store != nil {
		if digest := d.store.ActiveDigestFor(cfg); digest != "" {
			return digest
		}
	}
	return ipsec.UnknownGeneration
}

// ipsecMarkedGeneration returns the config of the generation charon's marker names, when
// this node still retains that generation AND charon's loaded connections are exactly
// what it renders. nil means charon cannot tell us, and the caller keeps its fallback.
// It asks charon twice (list-pools, list-conns), so it runs only when there is no record.
func (d *Daemon) ipsecMarkedGeneration() *config.Config {
	if d.ipsec == nil || d.store == nil {
		return nil
	}
	gen, err := d.ipsec.LoadedGeneration()
	if err != nil {
		d.noteIPsecGeneration("charon names no single generation", err)
		return nil
	}
	if gen == ipsec.UnknownGeneration {
		d.noteIPsecGeneration("charon's marker names an unknown generation", nil)
		return nil
	}
	cfg := d.retainedIPsecGeneration(gen)
	if cfg == nil {
		d.noteIPsecGeneration("charon's generation is not retained on this node", nil)
		return nil
	}
	want, err := ipsec.ExpectedLoadedConns(cfg)
	if err != nil {
		d.noteIPsecGeneration("charon's generation cannot be validated", err)
		return nil
	}
	have, err := d.ipsec.ListLoadedConns()
	if err != nil {
		d.noteIPsecGeneration("charon's loaded connections are unavailable", err)
		return nil
	}
	if !have.Equal(want) {
		d.noteIPsecGeneration("charon's loaded connections do not match its marked generation", nil)
		return nil
	}
	d.noteIPsecGeneration("", nil)
	return cfg
}

// retainedIPsecGeneration resolves a marker token to a compiled config through the
// store, caching the last hit so a takeover wave (one pass per redundancy group)
// recompiles an older generation once. A miss is not cached: it is re-asked next pass.
func (d *Daemon) retainedIPsecGeneration(gen string) *config.Config {
	if c := d.ipsecGeneration.Load(); c != nil && c.gen == gen {
		return c.cfg
	}
	cfg, ok := d.store.RetainedGeneration(gen)
	if !ok {
		return nil
	}
	d.ipsecGeneration.Store(&ipsecGenerationCache{gen: gen, cfg: cfg})
	return cfg
}

// noteIPsecGeneration logs whether attribution followed charon's marker, and if not,
// why. fallback is empty when it did. It logs only when the outcome changes from the
// previous pass: a takeover wave runs one pass per redundancy group and would otherwise
// repeat the same line.
func (d *Daemon) noteIPsecGeneration(fallback string, err error) {
	if prev := d.ipsecGenerationNote.Swap(&fallback); prev != nil && *prev == fallback {
		return
	}
	if fallback == "" {
		slog.Info("cluster: IPsec attribution follows the generation charon reports loaded")
		return
	}
	slog.Info("cluster: IPsec attribution falls back to the promoted config",
		"reason", fallback, "err", err)
}

// isCurrentIPsecAttribution reports whether cfg is the config the latest attribution
// pass resolved, or the config a pass would use without asking charon (the record, else
// the promoted config). It never asks charon, so the SA index cache can call it.
func (d *Daemon) isCurrentIPsecAttribution(cfg *config.Config) bool {
	if cfg == d.ipsecAttribution.Load() {
		return true
	}
	if rec := d.ipsecLoadedCfg.Load(); rec != nil {
		return rec == cfg
	}
	return d.store != nil && d.store.ActiveConfig() == cfg
}
