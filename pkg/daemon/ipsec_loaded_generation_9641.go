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
// The marker may OVERRIDE the promoted config only when all of these hold. Every other
// outcome keeps the promoted config, which is exactly what attribution did before:
//
//   - IDENTITY, NOT PROOF. `swanctl --load-all` is not a transaction, so a partial load
//     can leave the marker and the connections at different generations. The named
//     generation is used only when charon's loaded connections are exactly what it
//     renders (ipsec.ExpectedLoadedConns).
//   - PROVABLY NOT THE PROMOTED CONFIG. When charon's loaded connections are exactly
//     what the promoted config renders, or that cannot be computed, the promoted config
//     stands. Connections that render identically carry no generation of their own: a
//     redundancy-group move that keeps an explicit local address changes only xpf's
//     interface config, which the apply's earlier steps took from the promoted config.
//   - NO APPLY OVERLAPPED THE PASS. An IPsec apply running when the pass starts, or
//     starting or finishing before it ends, can change what charon runs under it. The
//     caller then re-reads the record and the promoted config.
//
// A generation is resolved from the ones this process wrote first (a commit-confirmed
// rollback drops the rolled-back tree from the store), then from the store's retained
// trees.

import (
	"errors"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// ipsecWrittenMax bounds ipsecWritten. One rollback's worth of history is the case it
// exists for; a few more cost a pointer each.
const ipsecWrittenMax = 4

// ipsecGenerationCache pairs a generation marker token with its compiled config.
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

// rememberWrittenIPsecGeneration records that the swanctl file on disk now names gen for
// cfg, newest first. The list is replaced, never mutated, so readers need no lock.
func (d *Daemon) rememberWrittenIPsecGeneration(gen string, cfg *config.Config) {
	if gen == ipsec.UnknownGeneration || cfg == nil {
		return
	}
	next := []ipsecGenerationCache{{gen: gen, cfg: cfg}}
	if prev := d.ipsecWritten.Load(); prev != nil {
		for _, c := range *prev {
			if c.gen != gen && len(next) < ipsecWrittenMax {
				next = append(next, c)
			}
		}
	}
	d.ipsecWritten.Store(&next)
}

// ipsecStableMarkedGeneration is ipsecMarkedGeneration, trusted only when no IPsec apply
// was running as the pass started and none started or finished before it ended. nil
// means the caller keeps its fallback.
func (d *Daemon) ipsecStableMarkedGeneration() *config.Config {
	if d.ipsec == nil || d.store == nil {
		return nil
	}
	seq := d.ipsecApplySeq.Load()
	if d.ipsecApplyActive.Load() != 0 {
		d.noteIPsecGeneration("an IPsec apply is in progress", nil)
		return nil
	}
	cfg, reason, err := d.ipsecMarkedGeneration()
	if cfg != nil && (d.ipsecApplySeq.Load() != seq || d.ipsecApplyActive.Load() != 0) {
		cfg, reason, err = nil, "an IPsec apply overlapped the pass", nil
	}
	d.noteIPsecGeneration(reason, err)
	return cfg
}

// ipsecMarkedGeneration returns the config of the generation charon's marker names, or
// nil with the reason attribution keeps its fallback. It asks charon twice (list-pools,
// list-conns), so it runs only when there is no record.
func (d *Daemon) ipsecMarkedGeneration() (*config.Config, string, error) {
	gen, err := d.ipsec.LoadedGeneration()
	if err != nil {
		return nil, "charon names no single generation", err
	}
	if gen == ipsec.UnknownGeneration {
		return nil, "charon's marker names an unknown generation", nil
	}
	have, err := d.ipsec.ListLoadedConns()
	if err != nil {
		return nil, "charon's loaded connections are unavailable", err
	}
	promoted := d.store.ActiveConfig()
	if promoted == nil {
		return nil, "there is no promoted config to compare with", nil
	}
	switch pw, perr := ipsec.ExpectedLoadedConns(promoted); {
	case perr == nil && have.Equal(pw):
		return nil, "charon runs the promoted config's connections", nil
	case errors.Is(perr, ipsec.ErrGenerationUnvalidatable):
		return nil, "the promoted config's connections cannot be compared", perr
	}
	cfg := d.retainedIPsecGeneration(gen)
	if cfg == nil {
		return nil, "charon's generation is not retained on this node", nil
	}
	want, err := ipsec.ExpectedLoadedConns(cfg)
	if err != nil {
		return nil, "charon's generation cannot be validated", err
	}
	if !have.Equal(want) {
		return nil, "charon's loaded connections do not match its marked generation", nil
	}
	return cfg, "", nil
}

// retainedIPsecGeneration resolves a marker token to a compiled config: from the
// generations this process wrote, then through the store. The last hit is cached so a
// takeover wave (one pass per redundancy group) recompiles an older generation once. A
// miss is not cached: it is re-asked next pass.
func (d *Daemon) retainedIPsecGeneration(gen string) *config.Config {
	if c := d.ipsecGeneration.Load(); c != nil && c.gen == gen {
		return c.cfg
	}
	cfg := d.writtenIPsecGeneration(gen)
	if cfg == nil {
		var ok bool
		if cfg, ok = d.store.RetainedGeneration(gen); !ok {
			return nil
		}
	}
	d.ipsecGeneration.Store(&ipsecGenerationCache{gen: gen, cfg: cfg})
	return cfg
}

// writtenIPsecGeneration returns the config this process wrote under gen, if it is
// still among the most recent ipsecWrittenMax.
func (d *Daemon) writtenIPsecGeneration(gen string) *config.Config {
	if list := d.ipsecWritten.Load(); list != nil {
		for _, c := range *list {
			if c.gen == gen {
				return c.cfg
			}
		}
	}
	return nil
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
	slog.Info("cluster: IPsec attribution keeps the promoted config",
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
