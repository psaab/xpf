use super::*;
use std::sync::atomic::Ordering;

/// Publish one cumulative worker-local ScreenState snapshot on the first live
/// binding as a transport slot. Go sums binding samples into process-wide
/// counters rather than claiming per-binding attribution.
pub(super) fn publish_screen_state_status(screen_state: &ScreenState, bindings: &[BindingWorker]) {
    let Some(binding) = bindings
        .iter()
        .find(|binding| binding.live.bound.load(Ordering::Relaxed))
    else {
        return;
    };
    binding.live.screen_substituted_default_drops.store(
        screen_state.substituted_default_drops(),
        Ordering::Relaxed,
    );
    binding.live.screen_syn_flood_dst_drops.store(
        screen_state.syn_flood_dst_drops(),
        Ordering::Relaxed,
    );
    binding.live.screen_syn_flood_src_drops.store(
        screen_state.syn_flood_src_drops(),
        Ordering::Relaxed,
    );
    binding.live.screen_syn_flood_alarm_events.store(
        screen_state.syn_flood_alarm_events(),
        Ordering::Relaxed,
    );
    binding.live.screen_alarm_without_drop_events.store(
        screen_state.alarm_without_drop_events(),
        Ordering::Relaxed,
    );
    binding.live.screen_missing_profile_warns.store(
        screen_state.missing_profile_warn_count(),
        Ordering::Relaxed,
    );
    binding.live.screen_inert_profile_warns.store(
        screen_state.inert_profile_warn_count(),
        Ordering::Relaxed,
    );
    binding.live.screen_scan_sweep_skipped_pressure.store(
        screen_state.scan_sweep_skipped_pressure(),
        Ordering::Relaxed,
    );
    binding.live.screen_scan_sweep_evicted_pressure.store(
        screen_state.scan_sweep_evicted_pressure(),
        Ordering::Relaxed,
    );
}
