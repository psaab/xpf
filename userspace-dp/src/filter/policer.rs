// Token-bucket and three-color policer state for the userspace filter path.

const TOKEN_SCALE: u128 = 1_000_000_000;

#[inline]
fn scaled_bytes(bytes: u64) -> u128 {
    u128::from(bytes) * TOKEN_SCALE
}

#[inline]
fn refill_scaled(rate_bytes_per_sec: u64, elapsed_ns: u64) -> u128 {
    u128::from(rate_bytes_per_sec) * u128::from(elapsed_ns)
}

#[inline]
fn refill_scaled_bits(rate_bits_per_sec: u64, elapsed_ns: u64) -> u128 {
    u128::from(rate_bits_per_sec) * u128::from(elapsed_ns) / 8
}

#[inline]
fn capped_add(tokens: u128, add: u128, cap: u128) -> u128 {
    tokens.saturating_add(add).min(cap)
}

/// Token-bucket policer state.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct PolicerState {
    pub(crate) name: String,
    /// Refill rate in bits per second.
    pub(crate) rate_bits_per_sec: u64,
    /// Maximum bucket size in bytes.
    pub(crate) burst_bytes: u64,
    /// Current token count in bytes scaled by `TOKEN_SCALE`.
    pub(crate) tokens: u128,
    /// Last refill timestamp (monotonic nanoseconds).
    pub(crate) last_refill_ns: u64,
    /// Whether to discard excess traffic (vs. mark).
    pub(crate) discard_excess: bool,
    /// Whether the policer has been initialized with the first packet time.
    initialized: bool,
}

impl PolicerState {
    pub(crate) fn new(
        name: String,
        bandwidth_bps: u64,
        burst_bytes: u64,
        discard_excess: bool,
    ) -> Self {
        Self {
            name,
            rate_bits_per_sec: bandwidth_bps,
            burst_bytes,
            tokens: scaled_bytes(burst_bytes),
            last_refill_ns: 0,
            discard_excess,
            initialized: false,
        }
    }

    /// Refill tokens based on elapsed time and try to consume `packet_bytes`.
    /// Returns true if the packet is within the rate limit (conforming).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn consume(&mut self, now_ns: u64, packet_bytes: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.last_refill_ns = now_ns;
            self.tokens = scaled_bytes(self.burst_bytes);
        }
        // Refill tokens
        if now_ns > self.last_refill_ns {
            let elapsed_ns = now_ns - self.last_refill_ns;
            let refill = refill_scaled_bits(self.rate_bits_per_sec, elapsed_ns);
            self.tokens = capped_add(self.tokens, refill, scaled_bytes(self.burst_bytes));
            self.last_refill_ns = now_ns;
        }
        // Try to consume
        let cost = scaled_bytes(packet_bytes);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketColor {
    Green,
    Yellow,
    Red,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThreeColorMode {
    SingleRate,
    TwoRate,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ColorTreatment {
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

impl ColorTreatment {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn rewrite(dscp: u8) -> Self {
        Self {
            dscp_rewrite: Some(dscp & 0x3f),
            drop: false,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn drop() -> Self {
        Self {
            dscp_rewrite: None,
            drop: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreeColorTreatments {
    pub(crate) green: ColorTreatment,
    pub(crate) yellow: ColorTreatment,
    pub(crate) red: ColorTreatment,
}

impl ThreeColorTreatments {
    fn treatment_for(self, color: PacketColor) -> ColorTreatment {
        match color {
            PacketColor::Green => self.green,
            PacketColor::Yellow => self.yellow,
            PacketColor::Red => self.red,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ThreeColorDecision {
    pub(crate) color: PacketColor,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicerConfigError {
    ZeroRate,
    ZeroBurst,
    PeakRateBelowCommittedRate,
    PeakBurstBelowCommittedBurst,
}

/// Compact RFC 2697/2698 policer state. All hot fields are numeric so the
/// state can move to ID-indexed shards without retaining name-keyed lookup.
#[derive(Clone, Debug)]
pub(crate) struct ThreeColorPolicerState {
    mode: ThreeColorMode,
    color_blind: bool,
    committed_rate_bytes_per_sec: u64,
    committed_burst_bytes: u64,
    peak_or_excess_rate_bytes_per_sec: u64,
    peak_or_excess_burst_bytes: u64,
    committed_tokens: u128,
    peak_or_excess_tokens: u128,
    last_refill_ns: u64,
    initialized: bool,
    treatments: ThreeColorTreatments,
}

impl ThreeColorPolicerState {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn sr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        excess_burst_bytes: u64,
        color_blind: bool,
    ) -> Result<Self, PolicerConfigError> {
        Self::sr_tcm_with_treatments(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            excess_burst_bytes,
            color_blind,
            ThreeColorTreatments::default(),
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn sr_tcm_with_treatments(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        excess_burst_bytes: u64,
        color_blind: bool,
        treatments: ThreeColorTreatments,
    ) -> Result<Self, PolicerConfigError> {
        if committed_rate_bytes_per_sec == 0 {
            return Err(PolicerConfigError::ZeroRate);
        }
        if committed_burst_bytes == 0 || excess_burst_bytes == 0 {
            return Err(PolicerConfigError::ZeroBurst);
        }
        Ok(Self {
            mode: ThreeColorMode::SingleRate,
            color_blind,
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            peak_or_excess_rate_bytes_per_sec: 0,
            peak_or_excess_burst_bytes: excess_burst_bytes,
            committed_tokens: scaled_bytes(committed_burst_bytes),
            peak_or_excess_tokens: scaled_bytes(excess_burst_bytes),
            last_refill_ns: 0,
            initialized: false,
            treatments,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn tr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        peak_rate_bytes_per_sec: u64,
        peak_burst_bytes: u64,
        color_blind: bool,
    ) -> Result<Self, PolicerConfigError> {
        Self::tr_tcm_with_treatments(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            peak_rate_bytes_per_sec,
            peak_burst_bytes,
            color_blind,
            ThreeColorTreatments::default(),
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn tr_tcm_with_treatments(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        peak_rate_bytes_per_sec: u64,
        peak_burst_bytes: u64,
        color_blind: bool,
        treatments: ThreeColorTreatments,
    ) -> Result<Self, PolicerConfigError> {
        if committed_rate_bytes_per_sec == 0 || peak_rate_bytes_per_sec == 0 {
            return Err(PolicerConfigError::ZeroRate);
        }
        if committed_burst_bytes == 0 || peak_burst_bytes == 0 {
            return Err(PolicerConfigError::ZeroBurst);
        }
        if peak_rate_bytes_per_sec < committed_rate_bytes_per_sec {
            return Err(PolicerConfigError::PeakRateBelowCommittedRate);
        }
        if peak_burst_bytes < committed_burst_bytes {
            return Err(PolicerConfigError::PeakBurstBelowCommittedBurst);
        }
        Ok(Self {
            mode: ThreeColorMode::TwoRate,
            color_blind,
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            peak_or_excess_rate_bytes_per_sec: peak_rate_bytes_per_sec,
            peak_or_excess_burst_bytes: peak_burst_bytes,
            committed_tokens: scaled_bytes(committed_burst_bytes),
            peak_or_excess_tokens: scaled_bytes(peak_burst_bytes),
            last_refill_ns: 0,
            initialized: false,
            treatments,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn meter(
        &mut self,
        now_ns: u64,
        packet_bytes: u64,
        incoming_color: PacketColor,
    ) -> ThreeColorDecision {
        self.refill(now_ns);
        let effective_incoming_color = if self.color_blind {
            PacketColor::Green
        } else {
            incoming_color
        };
        let color = match self.mode {
            ThreeColorMode::SingleRate => self.meter_sr_tcm(packet_bytes, effective_incoming_color),
            ThreeColorMode::TwoRate => self.meter_tr_tcm(packet_bytes, effective_incoming_color),
        };
        let treatment = self.treatments.treatment_for(color);
        ThreeColorDecision {
            color,
            dscp_rewrite: treatment.dscp_rewrite,
            drop: treatment.drop,
        }
    }

    fn refill(&mut self, now_ns: u64) {
        if !self.initialized {
            self.initialized = true;
            self.last_refill_ns = now_ns;
            self.committed_tokens = scaled_bytes(self.committed_burst_bytes);
            self.peak_or_excess_tokens = scaled_bytes(self.peak_or_excess_burst_bytes);
            return;
        }
        if now_ns <= self.last_refill_ns {
            return;
        }

        let elapsed_ns = now_ns - self.last_refill_ns;
        match self.mode {
            ThreeColorMode::SingleRate => self.refill_sr_tcm(elapsed_ns),
            ThreeColorMode::TwoRate => self.refill_tr_tcm(elapsed_ns),
        }
        self.last_refill_ns = now_ns;
    }

    fn refill_sr_tcm(&mut self, elapsed_ns: u64) {
        let refill = refill_scaled(self.committed_rate_bytes_per_sec, elapsed_ns);
        let committed_cap = scaled_bytes(self.committed_burst_bytes);
        let excess_cap = scaled_bytes(self.peak_or_excess_burst_bytes);
        let committed_space = committed_cap.saturating_sub(self.committed_tokens);
        let committed_add = refill.min(committed_space);
        self.committed_tokens += committed_add;
        let excess_add = refill - committed_add;
        self.peak_or_excess_tokens = capped_add(self.peak_or_excess_tokens, excess_add, excess_cap);
    }

    fn refill_tr_tcm(&mut self, elapsed_ns: u64) {
        self.committed_tokens = capped_add(
            self.committed_tokens,
            refill_scaled(self.committed_rate_bytes_per_sec, elapsed_ns),
            scaled_bytes(self.committed_burst_bytes),
        );
        self.peak_or_excess_tokens = capped_add(
            self.peak_or_excess_tokens,
            refill_scaled(self.peak_or_excess_rate_bytes_per_sec, elapsed_ns),
            scaled_bytes(self.peak_or_excess_burst_bytes),
        );
    }

    fn meter_sr_tcm(&mut self, packet_bytes: u64, incoming_color: PacketColor) -> PacketColor {
        let cost = scaled_bytes(packet_bytes);
        if incoming_color == PacketColor::Green && self.committed_tokens >= cost {
            self.committed_tokens -= cost;
            return PacketColor::Green;
        }
        if incoming_color != PacketColor::Red && self.peak_or_excess_tokens >= cost {
            self.peak_or_excess_tokens -= cost;
            return PacketColor::Yellow;
        }
        PacketColor::Red
    }

    fn meter_tr_tcm(&mut self, packet_bytes: u64, incoming_color: PacketColor) -> PacketColor {
        let cost = scaled_bytes(packet_bytes);
        if incoming_color == PacketColor::Green
            && self.peak_or_excess_tokens >= cost
            && self.committed_tokens >= cost
        {
            self.peak_or_excess_tokens -= cost;
            self.committed_tokens -= cost;
            return PacketColor::Green;
        }
        if incoming_color != PacketColor::Red && self.peak_or_excess_tokens >= cost {
            self.peak_or_excess_tokens -= cost;
            return PacketColor::Yellow;
        }
        PacketColor::Red
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    fn sr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        excess_burst_bytes: u64,
        color_blind: bool,
    ) -> ThreeColorPolicerState {
        ThreeColorPolicerState::sr_tcm(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            excess_burst_bytes,
            color_blind,
        )
        .expect("valid srTCM config")
    }

    fn tr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        peak_rate_bytes_per_sec: u64,
        peak_burst_bytes: u64,
        color_blind: bool,
    ) -> ThreeColorPolicerState {
        ThreeColorPolicerState::tr_tcm(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            peak_rate_bytes_per_sec,
            peak_burst_bytes,
            color_blind,
        )
        .expect("valid trTCM config")
    }

    #[test]
    fn srTCM_green_yellow_red_at_thresholds() {
        let mut policer = sr_tcm(100, 100, 50, true);

        let green = policer.meter(0, 100, PacketColor::Green);
        let yellow = policer.meter(0, 50, PacketColor::Green);
        let red = policer.meter(0, 1, PacketColor::Green);

        assert_eq!(green.color, PacketColor::Green);
        assert_eq!(yellow.color, PacketColor::Yellow);
        assert_eq!(red.color, PacketColor::Red);
    }

    #[test]
    fn srTCM_c_overflow_refills_e_bucket() {
        let mut policer = sr_tcm(100, 100, 200, true);

        let first = policer.meter(0, 150, PacketColor::Green);
        assert_eq!(first.color, PacketColor::Yellow);

        let green = policer.meter(1_000_000_000, 100, PacketColor::Green);
        assert_eq!(green.color, PacketColor::Green);

        let yellow = policer.meter(1_000_000_000, 150, PacketColor::Green);
        assert_eq!(yellow.color, PacketColor::Yellow);
    }

    #[test]
    fn trTCM_independent_CIR_PIR() {
        let mut policer = tr_tcm(100, 100, 200, 200, true);

        let initial = policer.meter(0, 100, PacketColor::Green);
        assert_eq!(initial.color, PacketColor::Green);

        let yellow = policer.meter(500_000_000, 100, PacketColor::Green);
        assert_eq!(yellow.color, PacketColor::Yellow);

        let green = policer.meter(1_000_000_000, 100, PacketColor::Green);
        assert_eq!(green.color, PacketColor::Green);
    }

    #[test]
    fn color_aware_never_promotes_incoming_yellow_or_red() {
        let mut sr_policer = sr_tcm(100, 100, 100, false);

        let yellow = sr_policer.meter(0, 50, PacketColor::Yellow);
        let red = sr_policer.meter(0, 50, PacketColor::Red);

        assert_eq!(yellow.color, PacketColor::Yellow);
        assert_eq!(red.color, PacketColor::Red);

        let mut tr_policer = tr_tcm(100, 100, 100, 100, false);

        let yellow = tr_policer.meter(0, 50, PacketColor::Yellow);
        let red = tr_policer.meter(0, 50, PacketColor::Red);

        assert_eq!(yellow.color, PacketColor::Yellow);
        assert_eq!(red.color, PacketColor::Red);
    }

    #[test]
    fn color_blind_ignores_incoming_color() {
        let mut policer = sr_tcm(100, 100, 100, true);

        let green = policer.meter(0, 50, PacketColor::Red);

        assert_eq!(green.color, PacketColor::Green);
    }

    #[test]
    fn u128_bucket_math_boundary_inputs() {
        let mut policer = sr_tcm(u64::MAX, u64::MAX, u64::MAX, true);

        let first = policer.meter(0, u64::MAX, PacketColor::Green);
        let refilled = policer.meter(u64::MAX, u64::MAX, PacketColor::Green);

        assert_eq!(first.color, PacketColor::Green);
        assert_eq!(refilled.color, PacketColor::Green);
    }

    #[test]
    fn three_color_dscp_rewrite() {
        let treatments = ThreeColorTreatments {
            green: ColorTreatment::rewrite(10),
            yellow: ColorTreatment::rewrite(20),
            red: {
                let mut treatment = ColorTreatment::drop();
                treatment.dscp_rewrite = Some(30);
                treatment
            },
        };
        let mut policer =
            ThreeColorPolicerState::sr_tcm_with_treatments(100, 100, 50, true, treatments)
                .expect("valid srTCM config");

        let green = policer.meter(0, 100, PacketColor::Green);
        let yellow = policer.meter(0, 50, PacketColor::Green);
        let red = policer.meter(0, 1, PacketColor::Green);

        assert_eq!(green.dscp_rewrite, Some(10));
        assert!(!green.drop);
        assert_eq!(yellow.dscp_rewrite, Some(20));
        assert!(!yellow.drop);
        assert_eq!(red.dscp_rewrite, Some(30));
        assert!(red.drop);
    }
}
