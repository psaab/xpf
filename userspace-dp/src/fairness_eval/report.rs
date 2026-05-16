use serde::Serialize;

use super::args::Args;

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub(crate) cstruct_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cos_ifindex: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cos_queue_id: Option<u32>,
    pub(crate) distribution_a_i: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) binding_distribution_a_i: Option<Vec<u32>>,
    pub(crate) cstruct_distribution_a_i: Vec<u32>,
    pub(crate) cstruct_adjusted_for_a_i_overcount: bool,
    pub(crate) rss_expectation: String,
    pub(crate) rss_expectation_pass: bool,
    pub(crate) rss_expectation_reason: String,
    pub(crate) max_worker_flow_share: f64,
    pub(crate) n_active: u32,
    pub(crate) n_total_workers: u32,
    pub(crate) cstruct: f64,
    pub(crate) observed_cov: f64,
    pub(crate) gap: f64,
    pub(crate) epsilon: f64,
    pub(crate) saturated: bool,
    pub(crate) aggregate_mbps: f64,
    pub(crate) iperf_retransmits: u64,
    pub(crate) iperf_reverse: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_host_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_host_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_host_system_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_remote_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_remote_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_remote_system_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_sender_cpu_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_sender_cpu_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_sender_cpu_system_percent: Option<f64>,
    pub(crate) starved_flow_count: u32,
    /// Harness fail-fast guard result: sum(a_i) vs non-starved iperf streams.
    pub(crate) a_i_sum_check_ok: bool,
    pub(crate) a_i_sum: u32,
    pub(crate) iperf_non_starved_streams: u32,
    pub(crate) a_i_sum_under_tolerance: u32,
    pub(crate) a_i_sum_over_tolerance: u32,
    pub(crate) a_i_sum_tolerance: u32,
    /// PASS unless any gate fails.
    pub(crate) verdict: &'static str,
    pub(crate) failure_reasons: Vec<String>,
}

impl Report {
    pub(crate) fn passed(&self) -> bool {
        self.verdict == "PASS"
    }
}

pub(crate) fn emit(report: &Report, _args: &Args) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}
