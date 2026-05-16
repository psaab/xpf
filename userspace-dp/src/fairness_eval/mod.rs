pub(crate) mod args;
pub(crate) mod inputs;
pub(crate) mod per_worker;
pub(crate) mod report;
pub(crate) mod rss;
pub(crate) mod verdict;
pub(crate) mod windowing;

use crate::fairness::{compute_observed_cov, starved_flow_count};

use self::args::Args;
use self::inputs::Inputs;
use self::per_worker::{aggregate_cos_per_worker, aggregate_per_worker};
use self::report::Report;
use self::rss::parse_rss_expectation;
use self::verdict::{evaluate, VerdictInput, EPSILON};
use self::windowing::extract_window;

pub(crate) fn run_evaluation(args: &Args, inputs: Inputs) -> Result<Report, String> {
    let window = extract_window(&inputs.iperf, args.warmup_secs, args.final_burst_secs)?;
    let n_total_workers = args.n_workers;

    let observed_cov = compute_observed_cov(&window.per_flow_throughputs);

    let starved = starved_flow_count(
        &window
            .per_stream_buckets
            .values()
            .cloned()
            .collect::<Vec<_>>(),
    );

    // {a_i}: per-WORKER active flow count for the test's data-
    // direction interface. The TSV has 6 columns (timestamp,
    // binding_slot, queue_id, worker_id, iface, count); we filter to
    // --iface and aggregate by worker_id at each timestamp before
    // taking the median over the steady-state window.
    //
    // This addresses Codex round-3 + Gemini round-1 fatal: per-binding
    // counts spread across multiple interfaces (each TCP flow generates
    // entries on BOTH ingress AND egress bindings, plus one per queue)
    // produced a meaningless 18-element distribution. The contract's
    // {a_i} is per-worker on the bottleneck-direction interface; this
    // is what fairness-eval now computes.
    let agg = aggregate_per_worker(
        &inputs.binding_flows,
        &args.iface,
        n_total_workers,
        args.warmup_secs,
        args.final_burst_secs,
    )?;
    let binding_distribution_a_i = agg.distribution_a_i;
    let mut iface_filter_active = agg.iface_filter_active;
    let mut distribution_a_i = binding_distribution_a_i.clone();
    let mut cstruct_source = "binding";
    let mut selected_cos_ifindex = None;
    let mut selected_cos_queue_id = None;

    if let Some(cos_flows) = &inputs.cos_flows {
        let cos_ifindex = args
            .cos_ifindex
            .ok_or_else(|| "--cos-flows requires --cos-ifindex".to_string())?;
        let cos_queue_id = args
            .cos_queue_id
            .ok_or_else(|| "--cos-flows requires --cos-queue-id".to_string())?;
        distribution_a_i = aggregate_cos_per_worker(
            cos_flows,
            cos_ifindex,
            cos_queue_id,
            n_total_workers,
            args.warmup_secs,
            args.final_burst_secs,
        )?;
        iface_filter_active = true;
        cstruct_source = "cos_queue";
        selected_cos_ifindex = Some(cos_ifindex);
        selected_cos_queue_id = Some(cos_queue_id);
    }

    let rss_expectation = parse_rss_expectation(&args.rss_expectation)?;

    let aggregate_mbps = if window.aggregate_buckets_bps.is_empty() {
        0.0
    } else {
        (window.aggregate_buckets_bps.iter().sum::<u64>() as f64
            / window.aggregate_buckets_bps.len() as f64)
            / 1_000_000.0
    };
    let iperf_retransmits = inputs
        .iperf
        .end
        .as_ref()
        .map(|end| end.sum_sent.retransmits)
        .unwrap_or(0);
    let iperf_reverse = inputs.iperf.start.test_start.reverse != 0;
    let iperf_cpu = inputs
        .iperf
        .end
        .as_ref()
        .and_then(|end| end.cpu_utilization_percent.as_ref());
    let (
        iperf_cpu_host_total_percent,
        iperf_cpu_host_user_percent,
        iperf_cpu_host_system_percent,
        iperf_cpu_remote_total_percent,
        iperf_cpu_remote_user_percent,
        iperf_cpu_remote_system_percent,
        iperf_sender_cpu_total_percent,
        iperf_sender_cpu_user_percent,
        iperf_sender_cpu_system_percent,
    ) = if let Some(cpu) = iperf_cpu {
        let sender_total = if iperf_reverse {
            cpu.remote_total
        } else {
            cpu.host_total
        };
        let sender_user = if iperf_reverse {
            cpu.remote_user
        } else {
            cpu.host_user
        };
        let sender_system = if iperf_reverse {
            cpu.remote_system
        } else {
            cpu.host_system
        };
        (
            Some(cpu.host_total),
            Some(cpu.host_user),
            Some(cpu.host_system),
            Some(cpu.remote_total),
            Some(cpu.remote_user),
            Some(cpu.remote_system),
            Some(sender_total),
            Some(sender_user),
            Some(sender_system),
        )
    } else {
        (None, None, None, None, None, None, None, None, None)
    };

    // Stream count: prefer start.connected[].len() (concrete stream
    // sockets observed at iperf3 setup time) over test_start.num_streams
    // (a self-reported integer). The seeded map sees every connected
    // socket; any not present in steady-state intervals are starved
    // candidates. Codex round-2 finding: don't trust interval presence
    // alone — derive expected count from connected[].
    let n_iperf_streams = if inputs.iperf.start.connected.is_empty() {
        inputs.iperf.start.test_start.num_streams
    } else {
        inputs.iperf.start.connected.len() as u32
    };

    let decision = evaluate(VerdictInput {
        observed_cov,
        aggregate_buckets_bps: &window.aggregate_buckets_bps,
        shaper_rate_bps: args.shaper_rate_bps,
        distribution_a_i: &distribution_a_i,
        binding_distribution_a_i: &binding_distribution_a_i,
        cstruct_source,
        starved,
        n_iperf_streams,
        n_total_workers,
        iface_filter_active,
        rss_expectation: &rss_expectation,
    });

    Ok(Report {
        cstruct_source,
        cos_ifindex: selected_cos_ifindex,
        cos_queue_id: selected_cos_queue_id,
        distribution_a_i,
        binding_distribution_a_i: (cstruct_source == "cos_queue")
            .then_some(binding_distribution_a_i),
        cstruct_distribution_a_i: decision.cstruct_distribution_a_i,
        cstruct_adjusted_for_a_i_overcount: decision.cstruct_adjusted_for_a_i_overcount,
        rss_expectation: args.rss_expectation.clone(),
        rss_expectation_pass: decision.rss_expectation_pass,
        rss_expectation_reason: decision.rss_expectation_reason,
        max_worker_flow_share: decision.max_worker_flow_share,
        n_active: decision.n_active,
        n_total_workers,
        cstruct: decision.cstruct,
        observed_cov,
        gap: decision.gap,
        epsilon: EPSILON,
        saturated: decision.saturated,
        aggregate_mbps,
        iperf_retransmits,
        iperf_reverse,
        iperf_cpu_host_total_percent,
        iperf_cpu_host_user_percent,
        iperf_cpu_host_system_percent,
        iperf_cpu_remote_total_percent,
        iperf_cpu_remote_user_percent,
        iperf_cpu_remote_system_percent,
        iperf_sender_cpu_total_percent,
        iperf_sender_cpu_user_percent,
        iperf_sender_cpu_system_percent,
        starved_flow_count: starved,
        a_i_sum_check_ok: decision.a_i_sum_check_ok,
        a_i_sum: decision.a_i_sum,
        iperf_non_starved_streams: decision.iperf_non_starved_streams,
        a_i_sum_under_tolerance: decision.a_i_sum_under_tolerance,
        a_i_sum_over_tolerance: decision.a_i_sum_over_tolerance,
        a_i_sum_tolerance: decision.a_i_sum_tolerance,
        verdict: decision.verdict,
        failure_reasons: decision.failure_reasons,
    })
}
