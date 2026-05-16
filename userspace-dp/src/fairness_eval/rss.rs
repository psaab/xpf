use super::args::{parse_fraction_or_percent, parse_nonnegative_number_or_percent};
use super::per_worker::max_worker_flow_share;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RssExpectation {
    Any,
    Balanced,
    AtLeastActiveWorkers(u32),
    MaxWorkerFlowShare(f64),
    CstructMax(f64),
}

pub(crate) fn parse_rss_expectation(raw: &str) -> Result<RssExpectation, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("any") {
        return Ok(RssExpectation::Any);
    }
    if raw.eq_ignore_ascii_case("balanced") {
        return Ok(RssExpectation::Balanced);
    }

    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let normalized = compact
        .replace("<=", ":")
        .replace(">=", ":")
        .replace('=', ":");
    let mut parts = normalized.splitn(2, ':');
    let key = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default();
    match key {
        "at-least-active-workers" | "active-workers" => {
            let n = value
                .parse::<u32>()
                .map_err(|_| format!("invalid --rss-expectation active worker count: {raw}"))?;
            Ok(RssExpectation::AtLeastActiveWorkers(n))
        }
        "max-worker-flow-share" => {
            let share = parse_fraction_or_percent(value)
                .map_err(|e| format!("invalid --rss-expectation max-worker-flow-share: {e}"))?;
            Ok(RssExpectation::MaxWorkerFlowShare(share))
        }
        "cstruct-max" | "cstruct" => {
            let max = parse_nonnegative_number_or_percent(value)
                .map_err(|e| format!("invalid --rss-expectation cstruct threshold: {e}"))?;
            Ok(RssExpectation::CstructMax(max))
        }
        _ => Err(format!(
            "unknown --rss-expectation {raw}; expected any, balanced, \
             at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X"
        )),
    }
}

pub(crate) fn evaluate_rss_expectation(
    expectation: &RssExpectation,
    distribution_a_i: &[u32],
    cstruct: f64,
    n_total_workers: u32,
) -> (bool, String) {
    let total: u32 = distribution_a_i.iter().sum();
    let active_workers = distribution_a_i.iter().filter(|&&a| a > 0).count() as u32;
    let max_share = max_worker_flow_share(distribution_a_i);
    match expectation {
        RssExpectation::Any => (
            true,
            "any: no RSS/workload expectation configured".to_string(),
        ),
        RssExpectation::AtLeastActiveWorkers(min) => {
            if active_workers >= *min {
                (
                    true,
                    format!("active_workers={active_workers} >= expected {min}"),
                )
            } else {
                (
                    false,
                    format!("active_workers={active_workers} < expected {min}"),
                )
            }
        }
        RssExpectation::MaxWorkerFlowShare(max_allowed) => {
            if max_share <= *max_allowed {
                (
                    true,
                    format!("max_worker_flow_share={max_share:.4} <= expected {max_allowed:.4}"),
                )
            } else {
                (
                    false,
                    format!("max_worker_flow_share={max_share:.4} > expected {max_allowed:.4}"),
                )
            }
        }
        RssExpectation::CstructMax(max_allowed) => {
            if cstruct <= *max_allowed {
                (
                    true,
                    format!("cstruct={cstruct:.4} <= expected {max_allowed:.4}"),
                )
            } else {
                (
                    false,
                    format!("cstruct={cstruct:.4} > expected {max_allowed:.4}"),
                )
            }
        }
        RssExpectation::Balanced => {
            if total == 0 {
                return (false, "balanced: no active flows observed".to_string());
            }
            let expected_active = n_total_workers.min(total);
            let active_counts: Vec<u32> = distribution_a_i
                .iter()
                .copied()
                .filter(|&a| a > 0)
                .collect();
            let min = active_counts.iter().copied().min().unwrap_or(0);
            let max = active_counts.iter().copied().max().unwrap_or(0);
            let pass = active_workers == expected_active && max.saturating_sub(min) <= 1;
            if pass {
                (
                    true,
                    format!("balanced: active_workers={active_workers}, min={min}, max={max}"),
                )
            } else {
                (
                    false,
                    format!(
                        "balanced: active_workers={active_workers} expected {expected_active}, min={min}, max={max}"
                    ),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairness::compute_cstruct;

    #[test]
    fn rss_expectation_balanced_accepts_even_integer_distribution() {
        let expectation = parse_rss_expectation("balanced").unwrap();
        let (pass, reason) = evaluate_rss_expectation(&expectation, &[2, 2, 2, 2, 2, 2], 0.0, 6);
        assert!(pass, "expected balanced pass: {reason}");
    }

    #[test]
    fn rss_expectation_balanced_rejects_skewed_distribution() {
        let expectation = parse_rss_expectation("balanced").unwrap();
        let (pass, reason) = evaluate_rss_expectation(&expectation, &[9, 1, 1, 1, 0, 0], 0.0, 6);
        assert!(!pass, "expected balanced failure");
        assert!(reason.contains("active_workers=4"), "reason: {reason}");
    }

    #[test]
    fn rss_expectation_max_share_accepts_percent_syntax() {
        let expectation = parse_rss_expectation("max-worker-flow-share:50%").unwrap();
        assert_eq!(expectation, RssExpectation::MaxWorkerFlowShare(0.5));
        let (pass, _reason) = evaluate_rss_expectation(&expectation, &[2, 2, 1, 1], 0.0, 4);
        assert!(pass);
    }

    #[test]
    fn rss_expectation_cstruct_max_rejects_high_structural_ceiling() {
        let expectation = parse_rss_expectation("cstruct<=25%").unwrap();
        let cstruct = compute_cstruct(&[9, 1, 1, 1]);
        assert!(cstruct > 1.0, "fixture must exercise CoV > 1.0");
        let (pass, reason) = evaluate_rss_expectation(&expectation, &[9, 1, 1, 1], cstruct, 4);
        assert!(!pass);
        assert!(reason.contains("cstruct=1."), "reason: {reason}");
    }

    #[test]
    fn rss_expectation_cstruct_max_accepts_whitespace_around_operator() {
        let expectation = parse_rss_expectation("cstruct <= 25%").unwrap();
        assert_eq!(expectation, RssExpectation::CstructMax(0.25));
    }

    #[test]
    fn rss_expectation_cstruct_max_accepts_values_above_one() {
        let expectation = parse_rss_expectation("cstruct-max:150%").unwrap();
        assert_eq!(expectation, RssExpectation::CstructMax(1.5));

        let expectation = parse_rss_expectation("cstruct<=1.2").unwrap();
        assert_eq!(expectation, RssExpectation::CstructMax(1.2));
    }

    #[test]
    fn rss_expectation_cstruct_max_rejects_negative_values() {
        let err = parse_rss_expectation("cstruct-max:-0.1").unwrap_err();
        assert!(err.contains("non-negative"), "err: {err}");
    }

    #[test]
    fn rss_expectation_at_least_active_workers_rejects_too_few_workers() {
        let expectation = parse_rss_expectation("at-least-active-workers:5").unwrap();
        let (pass, reason) = evaluate_rss_expectation(&expectation, &[4, 4, 0, 0, 0, 0], 0.0, 6);
        assert!(!pass);
        assert!(reason.contains("active_workers=2"), "reason: {reason}");
    }
}
