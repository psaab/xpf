use std::path::PathBuf;

pub(crate) struct Args {
    pub(crate) iperf_json: PathBuf,
    pub(crate) binding_flows: PathBuf,
    pub(crate) cos_flows: Option<PathBuf>,
    pub(crate) cos_ifindex: Option<i32>,
    pub(crate) cos_queue_id: Option<u32>,
    /// Filter binding-flows rows to this interface name. Empty string =
    /// no filter (sum across all interfaces — only correct if your
    /// topology has just one). Defaults blank; harness script sets it.
    pub(crate) iface: String,
    pub(crate) warmup_secs: u64,
    pub(crate) final_burst_secs: u64,
    pub(crate) n_workers: u32,
    pub(crate) shaper_rate_bps: u64,
    pub(crate) rss_expectation: String,
}

pub(crate) fn parse_args() -> Args {
    let mut iperf_json: Option<PathBuf> = None;
    let mut binding_flows: Option<PathBuf> = None;
    let mut cos_flows: Option<PathBuf> = None;
    let mut cos_ifindex: Option<i32> = None;
    let mut cos_queue_id: Option<u32> = None;
    let mut iface: String = String::new();
    let mut warmup_secs: u64 = 5;
    let mut final_burst_secs: u64 = 1;
    let mut n_workers: u32 = 6;
    let mut shaper_rate_bps: u64 = 0;
    let mut rss_expectation: String = "any".to_string();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iperf-json" => {
                iperf_json = args.next().map(PathBuf::from);
            }
            "--binding-flows" => {
                binding_flows = args.next().map(PathBuf::from);
            }
            "--cos-flows" => {
                cos_flows = Some(PathBuf::from(parse_required_string_arg(
                    "--cos-flows",
                    args.next(),
                )));
            }
            "--cos-ifindex" => {
                cos_ifindex = Some(parse_required_numeric_arg("--cos-ifindex", args.next()));
            }
            "--cos-queue-id" => {
                cos_queue_id = Some(parse_required_numeric_arg("--cos-queue-id", args.next()));
            }
            "--iface" => {
                iface = args.next().unwrap_or_default();
            }
            "--warmup-secs" => {
                warmup_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
            }
            "--final-burst-secs" => {
                final_burst_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--n-workers" => {
                n_workers = args.next().and_then(|s| s.parse().ok()).unwrap_or(6);
            }
            "--shaper-rate-bps" => {
                shaper_rate_bps = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--rss-expectation" => {
                rss_expectation = parse_required_string_arg("--rss-expectation", args.next());
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: fairness-eval --iperf-json PATH --binding-flows PATH \\\n  [--cos-flows PATH --cos-ifindex N --cos-queue-id N] \\\n  [--iface NAME] [--warmup-secs N] [--final-burst-secs N] \\\n  [--n-workers N] [--shaper-rate-bps N] [--rss-expectation EXPR]\n\n--iface NAME: filter binding-flows rows to this interface (recommended for legacy per-binding mode).\n--cos-flows: class-specific CoS active-flow TSV; when present, Cstruct uses the selected CoS queue.\n--rss-expectation: any, balanced, at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X."
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("fairness-eval: unknown arg {arg}; try --help");
                std::process::exit(2);
            }
        }
    }
    let iperf_json = match iperf_json {
        Some(p) => p,
        None => {
            eprintln!("fairness-eval: --iperf-json is required");
            std::process::exit(2);
        }
    };
    let binding_flows = match binding_flows {
        Some(p) => p,
        None => {
            eprintln!("fairness-eval: --binding-flows is required");
            std::process::exit(2);
        }
    };
    Args {
        iperf_json,
        binding_flows,
        cos_flows,
        cos_ifindex,
        cos_queue_id,
        iface,
        warmup_secs,
        final_burst_secs,
        n_workers,
        shaper_rate_bps,
        rss_expectation,
    }
}

fn parse_required_numeric_arg<T>(flag: &str, raw: Option<String>) -> T
where
    T: std::str::FromStr,
{
    match parse_required_numeric_value(flag, raw) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("fairness-eval: {err}");
            std::process::exit(2);
        }
    }
}

fn parse_required_string_arg(flag: &str, raw: Option<String>) -> String {
    match parse_required_string_value(flag, raw) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("fairness-eval: {err}");
            std::process::exit(2);
        }
    }
}

fn parse_required_string_value(flag: &str, raw: Option<String>) -> Result<String, String> {
    let value = raw.ok_or_else(|| format!("{flag} requires a value"))?;
    if value.starts_with("--") {
        return Err(format!("{flag} requires a value, got {value:?}"));
    }
    Ok(value)
}

fn parse_required_numeric_value<T>(flag: &str, raw: Option<String>) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let value = raw.ok_or_else(|| format!("{flag} requires a value"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("{flag} must be numeric, got {value:?}"))
}

fn parse_number_or_percent(raw: &str) -> Result<f64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("missing value".to_string());
    }
    let value = if let Some(percent) = raw.strip_suffix('%') {
        percent
            .parse::<f64>()
            .map_err(|_| format!("{raw} is not a number"))?
            / 100.0
    } else {
        raw.parse::<f64>()
            .map_err(|_| format!("{raw} is not a number"))?
    };
    if !value.is_finite() {
        return Err(format!("{raw} is not a finite number"));
    }
    Ok(value)
}

pub(crate) fn parse_fraction_or_percent(raw: &str) -> Result<f64, String> {
    let value = parse_number_or_percent(raw)?;
    if !(0.0..=1.0).contains(&value) {
        return Err(format!("{raw} must be between 0 and 1 or 0% and 100%"));
    }
    Ok(value)
}

pub(crate) fn parse_nonnegative_number_or_percent(raw: &str) -> Result<f64, String> {
    let value = parse_number_or_percent(raw)?;
    if value < 0.0 {
        return Err(format!("{raw} must be non-negative"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cos_numeric_flags_reports_bad_values() {
        let parsed: i32 = parse_required_numeric_value("--cos-ifindex", Some("12".to_string()))
            .expect("valid ifindex");
        assert_eq!(parsed, 12);

        let err = parse_required_numeric_value::<u32>("--cos-queue-id", Some("bad".to_string()))
            .unwrap_err();
        assert!(
            err.contains("--cos-queue-id") && err.contains("bad"),
            "err: {err}"
        );

        let err = parse_required_numeric_value::<i32>("--cos-ifindex", None).unwrap_err();
        assert!(err.contains("requires a value"), "err: {err}");
    }

    #[test]
    fn parse_required_string_flags_report_missing_values() {
        let err = parse_required_string_value("--rss-expectation", None).unwrap_err();
        assert!(err.contains("requires a value"), "err: {err}");

        let err = parse_required_string_value("--cos-flows", Some("--cos-ifindex".to_string()))
            .unwrap_err();
        assert!(err.contains("--cos-flows"), "err: {err}");
    }
}
