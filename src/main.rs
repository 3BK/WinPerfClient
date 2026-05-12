mod secure_guard;
mod audit;
mod metrics;

use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::ClientOptions;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Performance::*;
use windows::Win32::System::EventLog::EVENTLOG_ERROR_TYPE;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    interval_seconds: u64,
    pipe_name: String,
    metrics: Vec<MetricDef>,
}

#[derive(Deserialize)]
struct MetricDef { tag: String, path: String }

async fn run_service(cfg: Config, logger: Arc<audit::Auditor>) -> anyhow::Result<()> {
    let mut h_query = 0;
    unsafe { PdhOpenQueryW(None, 0, &mut h_query).ok()? };
    let _guard = secure_guard::PdhQueryGuard(h_query);

    let mut counters = Vec::new();
    for m in &cfg.metrics {
        let mut h_c = 0;
        let path = HSTRING::from(&m.path);
        if unsafe { PdhAddCounterW(h_query, PCWSTR(path.as_ptr()), 0, &mut h_c) }.is_ok() {
            counters.push((m.tag.clone(), h_c));
        }
    }

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_seconds));
    loop {
        interval.tick().await;
        if unsafe { PdhCollectQueryData(h_query) }.is_err() { continue; }

        let mut samples: Vec<metrics::Sample> = counters.iter().map(|(tag, h)| {
            let mut v = PDH_FMT_COUNTERVALUE::default();
            unsafe { PdhGetFormattedCounterValue(*h, PDH_FMT_DOUBLE, None, &mut v); }
            metrics::Sample { tag: tag.clone(), value: v.Anonymous.doubleValue }
        }).collect();

        let payload = metrics::format_payload(&samples);
        if let Ok(mut pipe) = ClientOptions::new().open(&cfg.pipe_name) {
            let _ = pipe.write_all(payload.as_bytes()).await;
        } else {
            logger.log(501, "Named Pipe Connection Failure", EVENTLOG_ERROR_TYPE);
        }
        // Samples are zeroized here upon drop
    }
}

#[tokio::main]
async fn main() {
    let logger = Arc::new(audit::Auditor::new("WinPerfRelay"));
    let cfg_str = std::fs::read_to_string("config.toml").expect("NIST CM-6: Missing Config");
    let cfg: Config = toml::from_str(&cfg_str).expect("NIST CM-6: Invalid Config");

    if let Err(e) = run_service(cfg, logger.clone()).await {
        logger.log(500, &format!("Fatal Service Error: {}", e), EVENTLOG_ERROR_TYPE);
    }
}
