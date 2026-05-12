mod secure_guard;
mod audit;
mod metrics;

use std::time::Duration;

use anyhow::Context;
use log::{error, info, warn};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::ClientOptions;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Performance::*;

#[derive(Deserialize)]
struct Config {
    interval_seconds: u64,
    pipe_name: String,
    metrics: Vec<MetricDef>,
}

#[derive(Deserialize)]
struct MetricDef {
    tag: String,
    path: String,
}

async fn run_service(cfg: Config) -> anyhow::Result<()> {
    // Use the binding type for PDH handles.
    let mut h_query: PDH_HQUERY = PDH_HQUERY::default();

    // PDH: Open Query
    let status = unsafe { PdhOpenQueryW(None, 0, &mut h_query) };
    if status != 0 {
        anyhow::bail!("PdhOpenQueryW failed with status: {}", status);
    }

    // RAII guard ensures PdhCloseQuery is called on drop (as per your secure_guard design).
    let _guard = secure_guard::PdhQueryGuard(h_query.0);

    // Add counters
    let mut counters: Vec<(String, PDH_HCOUNTER)> = Vec::new();
    for m in &cfg.metrics {
        let mut h_c: PDH_HCOUNTER = PDH_HCOUNTER::default();
        let path = HSTRING::from(&m.path);
        let status = unsafe { PdhAddCounterW(h_query, PCWSTR(path.as_ptr()), 0, &mut h_c) };
        if status == 0 {
            counters.push((m.tag.clone(), h_c));
        } else {
            warn!("Failed to add counter: {} (status: {})", m.path, status);
        }
    }

    if counters.is_empty() {
        anyhow::bail!("No PDH counters successfully added; check config paths.");
    }

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_seconds.max(1)));

    // CWE-778: rate-limited failure reporting counters
    let mut collect_failures: u32 = 0;
    let mut format_failures: u32 = 0;
    let mut pipe_failures: u32 = 0;

    loop {
        interval.tick().await;

        // Collect Data (CWE-703 + CWE-778)
        let st_collect = unsafe { PdhCollectQueryData(h_query) };
        if st_collect != 0 {
            collect_failures = collect_failures.saturating_add(1);
            if collect_failures <= 3 || collect_failures % 60 == 0 {
                warn!(
                    "PdhCollectQueryData failed (status: {}), failures={}",
                    st_collect, collect_failures
                );
            }
            continue;
        } else {
            collect_failures = 0;
        }

        // Build samples with PDH validation (CWE-703)
        let mut samples: Vec<metrics::Sample> = Vec::with_capacity(counters.len());
        for (tag, h) in &counters {
            let mut v = PDH_FMT_COUNTERVALUE::default();

            let st = unsafe { PdhGetFormattedCounterValue(*h, PDH_FMT_DOUBLE, None, &mut v) };
            if st != 0 {
                format_failures = format_failures.saturating_add(1);
                if format_failures <= 3 || format_failures % 200 == 0 {
                    warn!(
                        "PdhGetFormattedCounterValue failed (status: {}), failures={}",
                        st, format_failures
                    );
                }
                continue;
            }

            // PDH marks validity via CStatus
            if v.CStatus != 0 {
                // skip invalid/unavailable counter value
                continue;
            }

            let value = unsafe { v.Anonymous.doubleValue };
            samples.push(metrics::Sample {
                tag: tag.clone(),
                value,
            });
        }

        // If nothing valid, continue quietly (but you may want a low-rate warn).
        if samples.is_empty() {
            continue;
        }

        // Format payload (newline framing is handled by metrics::format_payload)
        let payload = metrics::format_payload(&samples);

        // Named Pipe Transmission
        match ClientOptions::new().open(&cfg.pipe_name) {
            Ok(mut pipe) => {
                if let Err(e) = pipe.write_all(payload.as_bytes()).await {
                    pipe_failures = pipe_failures.saturating_add(1);
                    if pipe_failures <= 3 || pipe_failures % 60 == 0 {
                        error!(
                            "Failed to write to named pipe ({}): {}, failures={}",
                            cfg.pipe_name, e, pipe_failures
                        );
                    }
                } else {
                    pipe_failures = 0;
                }
            }
            Err(e) => {
                pipe_failures = pipe_failures.saturating_add(1);
                if pipe_failures <= 3 || pipe_failures % 60 == 0 {
                    warn!(
                        "Named pipe open failure ({}): {}, failures={}",
                        cfg.pipe_name, e, pipe_failures
                    );
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize global logger for Event Viewer auditing
    if let Err(e) = audit::WinEventLogger::init("WinPerfClient") {
        eprintln!("Failed to initialize Windows Event Logger: {e}");
        return;
    }

    info!("WinPerfClient starting...");

    // Secure Configuration Loading
    let cfg_str = match std::fs::read_to_string("config.toml") {
        Ok(s) => s,
        Err(e) => {
            error!("Missing config: {e}");
            return;
        }
    };

    let cfg: Config = match toml::from_str(&cfg_str) {
        Ok(c) => c,
        Err(e) => {
            error!("Invalid config format: {e}");
            return;
        }
    };

    if let Err(e) = run_service(cfg).await {
        error!("Fatal service error: {e:#}");
    }
}
