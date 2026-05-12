mod secure_guard;
mod audit;
mod metrics;

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::ClientOptions;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Performance::*;
use serde::Deserialize;
// Use standard log macros
use log::{info, warn, error};

#[derive(Deserialize)]
struct Config {
    interval_seconds: u64,
    pipe_name: String,
    metrics: Vec<MetricDef>,
}

#[derive(Deserialize)]
struct MetricDef { tag: String, path: String }

async fn run_service(cfg: Config) -> anyhow::Result<()> {
    let mut h_query = 0;
    
    // PDH Fix: Direct status check (u32)
    let status = unsafe { PdhOpenQueryW(None, 0, &mut h_query) };
    if status != 0 {
        anyhow::bail!("PdhOpenQueryW failed with status: {status}");
    }
    let _guard = secure_guard::PdhQueryGuard(h_query);

    let mut counters = Vec::new();
    for m in &cfg.metrics {
        let mut h_c = 0;
        let path = HSTRING::from(&m.path);
        // PDH Fix: .is_ok() does not exist for u32
        let status = unsafe { PdhAddCounterW(h_query, PCWSTR(path.as_ptr()), 0, &mut h_c) };
        if status == 0 {
            counters.push((m.tag.clone(), h_c));
        } else {
            warn!("Failed to add counter: {} (Status: {})", m.path, status);
        }
    }

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_seconds));
    loop {
        interval.tick().await;
        
        // PDH Fix: .is_err() does not exist for u32
        if unsafe { PdhCollectQueryData(h_query) } != 0 { 
            continue; 
        }

        let samples: Vec<metrics::Sample> = counters.iter().map(|(tag, h)| {
            let mut v = PDH_FMT_COUNTERVALUE::default();
            unsafe { PdhGetFormattedCounterValue(*h, PDH_FMT_DOUBLE, None, &mut v); }
            metrics::Sample { tag: tag.clone(), value: v.Anonymous.doubleValue }
        }).collect();

        let payload = metrics::format_payload(&samples);
        
        if let Ok(mut pipe) = ClientOptions::new().open(&cfg.pipe_name) {
            if let Err(e) = pipe.write_all(payload.as_bytes()).await {
                error!("Failed to write to named pipe: {e}");
            }
        } else {
            // Updated to use log macro
            warn!("Named Pipe Connection Failure: {}", cfg.pipe_name);
        }
        // Samples are zeroized here upon drop
    }
}

#[tokio::main]
async fn main() {
    // NIST AU-12: Initialize the new global WinEventLogger
    if let Err(e) = audit::WinEventLogger::init("WinPerfRelay") {
        eprintln!("Failed to initialize Windows Event Logger: {e}");
        return;
    }

    info!("WinPerfRelay Service starting...");

    let cfg_str = match std::fs::read_to_string("config.toml") {
        Ok(s) => s,
        Err(e) => {
            error!("NIST CM-6: Missing Config: {e}");
            return;
        }
    };

    let cfg: Config = match toml::from_str(&cfg_str) {
        Ok(c) => c,
        Err(e) => {
            error!("NIST CM-6: Invalid Config format: {e}");
            return;
        }
    };

    if let Err(e) = run_service(cfg).await {
        error!("Fatal Service Error: {e}");
    }
}
