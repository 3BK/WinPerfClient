mod secure_guard;
mod audit;
mod metrics;

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::ClientOptions;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Performance::*;
use serde::Deserialize;
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
    
    // PDH: Open Query (u32 check)
    let status = unsafe { PdhOpenQueryW(None, 0, &mut h_query) };
    if status != 0 {
        anyhow::bail!("PdhOpenQueryW failed with status: {status}");
    }
    
    // RAII Guard ensures PdhCloseQuery is called on drop
    let _guard = secure_guard::PdhQueryGuard(h_query);

    let mut counters = Vec::new();
    for m in &cfg.metrics {
        let mut h_c = 0;
        let path = HSTRING::from(&m.path);
        
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
        
        // Collect Data
        if unsafe { PdhCollectQueryData(h_query) } != 0 { 
            continue; 
        }

        let samples: Vec<metrics::Sample> = counters.iter().map(|(tag, h)| {
            let mut v = PDH_FMT_COUNTERVALUE::default();
            
            // FIX: Accessing union field 'Anonymous' requires unsafe block
            let value = unsafe {
                PdhGetFormattedCounterValue(*h, PDH_FMT_DOUBLE, None, &mut v);
                v.Anonymous.doubleValue 
            };

            metrics::Sample { 
                tag: tag.clone(), 
                value 
            }
        }).collect();

        let payload = metrics::format_payload(&samples);
        
        // Named Pipe Transmission
        match ClientOptions::new().open(&cfg.pipe_name) {
            Ok(mut pipe) => {
                if let Err(e) = pipe.write_all(payload.as_bytes()).await {
                    error!("Failed to write to named pipe: {e}");
                }
            }
            Err(e) => {
                warn!("Named Pipe Connection Failure ({}): {e}", cfg.pipe_name);
            }
        }
        
        // Metrics samples are zeroized here upon drop if 'metrics::Sample' implements Zeroize
    }
}

#[tokio::main]
async fn main() {
    // NIST AU-12: Initialize global logger for Event Viewer
    if let Err(e) = audit::WinEventLogger::init("WinPerfRelay") {
        eprintln!("Failed to initialize Windows Event Logger: {e}");
        return;
    }

    info!("WinPerfRelay Service starting...");

    // NIST CM-6: Secure Configuration Loading
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
