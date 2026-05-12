mod secure_guard;
mod audit;
mod metrics;

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::ClientOptions;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Performance::*;
use log::{info, warn, error};

async fn run_service(cfg: Config) -> anyhow::Result<()> {
    let mut h_query = 0;
    // Status Check: Pdh returns u32, not HRESULT
    if unsafe { PdhOpenQueryW(None, 0, &mut h_query) } != 0 {
        anyhow::bail!("Failed to open PDH Query");
    }
    let _guard = secure_guard::PdhQueryGuard(h_query);

    let mut counters = Vec::new();
    for m in &cfg.metrics {
        let mut h_c = 0;
        let path = HSTRING::from(&m.path);
        if unsafe { PdhAddCounterW(h_query, PCWSTR(path.as_ptr()), 0, &mut h_c) } == 0 {
            counters.push((m.tag.clone(), h_c));
        } else {
            warn!("Counter skipped (not found): {}", m.path);
        }
    }

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_seconds));
    loop {
        interval.tick().await;
        if unsafe { PdhCollectQueryData(h_query) } != 0 { continue; }

        let samples: Vec<metrics::Sample> = counters.iter().map(|(tag, h)| {
            let mut v = PDH_FMT_COUNTERVALUE::default();
            // FIX: Safe access to Union after initialization
            let val = unsafe {
                PdhGetFormattedCounterValue(*h, PDH_FMT_DOUBLE, None, &mut v);
                v.Anonymous.doubleValue 
            };
            metrics::Sample { tag: tag.clone(), value: val }
        }).collect();

        let payload = metrics::format_payload(&samples);
        
        match ClientOptions::new().open(&cfg.pipe_name) {
            Ok(mut pipe) => {
                let _ = pipe.write_all(payload.as_bytes()).await;
            }
            Err(_) => error!("Transmission Failure: Pipe {} unreachable", cfg.pipe_name),
        }
    }
}

#[tokio::main]
async fn main() {
    audit::WinEventLogger::init("WinPerfRelay").ok();
    info!("Service Guard Initialized");
    
    // ... config loading logic ...
}
