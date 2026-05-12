mod secure_guard;
mod audit;
mod metrics;

use std::time::Duration;
use std::{io, io::ErrorKind};

use log::{error, info, warn};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::time::sleep;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::ERROR_PIPE_BUSY;
use windows::Win32::System::Performance::*;

// PDH handles in the current `windows` crate bindings are represented as `isize`
// (the `PDH_HQUERY` / `PDH_HCOUNTER` typedefs are not exported as named types). 【1-2ccd0d】
type PdhQueryHandle = isize;
type PdhCounterHandle = isize;

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

/// CWE-117: neutralize CR/LF to prevent log injection / record forging.
/// Keep it cheap: single pass, cap length to avoid log bloat.
fn sanitize_for_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }
    const MAX: usize = 512;
    if out.len() > MAX {
        out.truncate(MAX);
        out.push_str("…");
    }
    out
}

/// Open a named pipe with bounded retries.
/// Tokio docs call out two common connection-time errors:
/// - NotFound: server not up yet
/// - ERROR_PIPE_BUSY: server exists but busy; sleep and retry
async fn open_pipe_with_retry(pipe_name: &str) -> io::Result<NamedPipeClient> {
    const ATTEMPTS: usize = 10;
    const SLEEP_MS: u64 = 50;

    let mut last_err: Option<io::Error> = None;

    for _ in 0..ATTEMPTS {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    last_err = Some(e);
                    sleep(Duration::from_millis(SLEEP_MS)).await;
                    continue;
                }

                if e.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) {
                    last_err = Some(e);
                    sleep(Duration::from_millis(SLEEP_MS)).await;
                    continue;
                }

                return Err(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::new(ErrorKind::Other, "pipe open failed")))
}

async fn run_service(cfg: Config) -> anyhow::Result<()> {
    // PDH query handle (binding-compatible type). 【1-2ccd0d】
    let mut h_query: PdhQueryHandle = 0;

    // PDH: Open Query
    let status = unsafe { PdhOpenQueryW(None, 0, &mut h_query) };
    if status != 0 {
        anyhow::bail!("PdhOpenQueryW failed with status: {}", status);
    }

    // RAII guard ensures PdhCloseQuery is called on drop.
    // NOTE: secure_guard::PdhQueryGuard::new expects `isize` after the fix. 【1-2ccd0d】
    let _guard = secure_guard::PdhQueryGuard::new(h_query);

    // Add counters
    let mut counters: Vec<(String, PdhCounterHandle)> = Vec::new();
    for m in &cfg.metrics {
        let mut h_c: PdhCounterHandle = 0;
        let path = HSTRING::from(&m.path);

        let status = unsafe { PdhAddCounterW(h_query, PCWSTR(path.as_ptr()), 0, &mut h_c) };
        if status == 0 {
            counters.push((m.tag.clone(), h_c));
        } else {
            warn!(
                "Failed to add counter: {} (status: {})",
                sanitize_for_log(&m.path),
                status
            );
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

            if v.CStatus != 0 {
                continue;
            }

            let value = unsafe { v.Anonymous.doubleValue };
            samples.push(metrics::Sample {
                tag: tag.clone(),
                value,
            });
        }

        if samples.is_empty() {
            continue;
        }

        // Format payload (newline framing is handled by metrics::format_payload)
        let payload = metrics::format_payload(&samples);

        // Named Pipe Transmission (with bounded retry on NotFound / ERROR_PIPE_BUSY)
        match open_pipe_with_retry(&cfg.pipe_name).await {
            Ok(mut pipe) => {
                if let Err(e) = pipe.write_all(payload.as_bytes()).await {
                    pipe_failures = pipe_failures.saturating_add(1);
                    if pipe_failures <= 3 || pipe_failures % 60 == 0 {
                        error!(
                            "Failed to write to named pipe ({}): {}, failures={}",
                            sanitize_for_log(&cfg.pipe_name),
                            e,
                            pipe_failures
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
                        sanitize_for_log(&cfg.pipe_name),
                        e,
                        pipe_failures
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
        // Prefer stderr here because logger failed to initialize.
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
