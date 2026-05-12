use log::{Level, LevelFilter, Log, Metadata, Record};
use std::sync::Mutex;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

fn sanitize_for_eventlog(s: &str) -> String {
    // CWE-117: neutralize CR/LF so attackers can't forge multiple log records.
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }

    // Cap size to prevent oversized events (cheap protection).
    const MAX: usize = 2048;
    if out.len() > MAX {
        out.truncate(MAX);
        out.push_str("…");
    }

    out
}

fn parse_level_filter(s: &str) -> LevelFilter {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" | "warning" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

fn default_level_filter() -> LevelFilter {
    // Allow env override without extra crates.
    // Examples:
    //   WINPERF_LOG_LEVEL=debug
    //   WINPERF_LOG_LEVEL=trace
    // Default: info
    std::env::var("WINPERF_LOG_LEVEL")
        .ok()
        .as_deref()
        .map(parse_level_filter)
        .unwrap_or(LevelFilter::Info)
}

/// Windows Event Log logger implementing the `log` crate backend.
pub struct WinEventLogger {
    handle: HANDLE,
    level: LevelFilter,
    lock: Mutex<()>,
}

impl WinEventLogger {
    /// Initialize the EventLog logger and configure the maximum log level.
    ///
    /// Full range supported, including Debug/Trace, controlled by:
    ///   WINPERF_LOG_LEVEL=trace|debug|info|warn|error|off
    pub fn init(source_name: &str) -> Result<(), log::SetLoggerError> {
        let level = default_level_filter();

        // Register once (avoid per-record churn).
        let source = HSTRING::from(source_name);
        let handle = unsafe {
            RegisterEventSourceW(None, PCWSTR(source.as_ptr()))
                .unwrap_or_else(|_| HANDLE::default())
        };

        let logger = Box::leak(Box::new(Self {
            handle,
            level,
            lock: Mutex::new(()),
        }));

        log::set_logger(logger)?;
        // IMPORTANT: set the global max level to what we want to allow.
        log::set_max_level(level);
        Ok(())
    }

    fn map_level(level: Level) -> REPORT_EVENT_TYPE {
        match level {
            Level::Error => EVENTLOG_ERROR_TYPE,
            Level::Warn => EVENTLOG_WARNING_TYPE,
            _ => EVENTLOG_INFORMATION_TYPE,
        }
    }
}

impl Log for WinEventLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Respect configured filter (supports Debug/Trace when enabled).
        metadata.level() <= self.level.to_level().unwrap_or(Level::Error)
            && self.level != LevelFilter::Off
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // If registration failed, no-op (could optionally fallback to stderr).
        if self.handle == HANDLE::default() {
            return;
        }

        // Compose message and neutralize.
        let module = record.module_path().unwrap_or("main");
        let msg = format!("[{}][{}] {}", module, record.level(), record.args());
        let msg = sanitize_for_eventlog(&msg);

        let msg_w = HSTRING::from(msg);
        let strings = [PCWSTR(msg_w.as_ptr())];

        // Serialize access (conservative).
        let _g = self.lock.lock().ok();

        unsafe {
            let _ = ReportEventW(
                self.handle,
                Self::map_level(record.level()),
                0,      // category
                1000,   // event id
                None,   // user SID
                1,      // num strings
                0,      // data size
                Some(strings.as_ptr()),
                None,   // raw data
            );
        }
    }

    fn flush(&self) {}
}

impl Drop for WinEventLogger {
    fn drop(&mut self) {
        if self.handle != HANDLE::default() {
            unsafe {
                let _ = DeregisterEventSource(self.handle);
            }
        }
    }
}
