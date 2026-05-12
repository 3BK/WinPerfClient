use log::{Level, LevelFilter, Log, Metadata, Record};
use std::sync::Mutex;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

fn sanitize_for_eventlog(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }
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

fn configured_level() -> LevelFilter {
    std::env::var("WINPERF_LOG_LEVEL")
        .ok()
        .as_deref()
        .map(parse_level_filter)
        .unwrap_or(LevelFilter::Info)
}

pub struct WinEventLogger {
    handle: HANDLE,
    level: LevelFilter,
    lock: Mutex<()>,
}

// The `log::Log` trait requires `Send + Sync`.
// HANDLE wraps a raw pointer, so Rust doesn't auto-derive these traits.
// This is safe here because:
// - the handle is immutable after init
// - calls are serialized by `lock`
unsafe impl Send for WinEventLogger {}
unsafe impl Sync for WinEventLogger {}

impl WinEventLogger {
    pub fn init(source_name: &str) -> Result<(), log::SetLoggerError> {
        let level = configured_level();
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
        if self.level == LevelFilter::Off {
            return false;
        }
        metadata.level() <= self.level.to_level().unwrap_or(Level::Error)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if self.handle == HANDLE::default() {
            return;
        }

        let module = record.module_path().unwrap_or("main");
        let msg = format!("[{}][{}] {}", module, record.level(), record.args());
        let msg = sanitize_for_eventlog(&msg);

        let msg_w = HSTRING::from(msg);
        let strings = [PCWSTR(msg_w.as_ptr())];

        let _g = self.lock.lock().ok();

        unsafe {
            // IMPORTANT: windows-0.58 binding expects 8 args (per compiler error).
            // Signature order in your build is:
            //   (heventlog, wtype, wcategory, dweventid, lpusersid, dwdatasize, lprawdata, lpstrings)
            let _ = ReportEventW(
                self.handle,
                Self::map_level(record.level()),
                0,      // category
                1000,   // event id
                None,   // user SID
                0,      // data size
                None,   // raw data pointer
                Some(strings.as_ptr()),
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
