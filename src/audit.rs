use log::{Level, Log, Metadata, Record};
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

pub struct WinEventLogger {
    handle: HANDLE,
    lock: Mutex<()>,
}

impl WinEventLogger {
    pub fn init(source_name: &str) -> Result<(), log::SetLoggerError> {
        let source = HSTRING::from(source_name);

        // Register once (avoids per-record churn).
        let handle = unsafe {
            RegisterEventSourceW(None, PCWSTR(source.as_ptr()))
                .unwrap_or_else(|_| HANDLE::default())
        };

        let logger = Box::leak(Box::new(Self {
            handle,
            lock: Mutex::new(()),
        }));

        log::set_logger(logger)?;
        log::set_max_level(log::LevelFilter::Info);
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
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if self.handle == HANDLE::default() {
            return;
        }

        let module = record.module_path().unwrap_or("main");
        let msg = format!("[{}] {}", module, record.args());
        let msg = sanitize_for_eventlog(&msg);

        let msg_w = HSTRING::from(msg);
        let strings = [PCWSTR(msg_w.as_ptr())];

        // Serialize to be conservative with handle usage.
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
