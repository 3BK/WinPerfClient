use log::{Level, Log, Metadata, Record};
use std::sync::Mutex;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

pub struct WinEventLogger {
    source: HSTRING,
    handle: HANDLE,
    lock: Mutex<()>,
}

impl WinEventLogger {
    pub fn init(source_name: &str) -> Result<(), log::SetLoggerError> {
        let source = HSTRING::from(source_name);

        // CWE-400 fix: register once; reuse handle.
        let handle = unsafe {
            RegisterEventSourceW(None, PCWSTR(source.as_ptr()))
                .unwrap_or_else(|_| HANDLE::default())
        };

        let logger = Box::leak(Box::new(Self {
            source,
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

        // If registration failed, no-op.
        if self.handle == HANDLE::default() {
            return;
        }

        let message = format!(
            "[{}] {}",
            record.module_path().unwrap_or("main"),
            record.args()
        );
        let msg_w = HSTRING::from(message);
        let strings = [PCWSTR(msg_w.as_ptr())];

        // Serialize access (conservative).
        let _g = self.lock.lock().ok();

        unsafe {
            // ReportEventW signature in windows bindings includes raw data arg.
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
