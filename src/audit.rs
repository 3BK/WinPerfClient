use log::{Log, Metadata, Record, Level};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::EventLog::*;

pub struct WinEventLogger {
    source: HSTRING,
}

impl WinEventLogger {
    /// Initializes the global logger. Call this once in main().
    pub fn init(source_name: &str) -> Result<(), log::SetLoggerError> {
        let logger = Box::leak(Box::new(Self {
            source: HSTRING::from(source_name),
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

        unsafe {
            if let Ok(h) = RegisterEventSourceW(None, &self.source) {
                // Formatting the message for NIST AU-12 compliance
                let message = format!("[{}] {}", record.module_path().unwrap_or("main"), record.args());
                let msg_w = HSTRING::from(message);
                let strings = [PCWSTR(msg_w.as_ptr())];

                // Fixed: All 9 arguments required by windows-rs v0.58
                let _ = ReportEventW(
                    h,
                    Self::map_level(record.level()),
                    0,      // wCategory
                    1000,   // dwEventID
                    None,   // lpUserSid
                    1,      // wNumStrings
                    0,      // dwDataSize
                    Some(&strings.as_ptr()), // lpStrings
                    None,   // lpRawData
                );

                let _ = DeregisterEventSource(h);
            }
        }
    }

    fn flush(&self) {}
}
