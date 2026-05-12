use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::EventLog::*;

pub struct Auditor(HSTRING);

impl Auditor {
    pub fn new(name: &str) -> Self { Self(HSTRING::from(name)) }
    pub fn log(&self, id: u32, msg: &str, level: u16) {
        unsafe {
            if let Ok(h) = RegisterEventSourceW(None, &self.0) {
                let m = HSTRING::from(msg);
                let _ = ReportEventW(h, level, 0, id, None, Some(&[PCWSTR(m.as_ptr())]), None);
                let _ = DeregisterEventSource(h);
            }
        }
    }
}
