use windows::Win32::System::Performance::{PdhCloseQuery, PDH_HQUERY};

/// RAII guard for a PDH query handle.
/// Owns the query handle and closes it on drop.
pub struct PdhQueryGuard(PDH_HQUERY);

impl PdhQueryGuard {
    pub fn new(h: PDH_HQUERY) -> Self {
        Self(h)
    }

    /// Optional: expose handle read-only if you truly need it.
    pub fn handle(&self) -> PDH_HQUERY {
        self.0
    }
}

impl Drop for PdhQueryGuard {
    fn drop(&mut self) {
        if self.0 != PDH_HQUERY::default() {
            unsafe {
                let _ = PdhCloseQuery(self.0);
            }
        }
    }
}
