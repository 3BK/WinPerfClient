use log::debug;
use windows::Win32::System::Performance::PdhCloseQuery;

/// In the `windows` crate, PDH query handles are represented as `isize` in many bindings.
pub type PdhQueryHandle = isize;

/// RAII guard for a PDH query handle.
/// Owns the query handle and closes it on drop.
pub struct PdhQueryGuard(PdhQueryHandle);

impl PdhQueryGuard {
    pub fn new(h: PdhQueryHandle) -> Self {
        Self(h)
    }

    /// Optional: expose handle read-only if you truly need it.
    pub fn handle(&self) -> PdhQueryHandle {
        self.0
    }
}

impl Drop for PdhQueryGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let st = PdhCloseQuery(self.0);
                if st != 0 {
                    // Route via audit/log backend, not stderr.
                    debug!("PdhCloseQuery returned non-zero status: {}", st);
                }
            }
        }
    }
}
