use log::{debug, warn};
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
                let st = PdhCloseQuery(self.0);

                // PDH status codes: 0 == ERROR_SUCCESS in typical Win32 style.
                // Route diagnostics through the logging/audit backend, not stderr.
                if st != 0 {
                    // Prefer debug to avoid noise; escalate if you want.
                    debug!("PdhCloseQuery returned non-zero status: {}", st);

                    // If you want this to be more visible operationally, switch to warn!:
                    // warn!("PdhCloseQuery returned non-zero status: {}", st);
                    //
                    // Or keep both with a feature flag; leaving as debug by default.
                    let _ = &warn; // keep import usable if you switch levels later
                }
            }
        }
    }
}
