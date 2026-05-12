use windows::Win32::System::Performance::PdhCloseQuery;

pub struct PdhQueryGuard(pub isize);

impl Drop for PdhQueryGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            // Compliance: STIG requirement to release system resources
            unsafe { let _ = PdhCloseQuery(self.0); }
        }
    }
}
