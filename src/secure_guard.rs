use windows::Win32::System::Performance::*;

pub struct PdhQueryGuard(pub isize);

impl Drop for PdhQueryGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { let _ = PdhCloseQuery(self.0); }
        }
    }
}
