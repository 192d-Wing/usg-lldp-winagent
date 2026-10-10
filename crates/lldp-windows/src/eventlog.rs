//! Windows Event Log sink with token-bucket rate limiting.
//!
//! Messages are rendered by the generic .NET Framework message file
//! (`EventLogMessages.dll`), which maps every event ID to its first
//! insertion string. The installer registers the source; see
//! [`register_source`] for the dev-time equivalent.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HANDLE};
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    REPORT_EVENT_TYPE, RegisterEventSourceW, ReportEventW,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW,
};
use windows::core::PCWSTR;

use crate::util::to_wide;

/// Event source name.
pub const SOURCE: &str = "WinLLDP";

/// Severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

/// Event IDs. Stable; documented in docs/troubleshooting.md.
pub mod id {
    /// Service started.
    pub const SERVICE_STARTED: u32 = 1000;
    /// Service stopped.
    pub const SERVICE_STOPPED: u32 = 1001;
    /// Configuration loaded.
    pub const CONFIG_LOADED: u32 = 1002;
    /// Configuration error.
    pub const CONFIG_ERROR: u32 = 1003;
    /// Registry policy applied.
    pub const POLICY_APPLIED: u32 = 1004;
    /// Npcap missing or too old.
    pub const NPCAP_UNAVAILABLE: u32 = 1100;
    /// Npcap version in use.
    pub const NPCAP_VERSION: u32 = 1101;
    /// Interface is now managed.
    pub const INTERFACE_MANAGED: u32 = 1200;
    /// Interface is no longer managed.
    pub const INTERFACE_UNMANAGED: u32 = 1201;
    /// Packet channel open failed.
    pub const PORT_OPEN_FAILED: u32 = 1202;
    /// Port task failed.
    pub const PORT_FAILED: u32 = 1203;
    /// Neighbor added.
    pub const NEIGHBOR_ADDED: u32 = 1300;
    /// Neighbor updated.
    pub const NEIGHBOR_UPDATED: u32 = 1301;
    /// Neighbor expired.
    pub const NEIGHBOR_EXPIRED: u32 = 1302;
    /// Neighbor removed.
    pub const NEIGHBOR_REMOVED: u32 = 1303;
    /// Too many neighbors on an interface.
    pub const TOO_MANY_NEIGHBORS: u32 = 1304;
    /// Malformed frame discarded.
    pub const FRAME_DISCARDED: u32 = 1305;
    /// Transmit failure.
    pub const TRANSMIT_FAILED: u32 = 1306;
    /// MsLldp binding changed.
    pub const MSLLDP_BINDING_CHANGED: u32 = 1400;
    /// MsLldp binding change failed.
    pub const MSLLDP_BINDING_ERROR: u32 = 1401;
    /// IPC server started.
    pub const IPC_STARTED: u32 = 1500;
    /// IPC server error.
    pub const IPC_ERROR: u32 = 1501;
    /// Events were suppressed by rate limiting.
    pub const EVENTS_SUPPRESSED: u32 = 1900;
}

struct Bucket {
    capacity: u32,
    tokens: u32,
    refill_per_minute: u32,
    last: Instant,
    suppressed: u64,
}

impl Bucket {
    fn take(&mut self, now: Instant) -> Result<u64, ()> {
        let elapsed = now.saturating_duration_since(self.last);
        if elapsed >= Duration::from_secs(1) {
            let refill = u64::from(self.refill_per_minute).saturating_mul(elapsed.as_secs()) / 60;
            let refill = u32::try_from(refill).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
            if refill > 0 {
                self.last = now;
            }
        }
        if self.tokens == 0 {
            self.suppressed = self.suppressed.saturating_add(1);
            return Err(());
        }
        self.tokens = self.tokens.saturating_sub(1);
        Ok(std::mem::take(&mut self.suppressed))
    }
}

/// An open event source.
pub struct EventLog {
    handle: HANDLE,
    bucket: Mutex<Bucket>,
}

// SAFETY: the event source handle may be used from any thread.
#[allow(unsafe_code)]
unsafe impl Send for EventLog {}
#[allow(unsafe_code)]
unsafe impl Sync for EventLog {}

impl EventLog {
    /// Opens the source with `per_minute` as the sustained event rate.
    #[allow(unsafe_code)]
    pub fn open(per_minute: u32) -> Result<Self, String> {
        let w = to_wide(SOURCE);
        // SAFETY: `w` is NUL-terminated; handle is released in Drop.
        let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(w.as_ptr())) }
            .map_err(|e| format!("RegisterEventSourceW: {e}"))?;
        let per_minute = per_minute.max(1);
        Ok(Self {
            handle,
            bucket: Mutex::new(Bucket {
                capacity: per_minute,
                tokens: per_minute,
                refill_per_minute: per_minute,
                last: Instant::now(),
                suppressed: 0,
            }),
        })
    }

    /// Writes an event, subject to rate limiting. Returns false if it was
    /// suppressed.
    #[allow(unsafe_code)]
    pub fn report(&self, level: Level, event_id: u32, message: &str) -> bool {
        let Ok(Ok(released)) = self.bucket.lock().map(|mut b| b.take(Instant::now())) else {
            return false;
        };
        if released > 0 {
            self.write(
                Level::Warning,
                id::EVENTS_SUPPRESSED,
                &format!("{released} event(s) were suppressed by rate limiting"),
            );
        }
        self.write(level, event_id, message);
        true
    }

    #[allow(unsafe_code)]
    fn write(&self, level: Level, event_id: u32, message: &str) {
        let kind: REPORT_EVENT_TYPE = match level {
            Level::Info => EVENTLOG_INFORMATION_TYPE,
            Level::Warning => EVENTLOG_WARNING_TYPE,
            Level::Error => EVENTLOG_ERROR_TYPE,
        };
        let w = to_wide(message);
        let strings = [PCWSTR(w.as_ptr())];
        // SAFETY: `handle` is open; `strings` points at a NUL-terminated
        // buffer that outlives the call.
        unsafe {
            let _ = ReportEventW(
                self.handle,
                kind,
                0,
                event_id,
                None,
                0,
                Some(&strings),
                None,
            );
        }
    }
}

impl Drop for EventLog {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: handle from RegisterEventSourceW.
        unsafe {
            let _ = DeregisterEventSource(self.handle);
        }
    }
}

/// Registers the event source so messages render. Requires
/// administrative rights; the MSI does this in production.
#[allow(unsafe_code)]
pub fn register_source() -> Result<(), String> {
    let key = to_wide(&format!(
        "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\{SOURCE}"
    ));
    let mut h = HKEY::default();
    // SAFETY: strings are NUL-terminated; the key is closed below.
    unsafe {
        let rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &raw mut h,
            None,
        );
        if rc.is_err() {
            return Err(format!("RegCreateKeyExW returned {}", rc.0));
        }
        let file =
            to_wide("%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\EventLogMessages.dll");
        let name = to_wide("EventMessageFile");
        let bytes: Vec<u8> = file.iter().flat_map(|c| c.to_le_bytes()).collect();
        let rc1 = RegSetValueExW(h, PCWSTR(name.as_ptr()), None, REG_EXPAND_SZ, Some(&bytes));
        let name = to_wide("TypesSupported");
        let rc2 = RegSetValueExW(
            h,
            PCWSTR(name.as_ptr()),
            None,
            REG_DWORD,
            Some(&7u32.to_le_bytes()),
        );
        let _ = RegCloseKey(h);
        if rc1.is_err() || rc2.is_err() {
            return Err("RegSetValueExW failed".into());
        }
    }
    Ok(())
}

/// Removes the registration made by [`register_source`]. A source that is
/// not registered is not an error.
#[allow(unsafe_code)]
pub fn unregister_source() -> Result<(), String> {
    let key = to_wide(&format!(
        "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\{SOURCE}"
    ));
    // SAFETY: `key` is NUL-terminated.
    let rc = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(key.as_ptr())) };
    if rc.is_ok() || rc == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("RegDeleteKeyW returned {}", rc.0))
    }
}

#[cfg(test)]
mod tests {
    use super::Bucket;
    use std::time::{Duration, Instant};

    #[test]
    fn bucket_limits_and_reports_suppression() {
        let t0 = Instant::now();
        let mut b = Bucket {
            capacity: 3,
            tokens: 3,
            refill_per_minute: 60,
            last: t0,
            suppressed: 0,
        };
        assert_eq!(b.take(t0), Ok(0));
        assert_eq!(b.take(t0), Ok(0));
        assert_eq!(b.take(t0), Ok(0));
        assert_eq!(b.take(t0), Err(()));
        assert_eq!(b.take(t0), Err(()));
        // One second later one token is back, and the suppressed count is released.
        assert_eq!(b.take(t0 + Duration::from_secs(1)), Ok(2));
        assert_eq!(b.take(t0 + Duration::from_secs(1)), Err(()));
        // Never exceeds capacity.
        assert_eq!(b.take(t0 + Duration::from_secs(600)), Ok(1));
        assert_eq!(b.take(t0 + Duration::from_secs(600)), Ok(0));
        assert_eq!(b.take(t0 + Duration::from_secs(600)), Ok(0));
        assert_eq!(b.take(t0 + Duration::from_secs(600)), Err(()));
    }
}
