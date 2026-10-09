//! Control of the Microsoft LLDP protocol driver binding (`ms_lldp`) per
//! adapter, so this agent and MsLldp do not both advertise on one port.
//!
//! Implementation note: the documented, supported way to change adapter
//! bindings is the NetAdapter CIM class, which PowerShell exposes as
//! `Enable-/Disable-NetAdapterBinding`. This module invokes Windows
//! PowerShell 5.1 by absolute path with a fixed, non-interactive command
//! line and the adapter selected by GUID. A COM `INetCfg` implementation
//! can replace it later without changing callers.

use std::process::Command;

use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE,
    RRF_RT_REG_DWORD, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegSetValueExW,
};
use windows::core::PCWSTR;

use crate::util::to_wide;

/// Component ID of the Microsoft LLDP Protocol Driver binding.
pub const COMPONENT_ID: &str = "ms_lldp";

/// Where prior binding state is recorded so uninstall can restore it.
pub const STATE_KEY: &str = "SOFTWARE\\WinLLDP\\State\\Bindings";

/// Errors from binding control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingError(pub String);

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ms_lldp binding: {}", self.0)
    }
}

impl std::error::Error for BindingError {}

fn powershell() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    format!("{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
}

fn run(script: &str) -> Result<String, BindingError> {
    let out = Command::new(powershell())
        .args([
            "-NonInteractive",
            "-NoProfile",
            "-NoLogo",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|e| BindingError(format!("cannot start PowerShell: {e}")))?;
    if !out.status.success() {
        return Err(BindingError(format!(
            "PowerShell exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn guid_ok(guid: &str) -> Result<(), BindingError> {
    let g = guid.trim_matches(|c| c == '{' || c == '}');
    if g.len() == 36 && g.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        Ok(())
    } else {
        Err(BindingError(format!("invalid adapter GUID {guid}")))
    }
}

/// Whether `ms_lldp` is currently bound on the adapter.
pub fn is_enabled(guid: &str) -> Result<bool, BindingError> {
    guid_ok(guid)?;
    let s = format!(
        "(Get-NetAdapter -IncludeHidden | Where-Object InterfaceGuid -eq '{guid}' | Get-NetAdapterBinding -ComponentID {COMPONENT_ID}).Enabled"
    );
    match run(&s)?.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(BindingError(format!("unexpected output '{other}'"))),
    }
}

fn set(guid: &str, enable: bool) -> Result<(), BindingError> {
    guid_ok(guid)?;
    let verb = if enable { "Enable" } else { "Disable" };
    let s = format!(
        "Get-NetAdapter -IncludeHidden | Where-Object InterfaceGuid -eq '{guid}' | {verb}-NetAdapterBinding -ComponentID {COMPONENT_ID} -ErrorAction Stop"
    );
    run(&s).map(|_| ())
}

/// Disables `ms_lldp` on the adapter after recording its prior state.
/// Idempotent: if a record already exists it is left alone.
pub fn disable_and_record(guid: &str) -> Result<(), BindingError> {
    if read_state(guid).is_none() {
        let prior = is_enabled(guid)?;
        write_state(guid, prior)?;
        if !prior {
            return Ok(());
        }
    }
    set(guid, false)
}

/// Restores the recorded state and removes the record.
pub fn restore(guid: &str) -> Result<(), BindingError> {
    match read_state(guid) {
        Some(true) => {
            set(guid, true)?;
            clear_state(guid)
        }
        Some(false) => clear_state(guid),
        None => Ok(()),
    }
}

#[allow(unsafe_code)]
fn open_state_key(write: bool) -> Result<HKEY, BindingError> {
    let k = to_wide(STATE_KEY);
    let mut h = HKEY::default();
    let access = if write {
        KEY_READ | KEY_WRITE
    } else {
        KEY_READ
    };
    // SAFETY: `k` is NUL-terminated; `h` receives the key handle.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            access,
            None,
            &raw mut h,
            None,
        )
    };
    if rc.is_err() {
        Err(BindingError(format!("RegCreateKeyExW returned {}", rc.0)))
    } else {
        Ok(h)
    }
}

#[allow(unsafe_code)]
fn read_state(guid: &str) -> Option<bool> {
    let k = to_wide(STATE_KEY);
    let v = to_wide(guid);
    let mut data: u32 = 0;
    let mut size: u32 = 4;
    // SAFETY: as in policy::dword.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast()),
            Some(&raw mut size),
        )
    };
    rc.is_ok().then_some(data != 0)
}

#[allow(unsafe_code)]
fn write_state(guid: &str, enabled: bool) -> Result<(), BindingError> {
    let h = open_state_key(true)?;
    let v = to_wide(guid);
    let data: u32 = u32::from(enabled);
    // SAFETY: `h` is open; the data slice is 4 bytes of a u32.
    let rc = unsafe {
        RegSetValueExW(
            h,
            PCWSTR(v.as_ptr()),
            None,
            REG_DWORD,
            Some(&data.to_le_bytes()),
        )
    };
    // SAFETY: closing the key we opened.
    unsafe {
        let _ = RegCloseKey(h);
    }
    if rc.is_err() {
        Err(BindingError(format!("RegSetValueExW returned {}", rc.0)))
    } else {
        Ok(())
    }
}

#[allow(unsafe_code)]
fn clear_state(guid: &str) -> Result<(), BindingError> {
    let h = open_state_key(true)?;
    let v = to_wide(guid);
    // SAFETY: `h` is open and `v` is NUL-terminated.
    let rc = unsafe { RegDeleteValueW(h, PCWSTR(v.as_ptr())) };
    // SAFETY: closing the key we opened.
    unsafe {
        let _ = RegCloseKey(h);
    }
    if rc.is_err() {
        Err(BindingError(format!("RegDeleteValueW returned {}", rc.0)))
    } else {
        Ok(())
    }
}
