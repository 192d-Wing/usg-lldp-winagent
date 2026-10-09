//! Registry policy overrides from `HKLM\SOFTWARE\Policies\WinLLDP`.

use lldp_config::{InterfaceMode, PolicyOverrides};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::core::PCWSTR;

use crate::util::{to_wide, wide_to_string};

/// Policy key path.
pub const POLICY_KEY: &str = "SOFTWARE\\Policies\\WinLLDP";

/// Reads the policy values that exist. Missing values stay `None`.
pub fn read() -> PolicyOverrides {
    PolicyOverrides {
        enabled: dword("Enabled").map(|v| v != 0),
        default_mode: sz("DefaultMode").and_then(|s| match s.to_ascii_lowercase().as_str() {
            "disabled" => Some(InterfaceMode::Disabled),
            "rx_only" => Some(InterfaceMode::RxOnly),
            "tx_only" => Some(InterfaceMode::TxOnly),
            "rx_tx" => Some(InterfaceMode::RxTx),
            _ => None,
        }),
        advertise_fqdn: dword("AdvertiseFqdn").map(|v| v != 0),
        advertise_os_version: dword("AdvertiseOsVersion").map(|v| v != 0),
        advertise_hardware: dword("AdvertiseHardware").map(|v| v != 0),
        advertise_management_address: dword("AdvertiseManagementAddress").map(|v| v != 0),
    }
}

#[allow(unsafe_code)]
fn dword(name: &str) -> Option<u32> {
    let k = to_wide(POLICY_KEY);
    let v = to_wide(name);
    let mut data: u32 = 0;
    let mut size: u32 = 4;
    // SAFETY: strings are NUL-terminated; `data` has `size` bytes.
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
    rc.is_ok().then_some(data)
}

#[allow(unsafe_code)]
fn sz(name: &str) -> Option<String> {
    let k = to_wide(POLICY_KEY);
    let v = to_wide(name);
    let mut size: u32 = 0;
    // SAFETY: as in sysinfo::reg_sz.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&raw mut size),
        )
    };
    if rc.is_err() || size == 0 {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    // SAFETY: `buf` has at least `size` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&raw mut size),
        )
    };
    rc.is_ok().then(|| wide_to_string(&buf))
}
