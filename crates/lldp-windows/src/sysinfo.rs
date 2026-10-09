//! Local system facts used to build advertisements.

use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows::Win32::System::SystemInformation::{
    ComputerNameDnsFullyQualified, ComputerNameDnsHostname, FIRMWARE_TABLE_PROVIDER,
    GetComputerNameExW, GetNativeSystemInfo, GetSystemFirmwareTable, SYSTEM_INFO,
};
use windows::core::PCWSTR;

use crate::util::{to_wide, wide_to_string};

/// Facts about this machine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemInfo {
    /// DNS host name (short).
    pub hostname: String,
    /// Fully qualified DNS name; equals `hostname` when not domain-joined.
    pub fqdn: String,
    /// Registry `ProductName`, for example "Windows 11 Enterprise".
    pub product_name: String,
    /// Registry `DisplayVersion`, for example "24H2".
    pub display_version: String,
    /// Registry `CurrentBuild`.
    pub build: String,
    /// "x64", "ARM64", or "unknown".
    pub architecture: &'static str,
    /// SMBIOS system manufacturer.
    pub manufacturer: Option<String>,
    /// SMBIOS system product name.
    pub model: Option<String>,
    /// SMBIOS system UUID as 36-character text.
    pub smbios_uuid: Option<String>,
}

impl SystemInfo {
    /// Collects everything. Individual lookups that fail leave their field
    /// empty rather than failing the whole call.
    pub fn collect() -> Self {
        let (hostname, fqdn) = names();
        let (manufacturer, model, smbios_uuid) = smbios();
        Self {
            hostname,
            fqdn,
            product_name: reg_sz(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "ProductName",
            )
            .unwrap_or_default(),
            display_version: reg_sz(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "DisplayVersion",
            )
            .unwrap_or_default(),
            build: reg_sz(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "CurrentBuild",
            )
            .unwrap_or_default(),
            architecture: architecture(),
            manufacturer,
            model,
            smbios_uuid,
        }
    }

    /// Whether the machine has a DNS domain suffix.
    pub fn domain_joined(&self) -> bool {
        !self.fqdn.is_empty() && !self.fqdn.eq_ignore_ascii_case(&self.hostname)
    }

    /// Builds the System Description per the privacy switches.
    pub fn system_description(&self, os_version: bool, hardware: bool) -> String {
        let mut s = if self.product_name.is_empty() {
            "Microsoft Windows".to_owned()
        } else {
            format!("Microsoft {}", self.product_name)
        };
        if os_version {
            if !self.display_version.is_empty() {
                s.push(' ');
                s.push_str(&self.display_version);
            }
            if !self.build.is_empty() {
                s.push_str(" (build ");
                s.push_str(&self.build);
                s.push(')');
            }
            s.push(' ');
            s.push_str(self.architecture);
        }
        if hardware && let Some(m) = &self.manufacturer {
            s.push_str(" on ");
            s.push_str(m.trim());
            if let Some(model) = &self.model {
                s.push(' ');
                s.push_str(model.trim());
            }
        }
        s
    }
}

#[allow(unsafe_code)]
fn computer_name(
    format: windows::Win32::System::SystemInformation::COMPUTER_NAME_FORMAT,
) -> String {
    let mut size: u32 = 0;
    // SAFETY: a null buffer with size 0 asks for the required length.
    let _ = unsafe { GetComputerNameExW(format, None, &raw mut size) };
    if size == 0 {
        return String::new();
    }
    let mut buf = vec![0u16; size as usize];
    // SAFETY: `buf` has `size` elements.
    let ok = unsafe {
        GetComputerNameExW(
            format,
            Some(windows::core::PWSTR(buf.as_mut_ptr())),
            &raw mut size,
        )
    };
    if ok.is_err() {
        String::new()
    } else {
        wide_to_string(&buf)
    }
}

fn names() -> (String, String) {
    (
        computer_name(ComputerNameDnsHostname),
        computer_name(ComputerNameDnsFullyQualified),
    )
}

#[allow(unsafe_code)]
fn reg_sz(subkey: &str, value: &str) -> Option<String> {
    let k = to_wide(subkey);
    let v = to_wide(value);
    let mut size: u32 = 0;
    // SAFETY: strings are NUL-terminated; a null data pointer requests size.
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

#[allow(unsafe_code)]
fn architecture() -> &'static str {
    let mut si = SYSTEM_INFO::default();
    // SAFETY: `si` is a valid out-pointer.
    unsafe { GetNativeSystemInfo(&raw mut si) };
    // SAFETY: the union's Anonymous layout is the documented one.
    let arch = unsafe { si.Anonymous.Anonymous.wProcessorArchitecture };
    match arch.0 {
        9 => "x64",
        12 => "ARM64",
        0 => "x86",
        _ => "unknown",
    }
}

/// Reads SMBIOS type 1 (System Information).
#[allow(unsafe_code)]
fn smbios() -> (Option<String>, Option<String>, Option<String>) {
    const RSMB: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(0x5253_4D42);
    // SAFETY: a null buffer asks for the required size.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, None) } as usize;
    if size < 8 {
        return (None, None, None);
    }
    let mut buf = vec![0u8; size];
    // SAFETY: `buf` has `size` bytes.
    let got = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(&mut buf)) } as usize;
    if got < 8 || got > size {
        return (None, None, None);
    }
    crate::parse::parse_smbios_type1(buf.get(8..got).unwrap_or_default())
}
