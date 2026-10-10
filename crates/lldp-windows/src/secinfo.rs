//! Checks of the security posture the service expects at start-up: that
//! the files it trusts are writable only by administrators, and that the
//! process token holds no privilege beyond what the service declares.
//!
//! Both are defences against misconfiguration. A configuration file a
//! standard user can edit lets that user choose what the workstation
//! advertises and which interfaces it listens on; a token with more than
//! `SeChangeNotifyPrivilege` means the service was not registered through
//! the installer or `harden` and runs with more than it needs.

use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetTokenInformation, INHERIT_ONLY_ACE,
    LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

use crate::util::{to_wide, wide_to_string};

/// SIDs that may hold write access to the service's trusted files:
/// LocalSystem, Administrators, and TrustedInstaller.
const TRUSTED_SIDS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Access mask bits that let a principal change a file or its security:
/// `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`, `DELETE`,
/// `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL`.
const WRITE_MASK: u32 =
    0x0002 | 0x0004 | 0x0010 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;

/// A principal other than SYSTEM, Administrators, or TrustedInstaller that
/// can modify a trusted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    /// The SID as text.
    pub sid: String,
    /// Why it counts: `owner`, `no DACL`, or the access mask of its ACE.
    pub reason: String,
}

impl std::fmt::Display for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.sid, self.reason)
    }
}

/// Memory the system allocated with `LocalAlloc`.
struct LocalBuf(*mut c_void);

impl Drop for LocalBuf {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a system call that allocates
            // with LocalAlloc and is freed exactly once here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

#[allow(unsafe_code)]
fn sid_string(sid: PSID) -> Option<String> {
    let mut s = PWSTR::null();
    // SAFETY: `sid` points at a valid SID inside a live security
    // descriptor; the returned string is freed by `LocalBuf`.
    unsafe { ConvertSidToStringSidW(sid, &raw mut s) }.ok()?;
    let buf = LocalBuf(s.0.cast());
    if buf.0.is_null() {
        return None;
    }
    // SAFETY: `s` is a NUL-terminated UTF-16 string from the system.
    unsafe { s.to_string() }.ok()
}

/// Lists the principals, other than SYSTEM, Administrators, and
/// TrustedInstaller, that can modify `path`: the owner if it is someone
/// else, and every allow ACE that grants a write, delete, or security
/// change right. An empty list means only administrators can change the
/// file. A missing DACL (everyone has full control) is reported as the
/// Everyone SID.
#[allow(unsafe_code)]
pub fn non_admin_writers(path: &Path) -> Result<Vec<Writer>, String> {
    let name = to_wide(&path.display().to_string());
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated; the out-pointers are valid and the
    // descriptor they point into is freed by `LocalBuf`.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            &raw mut sd,
        )
    };
    if rc.is_err() {
        return Err(format!(
            "GetNamedSecurityInfoW({}) returned {}",
            path.display(),
            rc.0
        ));
    }
    let _sd = LocalBuf(sd.0);

    let mut out = Vec::new();
    if !owner.0.is_null()
        && let Some(sid) = sid_string(owner)
        && !TRUSTED_SIDS.contains(&sid.as_str())
    {
        out.push(Writer {
            sid,
            reason: "owner".into(),
        });
    }
    if dacl.is_null() {
        out.push(Writer {
            sid: "S-1-1-0".into(),
            reason: "no DACL".into(),
        });
        return Ok(out);
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points into the live descriptor; `info` has the size
    // passed.
    unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(0),
            AclSizeInformation,
        )
    }
    .map_err(|e| format!("GetAclInformation: {e}"))?;

    for index in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the ACE count of a live ACL.
        if unsafe { GetAce(dacl, index, &raw mut ace) }.is_err() || ace.is_null() {
            continue;
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE
            && header.AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        {
            continue;
        }
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0 {
            // Applies to children only; a file has none.
            continue;
        }
        // SAFETY: allowed and allowed-callback ACEs share the
        // ACCESS_ALLOWED_ACE prefix, and the SID starts at `SidStart`.
        let (mask, sid) = unsafe {
            let a = ace.cast::<ACCESS_ALLOWED_ACE>();
            (
                (*a).Mask,
                PSID((&raw const (*a).SidStart).cast_mut().cast()),
            )
        };
        if mask & WRITE_MASK == 0 {
            continue;
        }
        let Some(sid) = sid_string(sid) else {
            continue;
        };
        if TRUSTED_SIDS.contains(&sid.as_str()) {
            continue;
        }
        out.push(Writer {
            sid,
            reason: format!("access mask 0x{mask:08x}"),
        });
    }
    Ok(out)
}

/// Names of every privilege present in the process token, enabled or not.
#[allow(unsafe_code)]
pub fn process_privileges() -> Result<Vec<String>, String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle for the current process is always valid;
    // `token` is closed below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|e| format!("OpenProcessToken: {e}"))?;
    let result = privileges_of(token);
    // SAFETY: closing the handle we opened.
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

#[allow(unsafe_code)]
fn privileges_of(token: HANDLE) -> Result<Vec<String>, String> {
    let mut needed: u32 = 0;
    // SAFETY: a null buffer with length 0 asks for the required size.
    let _ = unsafe { GetTokenInformation(token, TokenPrivileges, None, 0, &raw mut needed) };
    if needed == 0 {
        return Err("GetTokenInformation: no size".into());
    }
    // A u32 buffer keeps the 4-byte alignment TOKEN_PRIVILEGES needs.
    let mut buf = vec![0u32; (needed as usize).div_ceil(4)];
    let buf_len = buf.len().saturating_mul(4);
    // SAFETY: `buf` has at least `needed` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &raw mut needed,
        )
    }
    .map_err(|e| format!("GetTokenInformation: {e}"))?;
    if buf_len < std::mem::size_of::<TOKEN_PRIVILEGES>() {
        return Err("GetTokenInformation: short buffer".into());
    }
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES header followed by
    // `PrivilegeCount` LUID_AND_ATTRIBUTES entries, as documented.
    let (count, first) = unsafe {
        let tp = buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
        ((*tp).PrivilegeCount as usize, (*tp).Privileges.as_ptr())
    };
    let needed_len = std::mem::size_of::<u32>()
        .saturating_add(count.saturating_mul(std::mem::size_of::<LUID_AND_ATTRIBUTES>()));
    if needed_len > buf_len {
        return Err("GetTokenInformation: inconsistent count".into());
    }
    // SAFETY: `count` entries fit in the buffer, checked above.
    let entries = unsafe { std::slice::from_raw_parts(first, count) };
    Ok(entries.iter().map(privilege_name).collect())
}

#[allow(unsafe_code)]
fn privilege_name(e: &LUID_AND_ATTRIBUTES) -> String {
    let fallback = || format!("luid:{:x}:{:x}", e.Luid.HighPart, e.Luid.LowPart);
    let mut len: u32 = 0;
    // SAFETY: a null buffer asks for the required length.
    let _ = unsafe { LookupPrivilegeNameW(PCWSTR::null(), &raw const e.Luid, None, &raw mut len) };
    if len == 0 {
        return fallback();
    }
    let mut name = vec![0u16; (len as usize).saturating_add(1)];
    let mut cch = u32::try_from(name.len()).unwrap_or(0);
    // SAFETY: `name` has `cch` elements.
    let ok = unsafe {
        LookupPrivilegeNameW(
            PCWSTR::null(),
            &raw const e.Luid,
            Some(PWSTR(name.as_mut_ptr())),
            &raw mut cch,
        )
    };
    if ok.is_ok() {
        wide_to_string(&name)
    } else {
        fallback()
    }
}

/// Privileges in the process token that are not in `allowed`.
pub fn unexpected_privileges(allowed: &[&str]) -> Result<Vec<String>, String> {
    Ok(process_privileges()?
        .into_iter()
        .filter(|p| !allowed.iter().any(|a| a.eq_ignore_ascii_case(p)))
        .collect())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::assert_is_empty)]
mod tests {
    use super::{non_admin_writers, process_privileges};

    #[test]
    fn system_binary_has_no_non_admin_writers() {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let p = std::path::Path::new(&root)
            .join("System32")
            .join("ntdll.dll");
        let w = non_admin_writers(&p).unwrap_or_else(|e| panic!("{e}"));
        assert!(w.is_empty(), "{w:?}");
    }

    #[test]
    fn file_in_the_user_profile_is_reported_unless_elevated() {
        let dir = std::env::temp_dir().join(format!("winlldp-secinfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        let f = dir.join("config.yaml");
        std::fs::write(&f, "version: 1\n").unwrap_or_else(|e| panic!("{e}"));
        let w = non_admin_writers(&f).unwrap_or_else(|e| panic!("{e}"));
        let _ = std::fs::remove_dir_all(&dir);
        // A file under the user's temp directory is owned by, or writable
        // by, that user. An elevated administrator's files are owned by the
        // Administrators group, so only assert when not elevated.
        let elevated =
            process_privileges().is_ok_and(|p| p.iter().any(|n| n == "SeDebugPrivilege"));
        if !elevated {
            assert!(!w.is_empty());
        }
    }

    #[test]
    fn privileges_are_listed() {
        let p = process_privileges().unwrap_or_else(|e| panic!("{e}"));
        assert!(p.iter().any(|n| n == "SeChangeNotifyPrivilege"), "{p:?}");
    }
}
