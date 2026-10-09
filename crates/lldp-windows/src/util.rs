//! Small helpers shared by the FFI modules.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

/// Converts a NUL-terminated UTF-16 buffer to a `String`.
pub(crate) fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(buf.get(..end).unwrap_or_default())
        .to_string_lossy()
        .into_owned()
}

/// Converts a `&str` to a NUL-terminated UTF-16 vector.
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Formats a GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, upper case.
pub(crate) fn guid_string(g: &windows::core::GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}
