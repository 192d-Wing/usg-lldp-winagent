//! Windows integration for WinLLDP.
//!
//! Everything here is `#[cfg(windows)]`; on other platforms the crate is
//! empty so the workspace still builds and tests. `unsafe` is confined to
//! the FFI modules and every block carries a safety comment.

#![deny(unsafe_code)]

#[cfg(windows)]
pub mod adapters;
#[cfg(windows)]
pub mod monitor;
#[cfg(windows)]
pub mod mslldp;
#[cfg(windows)]
pub mod npcap;
pub mod parse;
#[cfg(windows)]
pub mod policy;
#[cfg(windows)]
pub mod sysinfo;

#[cfg(windows)]
pub(crate) mod util;
