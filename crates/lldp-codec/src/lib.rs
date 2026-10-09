//! IEEE 802.1AB-2016 LLDPDU encoding and decoding.
//!
//! This crate is platform independent and contains no `unsafe` code. Every
//! byte read is bounds-checked and every length arithmetic is checked, so
//! malformed input yields a [`DecodeError`], never a panic.
//!
//! Layout follows the standard:
//! - [`ethernet`]: the Ethernet encapsulation (clause 7 and 8.1).
//! - [`tlv`]: the basic TLV framing (8.4).
//! - [`types`]: the value types of the mandatory and basic optional TLVs
//!   (8.5).
//! - [`org`]: organizationally specific TLV framing (8.6).
//! - [`lldpdu`]: whole-LLDPDU decode and encode with the receive validation
//!   rules of clause 9.
//!
//! Clause references are to IEEE Std 802.1AB-2016 and must be verified
//! against the published text (see `docs/standards-compliance.md`).

#![forbid(unsafe_code)]

pub mod error;
pub mod ethernet;
pub mod lldpdu;
pub mod org;
pub mod tlv;
pub mod types;

pub use error::{DecodeError, EncodeError};
pub use ethernet::{EthernetHeader, LLDP_ETHERTYPE, LldpDestination, MacAddr};
pub use lldpdu::{DecodeReport, DecodeWarning, Decoded, Lldpdu, Tlv};
pub use org::{DecodedOrgTlv, OrgTlv};
pub use types::{
    AddressFamily, Capability, ChassisId, ChassisIdSubtype, InterfaceNumbering, ManagementAddress,
    NetworkAddress, PortId, PortIdSubtype, SystemCapabilities,
};

/// Largest LLDPDU this crate will decode or encode, in octets.
///
/// A standard Ethernet frame carries at most 1500 octets of payload. Jumbo
/// frames are accepted up to this bound so a hostile sender cannot make the
/// decoder allocate without limit.
pub const MAX_LLDPDU_LEN: usize = 9216;
