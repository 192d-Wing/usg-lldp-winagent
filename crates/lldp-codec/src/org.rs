//! Organizationally specific TLV framing (IEEE 802.1AB-2016 clause 8.6).
//!
//! The value of a type-127 TLV is a 3-octet OUI, a 1-octet subtype, and 0 to
//! 507 octets of organizationally defined data. This module handles that
//! framing only; decoders for specific organizations live in submodules
//! added in later increments.

use crate::error::EncodeError;
use crate::tlv::MAX_VALUE_LEN;

/// Well-known OUIs.
pub mod oui {
    /// IEEE 802.1 (VLAN, protocol identity, link aggregation TLVs).
    pub const IEEE_802_1: [u8; 3] = [0x00, 0x80, 0xC2];
    /// IEEE 802.3 (MAC/PHY, power via MDI, max frame size TLVs).
    pub const IEEE_802_3: [u8; 3] = [0x00, 0x12, 0x0F];
    /// TIA (LLDP-MED).
    pub const TIA_MED: [u8; 3] = [0x00, 0x12, 0xBB];
}

/// Longest organizationally defined data field (511 minus OUI and subtype).
pub const MAX_ORG_DATA_LEN: usize = MAX_VALUE_LEN - 4;

/// A raw organizationally specific TLV.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrgTlv {
    /// Organizationally unique identifier.
    pub oui: [u8; 3],
    /// Organizationally defined subtype.
    pub subtype: u8,
    /// Organizationally defined data.
    pub data: Vec<u8>,
}

impl OrgTlv {
    /// Parses a type-127 TLV value. Returns `None` if shorter than 4 octets.
    pub fn parse(value: &[u8]) -> Option<Self> {
        let oui: [u8; 3] = value.get(..3)?.try_into().ok()?;
        let subtype = *value.get(3)?;
        let data = value.get(4..)?.to_vec();
        Some(Self { oui, subtype, data })
    }

    /// Serializes the TLV value.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.data.len() > MAX_ORG_DATA_LEN {
            return Err(EncodeError::ValueTooLong {
                tlv_type: crate::tlv::tlv_type::ORGANIZATIONAL,
                len: self.data.len().saturating_add(4),
            });
        }
        out.extend_from_slice(&self.oui);
        out.push(self.subtype);
        out.extend_from_slice(&self.data);
        Ok(())
    }
}
