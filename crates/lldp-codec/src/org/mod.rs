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

pub mod ieee8021;
pub mod ieee8023;
pub mod med;

/// An organizationally specific TLV interpreted by one of the known
/// decoders, or left raw.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodedOrgTlv<'a> {
    /// IEEE 802.1 TLV (OUI 00-80-C2).
    Ieee8021(ieee8021::Ieee8021Tlv),
    /// IEEE 802.3 TLV (OUI 00-12-0F).
    Ieee8023(ieee8023::Ieee8023Tlv),
    /// LLDP-MED TLV (OUI 00-12-BB).
    Med(med::MedTlv),
    /// A known OUI but a subtype or encoding the decoder does not accept.
    Unrecognized(&'a OrgTlv),
    /// An OUI this crate has no decoder for.
    Unknown(&'a OrgTlv),
}

impl OrgTlv {
    /// Interprets the TLV with the decoder for its OUI, if any.
    pub fn decode(&self) -> DecodedOrgTlv<'_> {
        match self.oui {
            oui::IEEE_802_1 => ieee8021::Ieee8021Tlv::decode(self.subtype, &self.data)
                .map_or(DecodedOrgTlv::Unrecognized(self), DecodedOrgTlv::Ieee8021),
            oui::IEEE_802_3 => ieee8023::Ieee8023Tlv::decode(self.subtype, &self.data)
                .map_or(DecodedOrgTlv::Unrecognized(self), DecodedOrgTlv::Ieee8023),
            oui::TIA_MED => med::MedTlv::decode(self.subtype, &self.data)
                .map_or(DecodedOrgTlv::Unrecognized(self), DecodedOrgTlv::Med),
            _ => DecodedOrgTlv::Unknown(self),
        }
    }
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    crate::ethernet::read_u16(b, at)
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let s: [u8; 4] = b.get(at..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(s))
}
