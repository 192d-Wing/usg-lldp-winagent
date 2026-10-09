//! Basic TLV framing (IEEE 802.1AB-2016 clause 8.4).
//!
//! Each TLV starts with a 16-bit header: 7 bits of type and 9 bits of
//! value length, most significant bit first.

use crate::error::{DecodeError, EncodeError};

/// Maximum value length representable by the 9-bit length field.
pub const MAX_VALUE_LEN: usize = 511;

/// TLV type codes defined in 802.1AB-2016 Table 8-1.
pub mod tlv_type {
    /// End of LLDPDU.
    pub const END: u8 = 0;
    /// Chassis ID.
    pub const CHASSIS_ID: u8 = 1;
    /// Port ID.
    pub const PORT_ID: u8 = 2;
    /// Time To Live.
    pub const TTL: u8 = 3;
    /// Port Description.
    pub const PORT_DESCRIPTION: u8 = 4;
    /// System Name.
    pub const SYSTEM_NAME: u8 = 5;
    /// System Description.
    pub const SYSTEM_DESCRIPTION: u8 = 6;
    /// System Capabilities.
    pub const SYSTEM_CAPABILITIES: u8 = 7;
    /// Management Address.
    pub const MANAGEMENT_ADDRESS: u8 = 8;
    /// Organizationally Specific.
    pub const ORGANIZATIONAL: u8 = 127;
}

/// A TLV as found on the wire: type code and a borrowed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTlv<'a> {
    /// 7-bit type code.
    pub tlv_type: u8,
    /// Value octets (0 to 511).
    pub value: &'a [u8],
    /// Offset of this TLV's header within the LLDPDU, for diagnostics.
    pub offset: usize,
}

/// Iterates over the TLVs of an LLDPDU.
///
/// Yields `Err` on the first framing error and then stops. Does not
/// interpret the End TLV; the caller decides whether to stop there.
#[derive(Debug, Clone)]
pub struct TlvIter<'a> {
    data: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> TlvIter<'a> {
    /// Creates an iterator over `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            failed: false,
        }
    }

    /// Current byte offset.
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<RawTlv<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset >= self.data.len() {
            return None;
        }
        let offset = self.offset;
        let Some(header) = crate::ethernet::read_u16(self.data, offset) else {
            self.failed = true;
            return Some(Err(DecodeError::TruncatedTlvHeader { offset }));
        };
        let tlv_type = (header >> 9) as u8;
        let len = usize::from(header & 0x01FF);
        let value_start = offset.saturating_add(2);
        let value_end = value_start.saturating_add(len);
        let Some(value) = self.data.get(value_start..value_end) else {
            self.failed = true;
            return Some(Err(DecodeError::TruncatedTlv {
                offset,
                declared: len,
                remaining: self.data.len().saturating_sub(value_start),
            }));
        };
        self.offset = value_end;
        Some(Ok(RawTlv {
            tlv_type,
            value,
            offset,
        }))
    }
}

/// Appends a TLV header and value to `out`.
pub fn write_tlv(out: &mut Vec<u8>, tlv_type: u8, value: &[u8]) -> Result<(), EncodeError> {
    if value.len() > MAX_VALUE_LEN {
        return Err(EncodeError::ValueTooLong {
            tlv_type,
            len: value.len(),
        });
    }
    // `len` is at most 511 here, so the conversion cannot fail.
    let len = u16::try_from(value.len()).unwrap_or(0) & 0x01FF;
    let header = (u16::from(tlv_type & 0x7F) << 9) | len;
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
