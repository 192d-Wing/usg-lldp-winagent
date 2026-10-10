//! Error types.

use core::fmt;

/// Why an LLDPDU or frame was rejected.
///
/// Every variant corresponds to a frame that must be discarded under the
/// receive rules of IEEE 802.1AB-2016 clause 9 (`badFrame`), or to a frame
/// that is not LLDP at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The frame is shorter than an Ethernet header.
    TruncatedFrame {
        /// Octets present.
        len: usize,
    },
    /// The EtherType is not 0x88CC.
    WrongEtherType {
        /// EtherType found.
        ethertype: u16,
    },
    /// The LLDPDU exceeds [`crate::MAX_LLDPDU_LEN`].
    LldpduTooLarge {
        /// Octets present.
        len: usize,
    },
    /// A TLV header is present but its value runs past the end of the LLDPDU.
    TruncatedTlv {
        /// Offset of the TLV header.
        offset: usize,
        /// Declared value length.
        declared: usize,
        /// Octets actually remaining.
        remaining: usize,
    },
    /// A TLV header itself is cut off (one trailing octet).
    TruncatedTlvHeader {
        /// Offset of the partial header.
        offset: usize,
    },
    /// The LLDPDU is empty.
    Empty,
    /// The first three TLVs are not Chassis ID, Port ID, TTL in that order.
    MandatoryTlvOrder {
        /// Which position (0, 1, 2) was wrong.
        position: u8,
        /// TLV type found at that position.
        found: u8,
    },
    /// Fewer than three TLVs precede the End TLV or end of data.
    MissingMandatoryTlv {
        /// TLV type that was expected.
        expected: u8,
    },
    /// A mandatory TLV type appears more than once.
    DuplicateMandatoryTlv {
        /// TLV type.
        tlv_type: u8,
    },
    /// A mandatory TLV has an invalid length for its type.
    InvalidMandatoryTlvLength {
        /// TLV type.
        tlv_type: u8,
        /// Length found.
        len: usize,
    },
    /// A Chassis ID or Port ID value is longer than 255 octets (9.2.7.7.1).
    InvalidIdentifier {
        /// TLV type (1 or 2).
        tlv_type: u8,
        /// Subtype found.
        subtype: u8,
        /// Length of the identifier value.
        len: usize,
    },
    /// An optional TLV is shorter than the fields it must contain, which
    /// invalidates the whole LLDPDU (9.2.7.7.2 b).
    OptionalTlvTooShort {
        /// TLV type.
        tlv_type: u8,
        /// Length found.
        len: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedFrame { len } => write!(f, "frame truncated ({len} octets)"),
            Self::WrongEtherType { ethertype } => {
                write!(f, "EtherType 0x{ethertype:04x} is not LLDP")
            }
            Self::LldpduTooLarge { len } => write!(f, "LLDPDU of {len} octets exceeds limit"),
            Self::TruncatedTlv {
                offset,
                declared,
                remaining,
            } => write!(
                f,
                "TLV at offset {offset} declares {declared} octets but {remaining} remain"
            ),
            Self::TruncatedTlvHeader { offset } => {
                write!(f, "partial TLV header at offset {offset}")
            }
            Self::Empty => write!(f, "empty LLDPDU"),
            Self::MandatoryTlvOrder { position, found } => write!(
                f,
                "mandatory TLV order violated: position {position} holds TLV type {found}"
            ),
            Self::MissingMandatoryTlv { expected } => {
                write!(f, "missing mandatory TLV type {expected}")
            }
            Self::DuplicateMandatoryTlv { tlv_type } => {
                write!(f, "duplicate mandatory TLV type {tlv_type}")
            }
            Self::InvalidMandatoryTlvLength { tlv_type, len } => {
                write!(f, "mandatory TLV type {tlv_type} has invalid length {len}")
            }
            Self::InvalidIdentifier {
                tlv_type,
                subtype,
                len,
            } => write!(
                f,
                "TLV type {tlv_type} subtype {subtype} has invalid identifier length {len}"
            ),
            Self::OptionalTlvTooShort { tlv_type, len } => {
                write!(f, "TLV type {tlv_type} of {len} octets is too short")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why an LLDPDU could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// A TLV value exceeds the 511-octet limit of the 9-bit length field.
    ValueTooLong {
        /// TLV type.
        tlv_type: u8,
        /// Length requested.
        len: usize,
    },
    /// The encoded LLDPDU would exceed the caller's size limit.
    LldpduTooLarge {
        /// Size that would have been produced.
        len: usize,
        /// Limit in effect.
        limit: usize,
    },
    /// A value is invalid for its field (for example an empty Chassis ID).
    InvalidValue(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLong { tlv_type, len } => {
                write!(f, "TLV type {tlv_type} value of {len} octets exceeds 511")
            }
            Self::LldpduTooLarge { len, limit } => {
                write!(f, "LLDPDU of {len} octets exceeds limit of {limit}")
            }
            Self::InvalidValue(what) => write!(f, "invalid value: {what}"),
        }
    }
}

impl std::error::Error for EncodeError {}
