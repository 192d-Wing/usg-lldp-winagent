//! Whole-LLDPDU decoding and encoding with the receive validation rules of
//! IEEE 802.1AB-2016 clause 9.2.7 (rxProcessFrame) as understood from the
//! standard. Rules marked `verify` must be checked against the text.

use crate::error::{DecodeError, EncodeError};
use crate::org::OrgTlv;
use crate::tlv::{RawTlv, TlvIter, tlv_type, write_tlv};
use crate::types::{ChassisId, MAX_STRING_LEN, ManagementAddress, PortId, SystemCapabilities};

/// A decoded TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tlv {
    /// Port Description (type 4).
    PortDescription(Vec<u8>),
    /// System Name (type 5).
    SystemName(Vec<u8>),
    /// System Description (type 6).
    SystemDescription(Vec<u8>),
    /// System Capabilities (type 7).
    SystemCapabilities(SystemCapabilities),
    /// Management Address (type 8). May appear more than once.
    ManagementAddress(ManagementAddress),
    /// Organizationally Specific (type 127). May appear more than once.
    Organizational(OrgTlv),
    /// A TLV with a type this crate does not know (9 to 126). Preserved
    /// verbatim.
    Unknown {
        /// TLV type.
        tlv_type: u8,
        /// Value octets.
        value: Vec<u8>,
    },
}

impl Tlv {
    /// The wire type code.
    pub const fn tlv_type(&self) -> u8 {
        match self {
            Self::PortDescription(_) => tlv_type::PORT_DESCRIPTION,
            Self::SystemName(_) => tlv_type::SYSTEM_NAME,
            Self::SystemDescription(_) => tlv_type::SYSTEM_DESCRIPTION,
            Self::SystemCapabilities(_) => tlv_type::SYSTEM_CAPABILITIES,
            Self::ManagementAddress(_) => tlv_type::MANAGEMENT_ADDRESS,
            Self::Organizational(_) => tlv_type::ORGANIZATIONAL,
            Self::Unknown { tlv_type, .. } => *tlv_type,
        }
    }
}

/// A decoded LLDPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldpdu {
    /// Chassis ID (mandatory, first).
    pub chassis_id: ChassisId,
    /// Port ID (mandatory, second).
    pub port_id: PortId,
    /// Time To Live in seconds (mandatory, third). Zero means shutdown.
    pub ttl: u16,
    /// Optional TLVs in wire order.
    pub optional: Vec<Tlv>,
}

/// Non-fatal observations made while decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeWarning {
    /// No End of LLDPDU TLV was found before the data ran out. The LLDPDU
    /// was accepted (`verify`: 802.1AB-2016 receive rules).
    MissingEndTlv,
    /// The End TLV had a nonzero length. Processing stopped there.
    EndTlvNonZeroLength {
        /// Length found.
        len: usize,
    },
    /// Octets followed the End TLV. Usually Ethernet padding; ignored.
    TrailingData {
        /// Number of octets ignored.
        len: usize,
    },
    /// An optional TLV that may appear at most once appeared again. The
    /// first instance was kept, this one discarded.
    DuplicateOptionalTlv {
        /// TLV type.
        tlv_type: u8,
        /// Offset of the discarded TLV.
        offset: usize,
    },
    /// A known optional TLV had an invalid length or content and was
    /// discarded.
    InvalidOptionalTlv {
        /// TLV type.
        tlv_type: u8,
        /// Offset.
        offset: usize,
        /// Length found.
        len: usize,
    },
    /// A TLV of unknown type (9 to 126) was preserved but not interpreted.
    UnrecognizedTlv {
        /// TLV type.
        tlv_type: u8,
        /// Offset.
        offset: usize,
    },
}

/// Counters and warnings from one decode, for the 802.1AB statistics group.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodeReport {
    /// Non-fatal observations.
    pub warnings: Vec<DecodeWarning>,
    /// TLVs of unrecognized type (feeds `lldpStatsRxPortTLVsUnrecognizedTotal`).
    pub tlvs_unrecognized: u32,
    /// TLVs discarded for invalid content (feeds `lldpStatsRxPortTLVsDiscardedTotal`).
    pub tlvs_discarded: u32,
}

/// Result of a successful decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The LLDPDU.
    pub lldpdu: Lldpdu,
    /// Diagnostics.
    pub report: DecodeReport,
}

impl Lldpdu {
    /// Creates an LLDPDU with the mandatory TLVs and no optional TLVs.
    pub const fn new(chassis_id: ChassisId, port_id: PortId, ttl: u16) -> Self {
        Self {
            chassis_id,
            port_id,
            ttl,
            optional: Vec::new(),
        }
    }

    /// Decodes an LLDPDU (the Ethernet payload, not the whole frame).
    ///
    /// Errors indicate the frame must be discarded and counted as a frame
    /// error. Warnings in the report indicate TLV-level issues that did not
    /// invalidate the LLDPDU.
    pub fn decode(data: &[u8]) -> Result<Decoded, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::Empty);
        }
        if data.len() > crate::MAX_LLDPDU_LEN {
            return Err(DecodeError::LldpduTooLarge { len: data.len() });
        }
        let mut iter = TlvIter::new(data);

        let chassis = expect_mandatory(&mut iter, 0, tlv_type::CHASSIS_ID)?;
        let chassis_id = ChassisId::parse(chassis.value)?;
        let port = expect_mandatory(&mut iter, 1, tlv_type::PORT_ID)?;
        let port_id = PortId::parse(port.value)?;
        let ttl_tlv = expect_mandatory(&mut iter, 2, tlv_type::TTL)?;
        let ttl = parse_ttl(ttl_tlv.value)?;

        let mut lldpdu = Self::new(chassis_id, port_id, ttl);
        let mut report = DecodeReport::default();
        let mut seen_end = false;
        let mut seen_once = [false; 4]; // types 4, 5, 6, 7

        for item in iter.by_ref() {
            let tlv = item?;
            match tlv.tlv_type {
                tlv_type::END => {
                    if !tlv.value.is_empty() {
                        report.warnings.push(DecodeWarning::EndTlvNonZeroLength {
                            len: tlv.value.len(),
                        });
                    }
                    seen_end = true;
                    break;
                }
                tlv_type::CHASSIS_ID | tlv_type::PORT_ID | tlv_type::TTL => {
                    return Err(DecodeError::DuplicateMandatoryTlv {
                        tlv_type: tlv.tlv_type,
                    });
                }
                tlv_type::PORT_DESCRIPTION
                | tlv_type::SYSTEM_NAME
                | tlv_type::SYSTEM_DESCRIPTION => {
                    let slot = usize::from(tlv.tlv_type.saturating_sub(tlv_type::PORT_DESCRIPTION));
                    if tlv.value.len() > MAX_STRING_LEN {
                        discard_invalid(&mut report, &tlv);
                    } else if seen_once.get(slot).copied().unwrap_or(false) {
                        discard_duplicate(&mut report, &tlv);
                    } else {
                        if let Some(s) = seen_once.get_mut(slot) {
                            *s = true;
                        }
                        lldpdu.optional.push(match tlv.tlv_type {
                            tlv_type::PORT_DESCRIPTION => Tlv::PortDescription(tlv.value.to_vec()),
                            tlv_type::SYSTEM_NAME => Tlv::SystemName(tlv.value.to_vec()),
                            _ => Tlv::SystemDescription(tlv.value.to_vec()),
                        });
                    }
                }
                tlv_type::SYSTEM_CAPABILITIES => match SystemCapabilities::parse(tlv.value) {
                    Some(caps) if !seen_once[3] => {
                        seen_once[3] = true;
                        lldpdu.optional.push(Tlv::SystemCapabilities(caps));
                    }
                    Some(_) => discard_duplicate(&mut report, &tlv),
                    None => discard_invalid(&mut report, &tlv),
                },
                tlv_type::MANAGEMENT_ADDRESS => match ManagementAddress::parse(tlv.value) {
                    Some(addr) => lldpdu.optional.push(Tlv::ManagementAddress(addr)),
                    None => discard_invalid(&mut report, &tlv),
                },
                tlv_type::ORGANIZATIONAL => match OrgTlv::parse(tlv.value) {
                    Some(org) => lldpdu.optional.push(Tlv::Organizational(org)),
                    None => discard_invalid(&mut report, &tlv),
                },
                other => {
                    report.tlvs_unrecognized = report.tlvs_unrecognized.saturating_add(1);
                    report.warnings.push(DecodeWarning::UnrecognizedTlv {
                        tlv_type: other,
                        offset: tlv.offset,
                    });
                    lldpdu.optional.push(Tlv::Unknown {
                        tlv_type: other,
                        value: tlv.value.to_vec(),
                    });
                }
            }
        }

        if seen_end {
            let trailing = data.len().saturating_sub(iter.offset());
            if trailing > 0 {
                report
                    .warnings
                    .push(DecodeWarning::TrailingData { len: trailing });
            }
        } else {
            report.warnings.push(DecodeWarning::MissingEndTlv);
        }

        Ok(Decoded { lldpdu, report })
    }

    /// Encodes the LLDPDU, including the End TLV. Fails if the result would
    /// exceed `limit` octets.
    pub fn encode(&self, limit: usize) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(256);
        let mut scratch = Vec::with_capacity(256);

        self.chassis_id.write(&mut scratch)?;
        write_tlv(&mut out, tlv_type::CHASSIS_ID, &scratch)?;
        scratch.clear();

        self.port_id.write(&mut scratch)?;
        write_tlv(&mut out, tlv_type::PORT_ID, &scratch)?;
        scratch.clear();

        write_tlv(&mut out, tlv_type::TTL, &self.ttl.to_be_bytes())?;

        for tlv in &self.optional {
            scratch.clear();
            match tlv {
                Tlv::PortDescription(s) | Tlv::SystemName(s) | Tlv::SystemDescription(s) => {
                    if s.len() > MAX_STRING_LEN {
                        return Err(EncodeError::ValueTooLong {
                            tlv_type: tlv.tlv_type(),
                            len: s.len(),
                        });
                    }
                    scratch.extend_from_slice(s);
                }
                Tlv::SystemCapabilities(c) => c.write(&mut scratch),
                Tlv::ManagementAddress(m) => m.write(&mut scratch)?,
                Tlv::Organizational(o) => o.write(&mut scratch)?,
                Tlv::Unknown { value, .. } => scratch.extend_from_slice(value),
            }
            write_tlv(&mut out, tlv.tlv_type(), &scratch)?;
        }

        write_tlv(&mut out, tlv_type::END, &[])?;

        if out.len() > limit {
            return Err(EncodeError::LldpduTooLarge {
                len: out.len(),
                limit,
            });
        }
        Ok(out)
    }

    /// First System Name TLV, if any.
    pub fn system_name(&self) -> Option<&[u8]> {
        self.optional.iter().find_map(|t| match t {
            Tlv::SystemName(s) => Some(s.as_slice()),
            _ => None,
        })
    }

    /// First System Description TLV, if any.
    pub fn system_description(&self) -> Option<&[u8]> {
        self.optional.iter().find_map(|t| match t {
            Tlv::SystemDescription(s) => Some(s.as_slice()),
            _ => None,
        })
    }

    /// First Port Description TLV, if any.
    pub fn port_description(&self) -> Option<&[u8]> {
        self.optional.iter().find_map(|t| match t {
            Tlv::PortDescription(s) => Some(s.as_slice()),
            _ => None,
        })
    }

    /// System Capabilities TLV, if any.
    pub fn system_capabilities(&self) -> Option<SystemCapabilities> {
        self.optional.iter().find_map(|t| match t {
            Tlv::SystemCapabilities(c) => Some(*c),
            _ => None,
        })
    }

    /// All Management Address TLVs in wire order.
    pub fn management_addresses(&self) -> impl Iterator<Item = &ManagementAddress> {
        self.optional.iter().filter_map(|t| match t {
            Tlv::ManagementAddress(m) => Some(m),
            _ => None,
        })
    }

    /// All organizationally specific TLVs in wire order.
    pub fn organizational(&self) -> impl Iterator<Item = &OrgTlv> {
        self.optional.iter().filter_map(|t| match t {
            Tlv::Organizational(o) => Some(o),
            _ => None,
        })
    }
}

fn expect_mandatory<'a>(
    iter: &mut TlvIter<'a>,
    position: u8,
    expected: u8,
) -> Result<RawTlv<'a>, DecodeError> {
    match iter.next() {
        None => Err(DecodeError::MissingMandatoryTlv { expected }),
        Some(Err(e)) => Err(e),
        Some(Ok(tlv)) if tlv.tlv_type == expected => Ok(tlv),
        Some(Ok(tlv)) if tlv.tlv_type == tlv_type::END => {
            Err(DecodeError::MissingMandatoryTlv { expected })
        }
        Some(Ok(tlv)) => Err(DecodeError::MandatoryTlvOrder {
            position,
            found: tlv.tlv_type,
        }),
    }
}

fn parse_ttl(value: &[u8]) -> Result<u16, DecodeError> {
    let bytes: [u8; 2] = value
        .try_into()
        .map_err(|_| DecodeError::InvalidMandatoryTlvLength {
            tlv_type: tlv_type::TTL,
            len: value.len(),
        })?;
    Ok(u16::from_be_bytes(bytes))
}

fn discard_invalid(report: &mut DecodeReport, tlv: &RawTlv<'_>) {
    report.tlvs_discarded = report.tlvs_discarded.saturating_add(1);
    report.warnings.push(DecodeWarning::InvalidOptionalTlv {
        tlv_type: tlv.tlv_type,
        offset: tlv.offset,
        len: tlv.value.len(),
    });
}

fn discard_duplicate(report: &mut DecodeReport, tlv: &RawTlv<'_>) {
    report.tlvs_discarded = report.tlvs_discarded.saturating_add(1);
    report.warnings.push(DecodeWarning::DuplicateOptionalTlv {
        tlv_type: tlv.tlv_type,
        offset: tlv.offset,
    });
}
