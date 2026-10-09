//! LLDP-MED TLVs (ANSI/TIA-1057, OUI 00-12-BB). Layouts follow TIA-1057
//! clause 10.2 and must be verified against that text.

use super::{OrgTlv, oui, u16_at};

/// Longest inventory string (TIA-1057 10.2.6, 0 to 32 octets).
pub const MAX_INVENTORY_LEN: usize = 32;

/// LLDP-MED device type (10.2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MedDeviceType {
    /// Type not defined.
    NotDefined,
    /// Endpoint class I (generic).
    EndpointClass1,
    /// Endpoint class II (media).
    EndpointClass2,
    /// Endpoint class III (communication device).
    EndpointClass3,
    /// Network connectivity device (switch).
    NetworkConnectivity,
    /// Reserved value.
    Reserved(u8),
}

impl MedDeviceType {
    /// Decodes the octet.
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NotDefined,
            1 => Self::EndpointClass1,
            2 => Self::EndpointClass2,
            3 => Self::EndpointClass3,
            4 => Self::NetworkConnectivity,
            other => Self::Reserved(other),
        }
    }

    /// Encodes the octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::NotDefined => 0,
            Self::EndpointClass1 => 1,
            Self::EndpointClass2 => 2,
            Self::EndpointClass3 => 3,
            Self::NetworkConnectivity => 4,
            Self::Reserved(v) => v,
        }
    }
}

/// LLDP-MED capability bits (10.2.2.1).
pub mod capability {
    /// LLDP-MED Capabilities TLV.
    pub const CAPABILITIES: u16 = 1 << 0;
    /// Network Policy TLV.
    pub const NETWORK_POLICY: u16 = 1 << 1;
    /// Location Identification TLV.
    pub const LOCATION: u16 = 1 << 2;
    /// Extended Power via MDI, PSE.
    pub const EXTENDED_POWER_PSE: u16 = 1 << 3;
    /// Extended Power via MDI, PD.
    pub const EXTENDED_POWER_PD: u16 = 1 << 4;
    /// Inventory TLVs.
    pub const INVENTORY: u16 = 1 << 5;
}

/// Location data format (10.2.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MedLocation {
    /// Coordinate-based LCI (RFC 3825 / 6225), 16 octets, kept raw.
    Coordinate(Vec<u8>),
    /// Civic address LCI (RFC 4776), kept raw.
    Civic(Vec<u8>),
    /// ECS ELIN, 10 to 25 numeric characters.
    Elin(Vec<u8>),
    /// Reserved format.
    Other {
        /// Format octet.
        format: u8,
        /// Raw data.
        data: Vec<u8>,
    },
}

/// Decoded LLDP-MED TLV.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MedTlv {
    /// Capabilities (subtype 1).
    Capabilities {
        /// Bitmap of [`capability`] values.
        capabilities: u16,
        /// Device type.
        device_type: MedDeviceType,
    },
    /// Network Policy (subtype 2).
    NetworkPolicy {
        /// Application type: 1 voice, 2 voice signaling, 3 guest voice,
        /// 4 guest voice signaling, 5 softphone voice, 6 video conferencing,
        /// 7 streaming video, 8 video signaling.
        application_type: u8,
        /// Policy unknown (U bit): the endpoint should use its own policy.
        unknown: bool,
        /// Tagged (T bit).
        tagged: bool,
        /// VLAN ID (12 bits).
        vlan_id: u16,
        /// Layer 2 priority (3 bits).
        l2_priority: u8,
        /// DSCP value (6 bits).
        dscp: u8,
    },
    /// Location Identification (subtype 3).
    Location(MedLocation),
    /// Extended Power via MDI (subtype 4).
    ExtendedPower {
        /// 0 = PSE, 1 = PD.
        power_type: u8,
        /// Power source.
        power_source: u8,
        /// Power priority: 1 critical, 2 high, 3 low.
        power_priority: u8,
        /// Power in units of 0.1 W.
        power_value: u16,
    },
    /// Hardware Revision (subtype 5).
    HardwareRevision(Vec<u8>),
    /// Firmware Revision (subtype 6).
    FirmwareRevision(Vec<u8>),
    /// Software Revision (subtype 7).
    SoftwareRevision(Vec<u8>),
    /// Serial Number (subtype 8).
    SerialNumber(Vec<u8>),
    /// Manufacturer Name (subtype 9).
    ManufacturerName(Vec<u8>),
    /// Model Name (subtype 10).
    ModelName(Vec<u8>),
    /// Asset ID (subtype 11).
    AssetId(Vec<u8>),
}

impl MedTlv {
    /// Decodes an LLDP-MED TLV from its subtype and data.
    pub fn decode(subtype: u8, data: &[u8]) -> Option<Self> {
        let inventory = |d: &[u8]| (d.len() <= MAX_INVENTORY_LEN).then(|| d.to_vec());
        Some(match subtype {
            1 => {
                if data.len() != 3 {
                    return None;
                }
                Self::Capabilities {
                    capabilities: u16_at(data, 0)?,
                    device_type: MedDeviceType::from_u8(*data.get(2)?),
                }
            }
            2 => {
                if data.len() != 4 {
                    return None;
                }
                let application_type = *data.first()?;
                let b1 = *data.get(1)?;
                let b2 = *data.get(2)?;
                let b3 = *data.get(3)?;
                // Layout: U T X | VLAN ID (12) | L2 priority (3) | DSCP (6)
                let vlan_id = (u16::from(b1 & 0x1F) << 7) | u16::from(b2 >> 1);
                let l2_priority = ((b2 & 0x01) << 2) | (b3 >> 6);
                Self::NetworkPolicy {
                    application_type,
                    unknown: b1 & 0x80 != 0,
                    tagged: b1 & 0x40 != 0,
                    vlan_id,
                    l2_priority,
                    dscp: b3 & 0x3F,
                }
            }
            3 => {
                let (&format, rest) = data.split_first()?;
                Self::Location(match format {
                    1 => MedLocation::Coordinate(rest.to_vec()),
                    2 => MedLocation::Civic(rest.to_vec()),
                    3 => MedLocation::Elin(rest.to_vec()),
                    other => MedLocation::Other {
                        format: other,
                        data: rest.to_vec(),
                    },
                })
            }
            4 => {
                if data.len() != 3 {
                    return None;
                }
                let tsp = *data.first()?;
                Self::ExtendedPower {
                    power_type: tsp >> 6,
                    power_source: (tsp >> 4) & 0x03,
                    power_priority: tsp & 0x0F,
                    power_value: u16_at(data, 1)?,
                }
            }
            5 => Self::HardwareRevision(inventory(data)?),
            6 => Self::FirmwareRevision(inventory(data)?),
            7 => Self::SoftwareRevision(inventory(data)?),
            8 => Self::SerialNumber(inventory(data)?),
            9 => Self::ManufacturerName(inventory(data)?),
            10 => Self::ModelName(inventory(data)?),
            11 => Self::AssetId(inventory(data)?),
            _ => return None,
        })
    }

    /// The subtype octet.
    pub const fn subtype(&self) -> u8 {
        match self {
            Self::Capabilities { .. } => 1,
            Self::NetworkPolicy { .. } => 2,
            Self::Location(_) => 3,
            Self::ExtendedPower { .. } => 4,
            Self::HardwareRevision(_) => 5,
            Self::FirmwareRevision(_) => 6,
            Self::SoftwareRevision(_) => 7,
            Self::SerialNumber(_) => 8,
            Self::ManufacturerName(_) => 9,
            Self::ModelName(_) => 10,
            Self::AssetId(_) => 11,
        }
    }

    /// Encodes to a raw organizational TLV. Returns `None` if an inventory
    /// string exceeds 32 octets or a bit field is out of range.
    pub fn to_org_tlv(&self) -> Option<OrgTlv> {
        let mut data = Vec::with_capacity(8);
        match self {
            Self::Capabilities {
                capabilities,
                device_type,
            } => {
                data.extend_from_slice(&capabilities.to_be_bytes());
                data.push(device_type.as_u8());
            }
            Self::NetworkPolicy {
                application_type,
                unknown,
                tagged,
                vlan_id,
                l2_priority,
                dscp,
            } => {
                if *vlan_id > 0x0FFF || *l2_priority > 7 || *dscp > 63 {
                    return None;
                }
                data.push(*application_type);
                let b1 = (u8::from(*unknown) << 7)
                    | (u8::from(*tagged) << 6)
                    | u8::try_from(vlan_id >> 7).ok()?;
                let b2 = u8::try_from((vlan_id & 0x7F) << 1).ok()? | (l2_priority >> 2);
                let b3 = ((l2_priority & 0x03) << 6) | dscp;
                data.extend_from_slice(&[b1, b2, b3]);
            }
            Self::Location(loc) => match loc {
                MedLocation::Coordinate(d) => {
                    data.push(1);
                    data.extend_from_slice(d);
                }
                MedLocation::Civic(d) => {
                    data.push(2);
                    data.extend_from_slice(d);
                }
                MedLocation::Elin(d) => {
                    data.push(3);
                    data.extend_from_slice(d);
                }
                MedLocation::Other { format, data: d } => {
                    data.push(*format);
                    data.extend_from_slice(d);
                }
            },
            Self::ExtendedPower {
                power_type,
                power_source,
                power_priority,
                power_value,
            } => {
                if *power_type > 3 || *power_source > 3 || *power_priority > 15 {
                    return None;
                }
                data.push((power_type << 6) | (power_source << 4) | power_priority);
                data.extend_from_slice(&power_value.to_be_bytes());
            }
            Self::HardwareRevision(s)
            | Self::FirmwareRevision(s)
            | Self::SoftwareRevision(s)
            | Self::SerialNumber(s)
            | Self::ManufacturerName(s)
            | Self::ModelName(s)
            | Self::AssetId(s) => {
                if s.len() > MAX_INVENTORY_LEN {
                    return None;
                }
                data.extend_from_slice(s);
            }
        }
        Some(OrgTlv {
            oui: oui::TIA_MED,
            subtype: self.subtype(),
            data,
        })
    }
}
