//! IEEE 802.1 organizationally specific TLVs (IEEE 802.1Q Annex D,
//! OUI 00-80-C2). Subtype numbers are taken from the IEEE 802.1
//! assigned-numbers list and must be verified against the current
//! 802.1Q text.

use super::{OrgTlv, oui, u16_at, u32_at};

/// Longest VLAN name (D.2.3, 0 to 32 octets).
pub const MAX_VLAN_NAME_LEN: usize = 32;
/// Longest protocol identity (D.2.4, 1 to 255 octets).
pub const MAX_PROTOCOL_IDENTITY_LEN: usize = 255;

/// Decoded IEEE 802.1 TLV.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Ieee8021Tlv {
    /// Port VLAN ID (subtype 1). Zero means the port is not VLAN-aware or
    /// has no PVID.
    PortVlanId(u16),
    /// Port and Protocol VLAN ID (subtype 2).
    PortAndProtocolVlanId {
        /// Port and protocol VLAN supported.
        supported: bool,
        /// Port and protocol VLAN enabled.
        enabled: bool,
        /// PPVID, or zero if not supported.
        ppvid: u16,
    },
    /// VLAN Name (subtype 3).
    VlanName {
        /// VLAN ID (1 to 4094).
        vid: u16,
        /// Name, 0 to 32 octets.
        name: Vec<u8>,
    },
    /// Protocol Identity (subtype 4).
    ProtocolIdentity(Vec<u8>),
    /// VID Usage Digest (subtype 5).
    VidUsageDigest(u32),
    /// Management VID (subtype 6).
    ManagementVid(u16),
    /// Link Aggregation (subtype 7).
    LinkAggregation(LinkAggregation),
}

/// Link aggregation status, shared with the deprecated 802.3 subtype 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkAggregation {
    /// The port can be aggregated.
    pub capable: bool,
    /// The port is currently in an aggregation.
    pub aggregated: bool,
    /// Aggregated port identifier (ifIndex of the aggregator), or zero.
    pub aggregated_port_id: u32,
}

impl LinkAggregation {
    /// Parses the 5-octet form.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 5 {
            return None;
        }
        let status = *data.first()?;
        Some(Self {
            capable: status & 0x01 != 0,
            aggregated: status & 0x02 != 0,
            aggregated_port_id: u32_at(data, 1)?,
        })
    }

    /// Serializes the 5-octet form.
    pub fn write(self, out: &mut Vec<u8>) {
        let status = u8::from(self.capable) | (u8::from(self.aggregated) << 1);
        out.push(status);
        out.extend_from_slice(&self.aggregated_port_id.to_be_bytes());
    }
}

impl Ieee8021Tlv {
    /// Decodes an 802.1 TLV from its subtype and data. Returns `None` for
    /// unknown subtypes or malformed data.
    pub fn decode(subtype: u8, data: &[u8]) -> Option<Self> {
        Some(match subtype {
            1 => Self::PortVlanId(exact_u16(data)?),
            2 => {
                if data.len() != 3 {
                    return None;
                }
                let flags = *data.first()?;
                Self::PortAndProtocolVlanId {
                    supported: flags & 0x02 != 0,
                    enabled: flags & 0x04 != 0,
                    ppvid: u16_at(data, 1)?,
                }
            }
            3 => {
                let vid = u16_at(data, 0)?;
                let len = usize::from(*data.get(2)?);
                let name = data.get(3..)?;
                if len > MAX_VLAN_NAME_LEN || name.len() != len {
                    return None;
                }
                Self::VlanName {
                    vid,
                    name: name.to_vec(),
                }
            }
            4 => {
                let len = usize::from(*data.first()?);
                let id = data.get(1..)?;
                if len == 0 || id.len() != len {
                    return None;
                }
                Self::ProtocolIdentity(id.to_vec())
            }
            5 => {
                if data.len() != 4 {
                    return None;
                }
                Self::VidUsageDigest(u32_at(data, 0)?)
            }
            6 => Self::ManagementVid(exact_u16(data)?),
            7 => Self::LinkAggregation(LinkAggregation::parse(data)?),
            _ => return None,
        })
    }

    /// The subtype octet.
    pub const fn subtype(&self) -> u8 {
        match self {
            Self::PortVlanId(_) => 1,
            Self::PortAndProtocolVlanId { .. } => 2,
            Self::VlanName { .. } => 3,
            Self::ProtocolIdentity(_) => 4,
            Self::VidUsageDigest(_) => 5,
            Self::ManagementVid(_) => 6,
            Self::LinkAggregation(_) => 7,
        }
    }

    /// Encodes to a raw organizational TLV. Returns `None` if a field is
    /// out of range (VLAN name over 32 octets, empty or overlong protocol
    /// identity).
    pub fn to_org_tlv(&self) -> Option<OrgTlv> {
        let mut data = Vec::with_capacity(8);
        match self {
            Self::PortVlanId(v) | Self::ManagementVid(v) => {
                data.extend_from_slice(&v.to_be_bytes());
            }
            Self::PortAndProtocolVlanId {
                supported,
                enabled,
                ppvid,
            } => {
                data.push((u8::from(*supported) << 1) | (u8::from(*enabled) << 2));
                data.extend_from_slice(&ppvid.to_be_bytes());
            }
            Self::VlanName { vid, name } => {
                if name.len() > MAX_VLAN_NAME_LEN {
                    return None;
                }
                data.extend_from_slice(&vid.to_be_bytes());
                data.push(u8::try_from(name.len()).ok()?);
                data.extend_from_slice(name);
            }
            Self::ProtocolIdentity(id) => {
                if id.is_empty() || id.len() > MAX_PROTOCOL_IDENTITY_LEN {
                    return None;
                }
                data.push(u8::try_from(id.len()).ok()?);
                data.extend_from_slice(id);
            }
            Self::VidUsageDigest(d) => data.extend_from_slice(&d.to_be_bytes()),
            Self::LinkAggregation(la) => la.write(&mut data),
        }
        Some(OrgTlv {
            oui: oui::IEEE_802_1,
            subtype: self.subtype(),
            data,
        })
    }
}

fn exact_u16(data: &[u8]) -> Option<u16> {
    (data.len() == 2).then(|| u16_at(data, 0)).flatten()
}
