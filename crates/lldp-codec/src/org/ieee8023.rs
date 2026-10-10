//! IEEE 802.3 organizationally specific TLVs (OUI 00-12-0F). Subtypes and
//! field layouts were checked against IEEE Std 802.3-2022 Clause 79.
//! Subtypes 6 (EEE fast wake), 7 (Additional Ethernet Capabilities), and
//! 8 (Power via MDI Measurements) are not decoded and are shown raw.

use super::ieee8021::LinkAggregation;
use super::{OrgTlv, oui, u16_at};

/// Decoded IEEE 802.3 TLV.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Ieee8023Tlv {
    /// MAC/PHY Configuration/Status (subtype 1).
    MacPhyConfigStatus(MacPhyConfigStatus),
    /// Power via MDI (subtype 2).
    PowerViaMdi(PowerViaMdi),
    /// Link Aggregation (subtype 3). Deprecated in favor of the IEEE 802.1
    /// subtype 7 TLV but still transmitted by much equipment.
    LinkAggregation(LinkAggregation),
    /// Maximum Frame Size (subtype 4).
    MaximumFrameSize(u16),
    /// Energy-Efficient Ethernet (subtype 5). Values in microseconds.
    Eee {
        /// Transmit Tw_sys_tx.
        transmit_tw: u16,
        /// Receive Tw_sys_rx.
        receive_tw: u16,
        /// Fallback receive Tw_sys.
        fallback_tw: u16,
        /// Echo transmit Tw.
        echo_transmit_tw: u16,
        /// Echo receive Tw.
        echo_receive_tw: u16,
    },
}

/// MAC/PHY Configuration/Status fields (79.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacPhyConfigStatus {
    /// Auto-negotiation is supported.
    pub autoneg_supported: bool,
    /// Auto-negotiation is enabled.
    pub autoneg_enabled: bool,
    /// PMD auto-negotiation advertised capability bitmap (ifMauAutoNegCapAdvertisedBits).
    pub pmd_autoneg_advertised: u16,
    /// Operational MAU type (IANA-maintained ifMauTypeList values).
    pub operational_mau_type: u16,
}

impl MacPhyConfigStatus {
    /// Parses the 5-octet value.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 5 {
            return None;
        }
        let flags = *data.first()?;
        Some(Self {
            autoneg_supported: flags & 0x01 != 0,
            autoneg_enabled: flags & 0x02 != 0,
            pmd_autoneg_advertised: u16_at(data, 1)?,
            operational_mau_type: u16_at(data, 3)?,
        })
    }

    /// Serializes the 5-octet value.
    pub fn write(self, out: &mut Vec<u8>) {
        out.push(u8::from(self.autoneg_supported) | (u8::from(self.autoneg_enabled) << 1));
        out.extend_from_slice(&self.pmd_autoneg_advertised.to_be_bytes());
        out.extend_from_slice(&self.operational_mau_type.to_be_bytes());
    }
}

/// Power via MDI fields (79.3.2). The three basic fields are always
/// present. The DLL classification extension (802.3at) adds five octets,
/// and the Type 3 and Type 4 extension (802.3bt) seventeen more, which are
/// kept raw in `extension`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[allow(clippy::struct_excessive_bools)] // mirrors the wire bit field
pub struct PowerViaMdi {
    /// Port class is PSE (bit 0 of MDI power support).
    pub port_class_pse: bool,
    /// PSE MDI power is supported.
    pub pse_mdi_power_supported: bool,
    /// PSE MDI power is enabled.
    pub pse_mdi_power_enabled: bool,
    /// PSE pairs can be controlled.
    pub pse_pairs_controllable: bool,
    /// PSE power pair: 1 = signal, 2 = spare.
    pub pse_power_pair: u8,
    /// Power class: 1 = class 0 ... 5 = class 4.
    pub power_class: u8,
    /// 802.3at DLL classification fields, if present.
    pub dll: Option<PowerDll>,
    /// Octets after the fields this crate interprets (802.3bt and later).
    pub extension: Vec<u8>,
}

/// 802.3at DLL classification fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PowerDll {
    /// Power type: 0 = type 2 PSE, 1 = type 2 PD, 2 = type 1 PSE, 3 = type 1 PD.
    pub power_type: u8,
    /// Power source (meaning depends on type).
    pub power_source: u8,
    /// Power priority: 0 = unknown, 1 = critical, 2 = high, 3 = low.
    pub power_priority: u8,
    /// PD 4PID: the PD supports powering of both Modes simultaneously.
    pub pd_4pid: bool,
    /// PD requested power in units of 0.1 W.
    pub pd_requested_power: u16,
    /// PSE allocated power in units of 0.1 W.
    pub pse_allocated_power: u16,
}

impl PowerViaMdi {
    /// Parses a value of 3 or more octets.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let support = *data.first()?;
        let pair = *data.get(1)?;
        let class = *data.get(2)?;
        let mut rest = data.get(3..)?;
        let dll = if rest.len() >= 5 {
            let tsp = *rest.first()?;
            let d = PowerDll {
                power_type: tsp >> 6,
                power_source: (tsp >> 4) & 0x03,
                power_priority: tsp & 0x03,
                pd_4pid: tsp & 0x04 != 0,
                pd_requested_power: u16_at(rest, 1)?,
                pse_allocated_power: u16_at(rest, 3)?,
            };
            rest = rest.get(5..)?;
            Some(d)
        } else if rest.is_empty() {
            None
        } else {
            return None;
        };
        Some(Self {
            port_class_pse: support & 0x01 != 0,
            pse_mdi_power_supported: support & 0x02 != 0,
            pse_mdi_power_enabled: support & 0x04 != 0,
            pse_pairs_controllable: support & 0x08 != 0,
            pse_power_pair: pair,
            power_class: class,
            dll,
            extension: rest.to_vec(),
        })
    }

    /// Serializes the value.
    pub fn write(&self, out: &mut Vec<u8>) {
        let support = u8::from(self.port_class_pse)
            | (u8::from(self.pse_mdi_power_supported) << 1)
            | (u8::from(self.pse_mdi_power_enabled) << 2)
            | (u8::from(self.pse_pairs_controllable) << 3);
        out.push(support);
        out.push(self.pse_power_pair);
        out.push(self.power_class);
        if let Some(d) = self.dll {
            out.push(
                (d.power_type << 6)
                    | ((d.power_source & 0x03) << 4)
                    | (u8::from(d.pd_4pid) << 2)
                    | (d.power_priority & 0x03),
            );
            out.extend_from_slice(&d.pd_requested_power.to_be_bytes());
            out.extend_from_slice(&d.pse_allocated_power.to_be_bytes());
            out.extend_from_slice(&self.extension);
        }
    }
}

impl Ieee8023Tlv {
    /// Decodes an 802.3 TLV from its subtype and data.
    pub fn decode(subtype: u8, data: &[u8]) -> Option<Self> {
        Some(match subtype {
            1 => Self::MacPhyConfigStatus(MacPhyConfigStatus::parse(data)?),
            2 => Self::PowerViaMdi(PowerViaMdi::parse(data)?),
            3 => Self::LinkAggregation(LinkAggregation::parse(data)?),
            4 => {
                if data.len() != 2 {
                    return None;
                }
                Self::MaximumFrameSize(u16_at(data, 0)?)
            }
            5 => {
                if data.len() != 10 {
                    return None;
                }
                Self::Eee {
                    transmit_tw: u16_at(data, 0)?,
                    receive_tw: u16_at(data, 2)?,
                    fallback_tw: u16_at(data, 4)?,
                    echo_transmit_tw: u16_at(data, 6)?,
                    echo_receive_tw: u16_at(data, 8)?,
                }
            }
            _ => return None,
        })
    }

    /// The subtype octet.
    pub const fn subtype(&self) -> u8 {
        match self {
            Self::MacPhyConfigStatus(_) => 1,
            Self::PowerViaMdi(_) => 2,
            Self::LinkAggregation(_) => 3,
            Self::MaximumFrameSize(_) => 4,
            Self::Eee { .. } => 5,
        }
    }

    /// Encodes to a raw organizational TLV.
    pub fn to_org_tlv(&self) -> OrgTlv {
        let mut data = Vec::with_capacity(12);
        match self {
            Self::MacPhyConfigStatus(m) => m.write(&mut data),
            Self::PowerViaMdi(p) => p.write(&mut data),
            Self::LinkAggregation(la) => la.write(&mut data),
            Self::MaximumFrameSize(s) => data.extend_from_slice(&s.to_be_bytes()),
            Self::Eee {
                transmit_tw,
                receive_tw,
                fallback_tw,
                echo_transmit_tw,
                echo_receive_tw,
            } => {
                for v in [
                    transmit_tw,
                    receive_tw,
                    fallback_tw,
                    echo_transmit_tw,
                    echo_receive_tw,
                ] {
                    data.extend_from_slice(&v.to_be_bytes());
                }
            }
        }
        OrgTlv {
            oui: oui::IEEE_802_3,
            subtype: self.subtype(),
            data,
        }
    }
}
