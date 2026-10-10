//! JSON-facing views of engine types. These are the public shapes the CLI
//! and PowerShell module consume; changing them is a protocol change.

use lldp_codec::org::DecodedOrgTlv;
use lldp_codec::org::ieee8021::Ieee8021Tlv;
use lldp_codec::org::ieee8023::Ieee8023Tlv;
use lldp_codec::org::med::{MedLocation, MedTlv};
use lldp_codec::types::lossy_text;
use lldp_codec::{Capability, Lldpdu, ManagementAddress, OrgTlv, Tlv};
use lldp_core::{AdminStatus, Neighbor, PortStats};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Interface administrative mode on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceModeView {
    /// Neither.
    Disabled,
    /// Receive only.
    RxOnly,
    /// Transmit only.
    TxOnly,
    /// Both.
    RxTx,
}

impl From<AdminStatus> for InterfaceModeView {
    fn from(a: AdminStatus) -> Self {
        match a {
            AdminStatus::Disabled => Self::Disabled,
            AdminStatus::RxOnly => Self::RxOnly,
            AdminStatus::TxOnly => Self::TxOnly,
            AdminStatus::RxTx => Self::RxTx,
        }
    }
}

impl From<InterfaceModeView> for AdminStatus {
    fn from(m: InterfaceModeView) -> Self {
        match m {
            InterfaceModeView::Disabled => Self::Disabled,
            InterfaceModeView::RxOnly => Self::RxOnly,
            InterfaceModeView::TxOnly => Self::TxOnly,
            InterfaceModeView::RxTx => Self::RxTx,
        }
    }
}

/// Service status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatusView {
    /// Service version string.
    pub version: String,
    /// Seconds since the service started.
    pub uptime_secs: u64,
    /// Npcap version string, or null if unavailable.
    pub npcap_version: Option<String>,
    /// Packet backend state description.
    pub backend_status: String,
    /// Configuration file path.
    pub config_path: String,
    /// Unix time the configuration was last loaded.
    pub config_loaded_unix: u64,
    /// Whether registry policy overrides were applied.
    pub policy_applied: bool,
    /// Interfaces known.
    pub interfaces_known: usize,
    /// Interfaces with a running port.
    pub interfaces_managed: usize,
    /// Total neighbors across interfaces.
    pub neighbors_total: usize,
    /// Host name as advertised.
    pub system_name: String,
    /// Chassis ID as advertised.
    pub chassis_id: String,
}

/// One interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceView {
    /// Adapter GUID.
    pub guid: String,
    /// Alias.
    pub alias: String,
    /// Hardware description.
    pub description: String,
    /// MAC address text.
    pub mac: Option<String>,
    /// `ifIndex`.
    pub if_index: u32,
    /// Kind: `physical_ethernet`, `wifi`, `virtual`, `other`.
    pub kind: String,
    /// Link up.
    pub connected: bool,
    /// Link speed in bits per second.
    pub link_speed: u64,
    /// Effective mode.
    pub mode: InterfaceModeView,
    /// A port task is running.
    pub managed: bool,
    /// Neighbor count.
    pub neighbors: usize,
    /// Unicast addresses as text.
    pub addresses: Vec<String>,
}

/// A TLV-level view of an LLDPDU, shared by neighbors and local
/// advertisements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpduView {
    /// Chassis ID.
    pub chassis_id: IdView,
    /// Port ID.
    pub port_id: IdView,
    /// TTL in seconds.
    pub ttl: u16,
    /// Port Description.
    pub port_description: Option<String>,
    /// System Name.
    pub system_name: Option<String>,
    /// System Description.
    pub system_description: Option<String>,
    /// Capabilities.
    pub capabilities: Option<CapabilitiesView>,
    /// Management addresses.
    pub management_addresses: Vec<ManagementAddressView>,
    /// Organizationally specific TLVs.
    pub org_tlvs: Vec<OrgTlvView>,
    /// Unknown basic TLVs.
    pub unknown_tlvs: Vec<UnknownTlvView>,
}

/// Chassis or Port ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdView {
    /// Subtype number.
    pub subtype: u8,
    /// Subtype name.
    pub subtype_name: String,
    /// Display form (MAC, address, or text).
    pub value: String,
    /// Raw value as hex.
    pub hex: String,
}

/// Capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesView {
    /// Supported capability names.
    pub supported: Vec<String>,
    /// Enabled capability names.
    pub enabled: Vec<String>,
    /// Enabled as switch-style letters, for example "B" or "S".
    pub short: String,
}

/// Management address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementAddressView {
    /// Address text.
    pub address: String,
    /// `ipv4`, `ipv6`, or `afn<n>`.
    pub family: String,
    /// `unknown`, `if_index`, `system_port_number`, or `reserved<n>`.
    pub interface_numbering: String,
    /// Interface number.
    pub interface_number: u32,
    /// OID as hex, if any.
    pub oid_hex: Option<String>,
}

/// Organizationally specific TLV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgTlvView {
    /// OUI as `xx:xx:xx`.
    pub oui: String,
    /// Organization name if known.
    pub organization: Option<String>,
    /// Subtype.
    pub subtype: u8,
    /// Decoded content if a decoder exists.
    pub decoded: Option<Value>,
    /// Raw data as hex.
    pub data_hex: String,
}

/// Unknown TLV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownTlvView {
    /// Type.
    pub tlv_type: u8,
    /// Value hex.
    pub value_hex: String,
}

/// A neighbor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborView {
    /// Local interface GUID.
    pub interface_guid: String,
    /// Local interface alias.
    pub interface_alias: String,
    /// Destination scope: `nearest_bridge`, `nearest_non_tpmr_bridge`, `nearest_customer_bridge`.
    pub scope: String,
    /// Source MAC of the last frame.
    pub source_mac: String,
    /// Seconds until expiry. The advertised TTL is `lldpdu.ttl`.
    pub ttl_remaining: u64,
    /// Unix time first seen.
    pub first_seen_unix: u64,
    /// Unix time last seen.
    pub last_seen_unix: u64,
    /// Unix time of expiry.
    pub expires_unix: u64,
    /// Frames received from this neighbor.
    pub frames: u64,
    /// The advertisement.
    #[serde(flatten)]
    pub lldpdu: LldpduView,
}

/// Local advertisement for one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAdvertisementView {
    /// Interface GUID.
    pub interface_guid: String,
    /// Interface alias.
    pub interface_alias: String,
    /// Mode.
    pub mode: InterfaceModeView,
    /// Destination MAC used.
    pub destination_mac: String,
    /// Source MAC used.
    pub source_mac: String,
    /// The LLDPDU.
    #[serde(flatten)]
    pub lldpdu: LldpduView,
    /// Encoded LLDPDU as hex.
    pub lldpdu_hex: String,
}

/// Counters for one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticsView {
    /// Interface GUID.
    pub interface_guid: String,
    /// Interface alias.
    pub interface_alias: String,
    /// `lldpStatsRxPortFramesTotal`.
    pub rx_frames_total: u64,
    /// `lldpStatsRxPortFramesDiscardedTotal`.
    pub rx_frames_discarded_total: u64,
    /// `lldpStatsRxPortFramesErrors`.
    pub rx_frames_errors: u64,
    /// `lldpStatsRxPortTLVsDiscardedTotal`.
    pub rx_tlvs_discarded_total: u64,
    /// `lldpStatsRxPortTLVsUnrecognizedTotal`.
    pub rx_tlvs_unrecognized_total: u64,
    /// `lldpStatsRxPortAgeoutsTotal`.
    pub rx_ageouts_total: u64,
    /// `lldpStatsTxPortFramesTotal`.
    pub tx_frames_total: u64,
    /// Neighbor inserts.
    pub rem_inserts: u64,
    /// Neighbor deletes.
    pub rem_deletes: u64,
    /// Neighbor drops (table full).
    pub rem_drops: u64,
    /// Receive queue overflows.
    pub rx_queue_overflow: u64,
}

impl StatisticsView {
    /// Builds from engine counters.
    pub fn from_stats(guid: &str, alias: &str, s: &PortStats) -> Self {
        Self {
            interface_guid: guid.into(),
            interface_alias: alias.into(),
            rx_frames_total: s.rx_frames_total,
            rx_frames_discarded_total: s.rx_frames_discarded_total,
            rx_frames_errors: s.rx_frames_errors,
            rx_tlvs_discarded_total: s.rx_tlvs_discarded_total,
            rx_tlvs_unrecognized_total: s.rx_tlvs_unrecognized_total,
            rx_ageouts_total: s.rx_ageouts_total,
            tx_frames_total: s.tx_frames_total,
            rem_inserts: s.rem_inserts,
            rem_deletes: s.rem_deletes,
            rem_drops: s.rem_drops,
            rx_queue_overflow: s.rx_queue_overflow,
        }
    }
}

/// Hex-encodes bytes without separators.
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

fn text(b: &[u8]) -> String {
    lossy_text(b)
}

/// Like [`text`], but keeps line breaks and tabs: Cisco IOS sends a
/// multi-line System Description.
fn multiline_text(b: &[u8]) -> String {
    match core::str::from_utf8(b) {
        Ok(s)
            if s.chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) =>
        {
            s.replace("\r\n", "\n").trim_end().to_owned()
        }
        _ => lossy_text(b),
    }
}

fn cap_name(c: Capability) -> &'static str {
    match c {
        Capability::Other => "other",
        Capability::Repeater => "repeater",
        Capability::Bridge => "bridge",
        Capability::WlanAccessPoint => "wlan_access_point",
        Capability::Router => "router",
        Capability::Telephone => "telephone",
        Capability::DocsisCableDevice => "docsis_cable_device",
        Capability::StationOnly => "station_only",
        Capability::CVlanComponent => "c_vlan_component",
        Capability::SVlanComponent => "s_vlan_component",
        Capability::TwoPortMacRelay => "two_port_mac_relay",
    }
}

impl LldpduView {
    /// Builds the view.
    pub fn from_lldpdu(pdu: &Lldpdu) -> Self {
        let chassis_id = IdView {
            subtype: pdu.chassis_id.subtype.as_u8(),
            subtype_name: format!("{:?}", pdu.chassis_id.subtype).to_ascii_lowercase(),
            value: pdu.chassis_id.to_string(),
            hex: hex(&pdu.chassis_id.value),
        };
        let port_id = IdView {
            subtype: pdu.port_id.subtype.as_u8(),
            subtype_name: format!("{:?}", pdu.port_id.subtype).to_ascii_lowercase(),
            value: pdu.port_id.to_string(),
            hex: hex(&pdu.port_id.value),
        };
        let capabilities = pdu.system_capabilities().map(|c| CapabilitiesView {
            supported: Capability::ALL
                .iter()
                .filter(|x| c.supports(**x))
                .map(|x| cap_name(*x).into())
                .collect(),
            enabled: c.enabled_iter().map(|x| cap_name(x).into()).collect(),
            short: c.enabled_iter().map(Capability::short_name).collect(),
        });
        let mut unknown_tlvs = Vec::new();
        for t in &pdu.optional {
            if let Tlv::Unknown { tlv_type, value } = t {
                unknown_tlvs.push(UnknownTlvView {
                    tlv_type: *tlv_type,
                    value_hex: hex(value),
                });
            }
        }
        Self {
            chassis_id,
            port_id,
            ttl: pdu.ttl,
            port_description: pdu.port_description().map(text),
            system_name: pdu.system_name().map(text),
            system_description: pdu.system_description().map(multiline_text),
            capabilities,
            management_addresses: pdu
                .management_addresses()
                .map(ManagementAddressView::from_addr)
                .collect(),
            org_tlvs: pdu.organizational().map(OrgTlvView::from_org).collect(),
            unknown_tlvs,
        }
    }
}

impl ManagementAddressView {
    /// Builds the view.
    pub fn from_addr(m: &ManagementAddress) -> Self {
        use lldp_codec::{AddressFamily, InterfaceNumbering};
        Self {
            address: m.address.to_string(),
            family: match m.address.family() {
                AddressFamily::Ipv4 => "ipv4".into(),
                AddressFamily::Ipv6 => "ipv6".into(),
                AddressFamily::Mac802 => "mac".into(),
                AddressFamily::Other(n) => format!("afn{n}"),
            },
            interface_numbering: match m.numbering {
                InterfaceNumbering::Unknown => "unknown".into(),
                InterfaceNumbering::IfIndex => "if_index".into(),
                InterfaceNumbering::SystemPortNumber => "system_port_number".into(),
                InterfaceNumbering::Reserved(n) => format!("reserved{n}"),
            },
            interface_number: m.interface_number,
            oid_hex: (!m.oid.is_empty()).then(|| hex(&m.oid)),
        }
    }
}

impl OrgTlvView {
    /// Builds the view, decoding known organizations.
    pub fn from_org(o: &OrgTlv) -> Self {
        let (organization, decoded) = match o.decode() {
            DecodedOrgTlv::Ieee8021(t) => (Some("IEEE 802.1"), Some(ieee8021_json(&t))),
            DecodedOrgTlv::Ieee8023(t) => (Some("IEEE 802.3"), Some(ieee8023_json(&t))),
            DecodedOrgTlv::Med(t) => (Some("LLDP-MED"), Some(med_json(&t))),
            DecodedOrgTlv::Unrecognized(_) | DecodedOrgTlv::Unknown(_) => {
                (organization_name(o.oui), None)
            }
            _ => (None, None),
        };
        Self {
            oui: format!("{:02x}:{:02x}:{:02x}", o.oui[0], o.oui[1], o.oui[2]),
            organization: organization.map(str::to_owned),
            subtype: o.subtype,
            decoded,
            data_hex: hex(&o.data),
        }
    }
}

fn organization_name(oui: [u8; 3]) -> Option<&'static str> {
    match oui {
        [0x00, 0x80, 0xC2] => Some("IEEE 802.1"),
        [0x00, 0x12, 0x0F] => Some("IEEE 802.3"),
        [0x00, 0x12, 0xBB] => Some("LLDP-MED"),
        [0x00, 0x00, 0x0C] => Some("Cisco"),
        [0x00, 0x90, 0x69] => Some("Juniper"),
        [0x00, 0x1C, 0x73] => Some("Arista"),
        [0x00, 0x0E, 0xCF] => Some("PROFINET"),
        _ => None,
    }
}

fn ieee8021_json(t: &Ieee8021Tlv) -> Value {
    match t {
        Ieee8021Tlv::PortVlanId(v) => json!({"type": "port_vlan_id", "pvid": v}),
        Ieee8021Tlv::PortAndProtocolVlanId {
            supported,
            enabled,
            ppvid,
        } => {
            json!({"type": "port_and_protocol_vlan_id", "supported": supported, "enabled": enabled, "ppvid": ppvid})
        }
        Ieee8021Tlv::VlanName { vid, name } => {
            json!({"type": "vlan_name", "vid": vid, "name": text(name)})
        }
        Ieee8021Tlv::ProtocolIdentity(p) => {
            json!({"type": "protocol_identity", "identity_hex": hex(p)})
        }
        Ieee8021Tlv::VidUsageDigest(d) => json!({"type": "vid_usage_digest", "digest": d}),
        Ieee8021Tlv::ManagementVid(v) => json!({"type": "management_vid", "vid": v}),
        Ieee8021Tlv::LinkAggregation(la) => {
            json!({"type": "link_aggregation", "capable": la.capable, "aggregated": la.aggregated, "aggregated_port_id": la.aggregated_port_id})
        }
        _ => json!({"type": "unknown"}),
    }
}

fn ieee8023_json(t: &Ieee8023Tlv) -> Value {
    match t {
        Ieee8023Tlv::MacPhyConfigStatus(m) => json!({
            "type": "mac_phy_configuration_status",
            "autoneg_supported": m.autoneg_supported,
            "autoneg_enabled": m.autoneg_enabled,
            "pmd_autoneg_advertised": m.pmd_autoneg_advertised,
            "operational_mau_type": m.operational_mau_type,
        }),
        Ieee8023Tlv::PowerViaMdi(p) => json!({
            "type": "power_via_mdi",
            "port_class_pse": p.port_class_pse,
            "pse_mdi_power_supported": p.pse_mdi_power_supported,
            "pse_mdi_power_enabled": p.pse_mdi_power_enabled,
            "pse_pairs_controllable": p.pse_pairs_controllable,
            "pse_power_pair": p.pse_power_pair,
            "power_class": p.power_class,
            "dll": p.dll.map(|d| json!({
                "power_type": d.power_type, "power_source": d.power_source, "power_priority": d.power_priority,
                "pd_requested_power_dw": d.pd_requested_power, "pse_allocated_power_dw": d.pse_allocated_power,
            })),
            "extension_hex": hex(&p.extension),
        }),
        Ieee8023Tlv::LinkAggregation(la) => {
            json!({"type": "link_aggregation", "capable": la.capable, "aggregated": la.aggregated, "aggregated_port_id": la.aggregated_port_id})
        }
        Ieee8023Tlv::MaximumFrameSize(s) => json!({"type": "maximum_frame_size", "octets": s}),
        Ieee8023Tlv::Eee {
            transmit_tw,
            receive_tw,
            fallback_tw,
            echo_transmit_tw,
            echo_receive_tw,
        } => json!({
            "type": "energy_efficient_ethernet",
            "transmit_tw_us": transmit_tw, "receive_tw_us": receive_tw, "fallback_tw_us": fallback_tw,
            "echo_transmit_tw_us": echo_transmit_tw, "echo_receive_tw_us": echo_receive_tw,
        }),
        _ => json!({"type": "unknown"}),
    }
}

fn med_json(t: &MedTlv) -> Value {
    match t {
        MedTlv::Capabilities {
            capabilities,
            device_type,
        } => {
            json!({"type": "capabilities", "capabilities": capabilities, "device_type": format!("{device_type:?}").to_ascii_lowercase()})
        }
        MedTlv::NetworkPolicy {
            application_type,
            unknown,
            tagged,
            vlan_id,
            l2_priority,
            dscp,
        } => json!({
            "type": "network_policy", "application_type": application_type, "unknown": unknown,
            "tagged": tagged, "vlan_id": vlan_id, "l2_priority": l2_priority, "dscp": dscp,
        }),
        MedTlv::Location(loc) => match loc {
            MedLocation::Coordinate(d) => {
                json!({"type": "location", "format": "coordinate", "data_hex": hex(d)})
            }
            MedLocation::Civic(d) => {
                json!({"type": "location", "format": "civic", "data_hex": hex(d)})
            }
            MedLocation::Elin(d) => json!({"type": "location", "format": "elin", "elin": text(d)}),
            MedLocation::Other { format, data } => {
                json!({"type": "location", "format": format, "data_hex": hex(data)})
            }
            _ => json!({"type": "location"}),
        },
        MedTlv::ExtendedPower {
            power_type,
            power_source,
            power_priority,
            power_value,
        } => json!({
            "type": "extended_power_via_mdi", "power_type": power_type, "power_source": power_source,
            "power_priority": power_priority, "power_dw": power_value,
        }),
        MedTlv::HardwareRevision(s) => json!({"type": "hardware_revision", "value": text(s)}),
        MedTlv::FirmwareRevision(s) => json!({"type": "firmware_revision", "value": text(s)}),
        MedTlv::SoftwareRevision(s) => json!({"type": "software_revision", "value": text(s)}),
        MedTlv::SerialNumber(s) => json!({"type": "serial_number", "value": text(s)}),
        MedTlv::ManufacturerName(s) => json!({"type": "manufacturer_name", "value": text(s)}),
        MedTlv::ModelName(s) => json!({"type": "model_name", "value": text(s)}),
        MedTlv::AssetId(s) => json!({"type": "asset_id", "value": text(s)}),
        _ => json!({"type": "unknown"}),
    }
}

impl NeighborView {
    /// Builds the view. `now` and `now_unix` are the monotonic and wall
    /// clock readings taken at the same moment, used to convert instants.
    pub fn from_neighbor(
        guid: &str,
        alias: &str,
        n: &Neighbor,
        now: std::time::Instant,
        now_unix: u64,
    ) -> Self {
        let to_unix = |i: std::time::Instant| {
            if i >= now {
                now_unix.saturating_add(i.saturating_duration_since(now).as_secs())
            } else {
                now_unix.saturating_sub(now.saturating_duration_since(i).as_secs())
            }
        };
        Self {
            interface_guid: guid.into(),
            interface_alias: alias.into(),
            scope: match n.msap.scope {
                lldp_codec::LldpDestination::NearestBridge => "nearest_bridge".into(),
                lldp_codec::LldpDestination::NearestNonTpmrBridge => {
                    "nearest_non_tpmr_bridge".into()
                }
                lldp_codec::LldpDestination::NearestCustomerBridge => {
                    "nearest_customer_bridge".into()
                }
            },
            source_mac: n.source_mac.to_string(),
            ttl_remaining: n.remaining_ttl(now).as_secs(),
            first_seen_unix: to_unix(n.first_seen),
            last_seen_unix: to_unix(n.last_seen),
            expires_unix: to_unix(n.expires_at),
            frames: n.frames,
            lldpdu: LldpduView::from_lldpdu(&n.lldpdu),
        }
    }
}
