//! Value types for the mandatory and basic optional TLVs
//! (IEEE 802.1AB-2016 clause 8.5).

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DecodeError, EncodeError};
use crate::ethernet::MacAddr;
use crate::tlv::tlv_type;

/// Longest identifier value in a Chassis ID or Port ID TLV (8.5.2.3, 8.5.3.3).
pub const MAX_ID_LEN: usize = 255;
/// Longest string value in Port Description, System Name, System Description.
pub const MAX_STRING_LEN: usize = 255;

/// Chassis ID subtypes (8.5.2.2, Table 8-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChassisIdSubtype {
    /// Chassis component (EntPhysicalAlias).
    ChassisComponent,
    /// Interface alias (ifAlias).
    InterfaceAlias,
    /// Port component (EntPhysicalAlias).
    PortComponent,
    /// MAC address.
    MacAddress,
    /// Network address (IANA address family number followed by address).
    NetworkAddress,
    /// Interface name (ifName).
    InterfaceName,
    /// Locally assigned (alphanumeric string).
    LocallyAssigned,
    /// Reserved value.
    Reserved(u8),
}

impl ChassisIdSubtype {
    /// Decodes the subtype octet.
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ChassisComponent,
            2 => Self::InterfaceAlias,
            3 => Self::PortComponent,
            4 => Self::MacAddress,
            5 => Self::NetworkAddress,
            6 => Self::InterfaceName,
            7 => Self::LocallyAssigned,
            other => Self::Reserved(other),
        }
    }

    /// Encodes the subtype octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ChassisComponent => 1,
            Self::InterfaceAlias => 2,
            Self::PortComponent => 3,
            Self::MacAddress => 4,
            Self::NetworkAddress => 5,
            Self::InterfaceName => 6,
            Self::LocallyAssigned => 7,
            Self::Reserved(v) => v,
        }
    }
}

/// Port ID subtypes (8.5.3.2, Table 8-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortIdSubtype {
    /// Interface alias (ifAlias).
    InterfaceAlias,
    /// Port component (EntPhysicalAlias).
    PortComponent,
    /// MAC address.
    MacAddress,
    /// Network address.
    NetworkAddress,
    /// Interface name (ifName).
    InterfaceName,
    /// Agent circuit ID (RFC 3046).
    AgentCircuitId,
    /// Locally assigned.
    LocallyAssigned,
    /// Reserved value.
    Reserved(u8),
}

impl PortIdSubtype {
    /// Decodes the subtype octet.
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::InterfaceAlias,
            2 => Self::PortComponent,
            3 => Self::MacAddress,
            4 => Self::NetworkAddress,
            5 => Self::InterfaceName,
            6 => Self::AgentCircuitId,
            7 => Self::LocallyAssigned,
            other => Self::Reserved(other),
        }
    }

    /// Encodes the subtype octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::InterfaceAlias => 1,
            Self::PortComponent => 2,
            Self::MacAddress => 3,
            Self::NetworkAddress => 4,
            Self::InterfaceName => 5,
            Self::AgentCircuitId => 6,
            Self::LocallyAssigned => 7,
            Self::Reserved(v) => v,
        }
    }
}

/// Checks the identifier length. Receive validation (9.2.7.7.1) tests only
/// the length, so a value that does not fit its subtype (a MAC address
/// subtype that is not 6 octets, say) is accepted and shown as hex.
fn validate_identifier(tlv: u8, subtype: u8, value: &[u8]) -> Result<(), DecodeError> {
    if value.is_empty() || value.len() > MAX_ID_LEN {
        return Err(DecodeError::InvalidIdentifier {
            tlv_type: tlv,
            subtype,
            len: value.len(),
        });
    }
    Ok(())
}

/// Chassis ID TLV value (8.5.2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChassisId {
    /// Subtype.
    pub subtype: ChassisIdSubtype,
    /// Identifier, 1 to 255 octets.
    pub value: Vec<u8>,
}

impl ChassisId {
    /// A MAC address Chassis ID.
    pub fn mac(mac: MacAddr) -> Self {
        Self {
            subtype: ChassisIdSubtype::MacAddress,
            value: mac.0.to_vec(),
        }
    }

    /// A locally assigned Chassis ID. Returns `None` if `s` is empty or
    /// longer than 255 octets.
    pub fn locally_assigned(s: &str) -> Option<Self> {
        (1..=MAX_ID_LEN).contains(&s.len()).then(|| Self {
            subtype: ChassisIdSubtype::LocallyAssigned,
            value: s.as_bytes().to_vec(),
        })
    }

    /// A network address Chassis ID.
    pub fn network_address(addr: &NetworkAddress) -> Self {
        Self {
            subtype: ChassisIdSubtype::NetworkAddress,
            value: addr.to_bytes(),
        }
    }

    /// Parses a Chassis ID TLV value (subtype octet followed by identifier).
    pub fn parse(value: &[u8]) -> Result<Self, DecodeError> {
        let (&st, id) = value.split_first().filter(|(_, id)| !id.is_empty()).ok_or(
            DecodeError::InvalidMandatoryTlvLength {
                tlv_type: tlv_type::CHASSIS_ID,
                len: value.len(),
            },
        )?;
        let subtype = ChassisIdSubtype::from_u8(st);
        validate_identifier(tlv_type::CHASSIS_ID, st, id)?;
        Ok(Self {
            subtype,
            value: id.to_vec(),
        })
    }

    /// Serializes the TLV value.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.value.is_empty() || self.value.len() > MAX_ID_LEN {
            return Err(EncodeError::InvalidValue(
                "chassis id must be 1 to 255 octets",
            ));
        }
        out.push(self.subtype.as_u8());
        out.extend_from_slice(&self.value);
        Ok(())
    }
}

impl fmt::Debug for ChassisId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChassisId({:?}, {})", self.subtype, self)
    }
}

impl fmt::Display for ChassisId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_identifier(
            f,
            self.subtype == ChassisIdSubtype::MacAddress,
            self.subtype == ChassisIdSubtype::NetworkAddress,
            &self.value,
        )
    }
}

/// Port ID TLV value (8.5.3).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId {
    /// Subtype.
    pub subtype: PortIdSubtype,
    /// Identifier, 1 to 255 octets.
    pub value: Vec<u8>,
}

impl PortId {
    /// A MAC address Port ID.
    pub fn mac(mac: MacAddr) -> Self {
        Self {
            subtype: PortIdSubtype::MacAddress,
            value: mac.0.to_vec(),
        }
    }

    /// An interface name Port ID. Returns `None` if `s` is empty or longer
    /// than 255 octets.
    pub fn interface_name(s: &str) -> Option<Self> {
        (1..=MAX_ID_LEN).contains(&s.len()).then(|| Self {
            subtype: PortIdSubtype::InterfaceName,
            value: s.as_bytes().to_vec(),
        })
    }

    /// A locally assigned Port ID. Returns `None` if `s` is empty or longer
    /// than 255 octets.
    pub fn locally_assigned(s: &str) -> Option<Self> {
        (1..=MAX_ID_LEN).contains(&s.len()).then(|| Self {
            subtype: PortIdSubtype::LocallyAssigned,
            value: s.as_bytes().to_vec(),
        })
    }

    /// Parses a Port ID TLV value.
    pub fn parse(value: &[u8]) -> Result<Self, DecodeError> {
        let (&st, id) = value.split_first().filter(|(_, id)| !id.is_empty()).ok_or(
            DecodeError::InvalidMandatoryTlvLength {
                tlv_type: tlv_type::PORT_ID,
                len: value.len(),
            },
        )?;
        let subtype = PortIdSubtype::from_u8(st);
        validate_identifier(tlv_type::PORT_ID, st, id)?;
        Ok(Self {
            subtype,
            value: id.to_vec(),
        })
    }

    /// Serializes the TLV value.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.value.is_empty() || self.value.len() > MAX_ID_LEN {
            return Err(EncodeError::InvalidValue("port id must be 1 to 255 octets"));
        }
        out.push(self.subtype.as_u8());
        out.extend_from_slice(&self.value);
        Ok(())
    }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PortId({:?}, {})", self.subtype, self)
    }
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_identifier(
            f,
            self.subtype == PortIdSubtype::MacAddress,
            self.subtype == PortIdSubtype::NetworkAddress,
            &self.value,
        )
    }
}

fn display_identifier(
    f: &mut fmt::Formatter<'_>,
    is_mac: bool,
    is_net: bool,
    value: &[u8],
) -> fmt::Result {
    if is_mac
        && value.len() == 6
        && let Some(mac) = MacAddr::from_slice(value)
    {
        return write!(f, "{mac}");
    }
    if is_net && let Some(addr) = NetworkAddress::from_bytes(value) {
        return write!(f, "{addr}");
    }
    write!(f, "{}", lossy_text(value))
}

/// Renders octets as text for display: UTF-8 if valid and printable,
/// otherwise hex.
pub fn lossy_text(value: &[u8]) -> String {
    match core::str::from_utf8(value) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_owned(),
        _ => value
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// System capability bits (8.5.8.1, Table 8-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum Capability {
    /// Other.
    Other = 1 << 0,
    /// Repeater.
    Repeater = 1 << 1,
    /// MAC Bridge.
    Bridge = 1 << 2,
    /// WLAN access point.
    WlanAccessPoint = 1 << 3,
    /// Router.
    Router = 1 << 4,
    /// Telephone.
    Telephone = 1 << 5,
    /// DOCSIS cable device.
    DocsisCableDevice = 1 << 6,
    /// Station only.
    StationOnly = 1 << 7,
    /// C-VLAN component of a VLAN bridge.
    CVlanComponent = 1 << 8,
    /// S-VLAN component of a VLAN bridge.
    SVlanComponent = 1 << 9,
    /// Two-port MAC relay.
    TwoPortMacRelay = 1 << 10,
}

impl Capability {
    /// All defined capabilities in bit order.
    pub const ALL: [Self; 11] = [
        Self::Other,
        Self::Repeater,
        Self::Bridge,
        Self::WlanAccessPoint,
        Self::Router,
        Self::Telephone,
        Self::DocsisCableDevice,
        Self::StationOnly,
        Self::CVlanComponent,
        Self::SVlanComponent,
        Self::TwoPortMacRelay,
    ];

    /// Bit mask.
    pub const fn bit(self) -> u16 {
        self as u16
    }

    /// Short name as used by switch CLIs ("B", "R", "S", ...).
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Other => "O",
            Self::Repeater => "P",
            Self::Bridge => "B",
            Self::WlanAccessPoint => "W",
            Self::Router => "R",
            Self::Telephone => "T",
            Self::DocsisCableDevice => "C",
            Self::StationOnly => "S",
            Self::CVlanComponent => "c",
            Self::SVlanComponent => "s",
            Self::TwoPortMacRelay => "M",
        }
    }
}

/// System Capabilities TLV value (8.5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SystemCapabilities {
    /// Capabilities the system supports.
    pub supported: u16,
    /// Capabilities currently enabled. A subset of `supported` (8.5.8.3).
    pub enabled: u16,
}

impl SystemCapabilities {
    /// A station-only endpoint with the capability enabled.
    pub const STATION_ONLY: Self = Self {
        supported: Capability::StationOnly.bit(),
        enabled: Capability::StationOnly.bit(),
    };

    /// Whether `cap` is in the supported set.
    pub const fn supports(self, cap: Capability) -> bool {
        self.supported & cap.bit() != 0
    }

    /// Whether `cap` is in the enabled set.
    pub const fn is_enabled(self, cap: Capability) -> bool {
        self.enabled & cap.bit() != 0
    }

    /// Enabled capabilities as an iterator.
    pub fn enabled_iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |c| self.is_enabled(*c))
    }

    /// Parses the TLV value. Returns `None` if it is shorter than the two
    /// 2-octet fields; octets after them are ignored, as a later version of
    /// the TLV may add fields (6.6.1).
    pub fn parse(value: &[u8]) -> Option<Self> {
        let supported = crate::ethernet::read_u16(value, 0)?;
        let enabled = crate::ethernet::read_u16(value, 2)?;
        Some(Self { supported, enabled })
    }

    /// Whether every enabled capability is also a supported one. A TLV
    /// for which this is false is in error and discarded (8.5.8.3).
    pub const fn is_consistent(self) -> bool {
        self.enabled & !self.supported == 0
    }

    /// Serializes the TLV value.
    pub fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.supported.to_be_bytes());
        out.extend_from_slice(&self.enabled.to_be_bytes());
    }
}

/// IANA address family numbers used in Management Address and network
/// address identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressFamily {
    /// IPv4 (IANA AFN 1).
    Ipv4,
    /// IPv6 (IANA AFN 2).
    Ipv6,
    /// IEEE 802 MAC (IANA AFN 6).
    Mac802,
    /// Any other IANA AFN.
    Other(u8),
}

impl AddressFamily {
    /// Decodes the AFN octet.
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Ipv4,
            2 => Self::Ipv6,
            6 => Self::Mac802,
            other => Self::Other(other),
        }
    }

    /// Encodes the AFN octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
            Self::Mac802 => 6,
            Self::Other(v) => v,
        }
    }
}

/// A network address: IANA address family number plus address octets.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkAddress {
    /// IPv4 address.
    Ipv4(Ipv4Addr),
    /// IPv6 address.
    Ipv6(Ipv6Addr),
    /// Any other family, 1 to 31 address octets (8.5.9.4).
    Other {
        /// IANA address family number.
        family: u8,
        /// Raw address octets.
        octets: Vec<u8>,
    },
}

impl NetworkAddress {
    /// Maximum octets in family + address: the management address subtype
    /// octet and an address of 1 to 31 octets (8.5.9.2, Figure 8-11).
    pub const MAX_LEN: usize = 32;

    /// Address family.
    pub fn family(&self) -> AddressFamily {
        match self {
            Self::Ipv4(_) => AddressFamily::Ipv4,
            Self::Ipv6(_) => AddressFamily::Ipv6,
            Self::Other { family, .. } => AddressFamily::from_u8(*family),
        }
    }

    /// Parses family octet followed by address octets. Returns `None` if
    /// the length is wrong for IPv4/IPv6, empty, or over `MAX_LEN`.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let (&fam, rest) = b.split_first()?;
        if rest.is_empty() || b.len() > Self::MAX_LEN {
            return None;
        }
        Some(match AddressFamily::from_u8(fam) {
            AddressFamily::Ipv4 => Self::Ipv4(Ipv4Addr::from(<[u8; 4]>::try_from(rest).ok()?)),
            AddressFamily::Ipv6 => Self::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).ok()?)),
            _ => Self::Other {
                family: fam,
                octets: rest.to_vec(),
            },
        })
    }

    /// Serializes to family octet followed by address octets.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![self.family().as_u8()];
        match self {
            Self::Ipv4(a) => v.extend_from_slice(&a.octets()),
            Self::Ipv6(a) => v.extend_from_slice(&a.octets()),
            Self::Other { octets, .. } => v.extend_from_slice(octets),
        }
        v
    }
}

impl From<Ipv4Addr> for NetworkAddress {
    fn from(a: Ipv4Addr) -> Self {
        Self::Ipv4(a)
    }
}

impl From<Ipv6Addr> for NetworkAddress {
    fn from(a: Ipv6Addr) -> Self {
        Self::Ipv6(a)
    }
}

impl From<std::net::IpAddr> for NetworkAddress {
    fn from(a: std::net::IpAddr) -> Self {
        match a {
            std::net::IpAddr::V4(v) => Self::Ipv4(v),
            std::net::IpAddr::V6(v) => Self::Ipv6(v),
        }
    }
}

impl fmt::Debug for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(a) => write!(f, "{a}"),
            Self::Ipv6(a) => write!(f, "{a}"),
            Self::Other { family, octets } => {
                write!(f, "afn{family}:")?;
                for b in octets {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// Interface numbering subtype in the Management Address TLV (8.5.9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InterfaceNumbering {
    /// Unknown; interface number is zero.
    Unknown,
    /// RFC 2863 ifIndex.
    IfIndex,
    /// System port number.
    SystemPortNumber,
    /// Reserved value.
    Reserved(u8),
}

impl InterfaceNumbering {
    /// Decodes the subtype octet.
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Unknown,
            2 => Self::IfIndex,
            3 => Self::SystemPortNumber,
            other => Self::Reserved(other),
        }
    }

    /// Encodes the subtype octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 1,
            Self::IfIndex => 2,
            Self::SystemPortNumber => 3,
            Self::Reserved(v) => v,
        }
    }
}

/// Why a Management Address TLV value was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagementAddressError {
    /// The TLV length does not match its two string length fields. The TLV
    /// is ignored and processing of the LLDPDU ends (8.5.9.9 f).
    LengthMismatch,
    /// A field is out of range. Only the TLV is discarded (9.2.7.7.2 d).
    Invalid,
}

/// Management Address TLV value (8.5.9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManagementAddress {
    /// The address.
    pub address: NetworkAddress,
    /// How `interface_number` is to be interpreted.
    pub numbering: InterfaceNumbering,
    /// Interface number (ifIndex or port number), zero if unknown.
    pub interface_number: u32,
    /// BER-encoded object identifier, 0 to 128 octets. Usually empty.
    pub oid: Vec<u8>,
}

impl ManagementAddress {
    /// Longest OID permitted (8.5.9.8).
    pub const MAX_OID_LEN: usize = 128;

    /// A management address with ifIndex numbering and no OID.
    pub fn with_if_index(address: NetworkAddress, if_index: u32) -> Self {
        Self {
            address,
            numbering: InterfaceNumbering::IfIndex,
            interface_number: if_index,
            oid: Vec::new(),
        }
    }

    /// Parses the TLV value. Returns `None` on any structural error.
    pub fn parse(value: &[u8]) -> Option<Self> {
        Self::parse_checked(value).ok()
    }

    /// Parses the TLV value, telling apart the two kinds of error that
    /// receive validation treats differently.
    pub(crate) fn parse_checked(value: &[u8]) -> Result<Self, ManagementAddressError> {
        use ManagementAddressError::{Invalid, LengthMismatch};
        let (&addr_len, rest) = value.split_first().ok_or(LengthMismatch)?;
        let addr_len = usize::from(addr_len);
        let addr_bytes = rest.get(..addr_len).ok_or(LengthMismatch)?;
        let rest = rest.get(addr_len..).ok_or(LengthMismatch)?;
        let (&numbering, rest) = rest.split_first().ok_or(LengthMismatch)?;
        let number_bytes: [u8; 4] = rest
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(LengthMismatch)?;
        let rest = rest.get(4..).ok_or(LengthMismatch)?;
        let (&oid_len, oid) = rest.split_first().ok_or(LengthMismatch)?;
        let oid_len = usize::from(oid_len);
        // 8.5.9.9 f): the TLV length is the two string lengths plus 7.
        if oid.len() != oid_len {
            return Err(LengthMismatch);
        }
        if oid_len > Self::MAX_OID_LEN {
            return Err(Invalid);
        }
        let address = NetworkAddress::from_bytes(addr_bytes).ok_or(Invalid)?;
        Ok(Self {
            address,
            numbering: InterfaceNumbering::from_u8(numbering),
            interface_number: u32::from_be_bytes(number_bytes),
            oid: oid.to_vec(),
        })
    }

    /// Serializes the TLV value.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let addr = self.address.to_bytes();
        if addr.len() > NetworkAddress::MAX_LEN {
            return Err(EncodeError::InvalidValue(
                "management address longer than 31 octets plus subtype",
            ));
        }
        if self.oid.len() > Self::MAX_OID_LEN {
            return Err(EncodeError::InvalidValue(
                "management address OID longer than 128 octets",
            ));
        }
        // Lengths are bounded above, so the conversions cannot fail.
        out.push(u8::try_from(addr.len()).unwrap_or(0));
        out.extend_from_slice(&addr);
        out.push(self.numbering.as_u8());
        out.extend_from_slice(&self.interface_number.to_be_bytes());
        out.push(u8::try_from(self.oid.len()).unwrap_or(0));
        out.extend_from_slice(&self.oid);
        Ok(())
    }
}
