//! Platform-neutral description of a network interface, produced by the
//! platform crate and consumed by the agent and configuration.

use std::net::IpAddr;

use lldp_codec::MacAddr;

/// Classification of a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceKind {
    /// Physical 802.3 adapter (including USB and dock Ethernet).
    PhysicalEthernet,
    /// 802.11 adapter.
    Wifi,
    /// Hyper-V, bridge, team, or other software adapter.
    Virtual,
    /// Loopback, tunnel, VPN, cellular, anything else.
    Other,
}

/// One unicast address with the attributes that matter for management
/// address selection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnicastAddress {
    /// The address.
    pub addr: IpAddr,
    /// RFC 8981 temporary address.
    pub temporary: bool,
    /// Duplicate address detection completed and the address is usable.
    pub preferred: bool,
    /// Prefix length.
    pub prefix_len: u8,
}

/// A network interface as the platform reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Stable identifier (adapter GUID on Windows, `{...}` upper case).
    pub guid: String,
    /// Interface LUID value (Windows), zero elsewhere.
    pub luid: u64,
    /// `ifIndex` (RFC 2863).
    pub if_index: u32,
    /// User-visible alias, for example "Ethernet". Renamable.
    pub alias: String,
    /// Hardware description.
    pub description: String,
    /// MAC address, if the interface has one.
    pub mac: Option<MacAddr>,
    /// Media is connected (link up).
    pub connected: bool,
    /// Transmit link speed in bits per second, zero if unknown.
    pub link_speed: u64,
    /// Classification.
    pub kind: InterfaceKind,
    /// Unicast addresses.
    pub addresses: Vec<UnicastAddress>,
}

/// A change reported by the platform's interface monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceChange {
    /// A new interface appeared.
    Added(InterfaceInfo),
    /// An interface disappeared.
    Removed(InterfaceInfo),
    /// Media connected.
    LinkUp(InterfaceInfo),
    /// Media disconnected.
    LinkDown(InterfaceInfo),
    /// Alias, description, addresses, or speed changed.
    Changed(InterfaceInfo),
}

impl InterfaceChange {
    /// The interface the change concerns.
    pub const fn info(&self) -> &InterfaceInfo {
        match self {
            Self::Added(i)
            | Self::Removed(i)
            | Self::LinkUp(i)
            | Self::LinkDown(i)
            | Self::Changed(i) => i,
        }
    }
}
