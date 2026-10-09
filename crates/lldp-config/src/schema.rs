//! Schema version 1 types. Every field has a default so a minimal file
//! (`version: 1`) is valid. Unknown fields are rejected so typos are
//! reported instead of silently ignored.

use lldp_core::{AdminStatus, TimerParams};
use serde::{Deserialize, Serialize};

/// Root of the configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version. Must be 1.
    pub version: u32,
    /// Agent-wide switches.
    #[serde(default)]
    pub agent: Agent,
    /// Protocol parameters and advertisement content.
    #[serde(default)]
    pub lldp: Lldp,
    /// Interface selection.
    #[serde(default)]
    pub interfaces: Interfaces,
    /// Logging.
    #[serde(default)]
    pub logging: Logging,
    /// Local IPC.
    #[serde(default)]
    pub ipc: Ipc,
    /// Windows integration.
    #[serde(default)]
    pub windows: Windows,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            agent: Agent::default(),
            lldp: Lldp::default(),
            interfaces: Interfaces::default(),
            logging: Logging::default(),
            ipc: Ipc::default(),
            windows: Windows::default(),
        }
    }
}

/// Agent-wide switches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Agent {
    /// Master switch. When false the service runs but every interface is
    /// disabled.
    pub enabled: bool,
}

impl Default for Agent {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Protocol parameters (IEEE names in comments) and advertisement content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Lldp {
    /// `msgTxInterval`, seconds. 1 to 3600.
    pub transmit_interval: u16,
    /// `msgTxHold`. 1 to 100.
    pub hold_multiplier: u8,
    /// `msgFastTx`, seconds. 1 to 3600.
    pub fast_tx_interval: u16,
    /// `txFastInit`. 1 to 8.
    pub fast_tx_count: u8,
    /// `txCreditMax`. 1 to 100.
    pub tx_credit_max: u8,
    /// `reinitDelay`, seconds. 1 to 10.
    pub reinit_delay: u8,
    /// Neighbor table size per interface. 1 to 64.
    pub max_neighbors_per_interface: usize,
    /// Chassis ID source.
    pub chassis_id: ChassisIdConfig,
    /// Port ID source.
    pub port_id: PortIdSource,
    /// Which optional TLVs and which parts of them to send.
    pub advertise: Advertise,
    /// Replaces the computed System Name.
    pub system_name_override: Option<String>,
    /// Replaces the computed System Description.
    pub system_description_override: Option<String>,
    /// Management address selection.
    pub management_addresses: ManagementAddresses,
}

impl Default for Lldp {
    fn default() -> Self {
        let t = TimerParams::DEFAULT;
        Self {
            transmit_interval: t.msg_tx_interval,
            hold_multiplier: t.msg_tx_hold,
            fast_tx_interval: t.msg_fast_tx,
            fast_tx_count: t.tx_fast_init,
            tx_credit_max: t.tx_credit_max,
            reinit_delay: t.reinit_delay,
            max_neighbors_per_interface: 8,
            chassis_id: ChassisIdConfig::default(),
            port_id: PortIdSource::default(),
            advertise: Advertise::default(),
            system_name_override: None,
            system_description_override: None,
            management_addresses: ManagementAddresses::default(),
        }
    }
}

impl Lldp {
    /// The timer parameters as the engine wants them.
    pub const fn timer_params(&self) -> TimerParams {
        TimerParams {
            msg_tx_interval: self.transmit_interval,
            msg_tx_hold: self.hold_multiplier,
            msg_fast_tx: self.fast_tx_interval,
            tx_fast_init: self.fast_tx_count,
            tx_credit_max: self.tx_credit_max,
            reinit_delay: self.reinit_delay,
        }
    }
}

/// Chassis ID configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ChassisIdConfig {
    /// Where the value comes from.
    pub source: ChassisIdSource,
    /// The value when `source` is `custom`.
    pub value: Option<String>,
}

/// Chassis ID sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChassisIdSource {
    /// Locally assigned subtype, value is the computer name.
    #[default]
    Hostname,
    /// Locally assigned subtype, value is the SMBIOS system UUID.
    SmbiosUuid,
    /// MAC address subtype, value is the transmitting adapter's MAC. Not
    /// stable across docks; provided for compatibility.
    Mac,
    /// Locally assigned subtype, value from `chassis_id.value`.
    Custom,
}

/// Port ID sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PortIdSource {
    /// MAC address subtype.
    #[default]
    Mac,
    /// Interface name subtype, value is the Windows alias.
    InterfaceName,
}

/// Optional TLV and privacy switches.
#[allow(clippy::struct_excessive_bools)] // each is an independent user-facing switch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Advertise {
    /// Send Port Description.
    pub port_description: bool,
    /// Include the adapter hardware description in Port Description.
    pub adapter_description: bool,
    /// Send System Name.
    pub system_name: bool,
    /// Use the FQDN rather than the short name when domain-joined.
    pub system_name_fqdn: bool,
    /// Send System Description.
    pub system_description: bool,
    /// Include the OS version in System Description.
    pub os_version: bool,
    /// Include manufacturer and model in System Description.
    pub hardware: bool,
    /// Send System Capabilities.
    pub system_capabilities: bool,
    /// Advertise the Bridge capability when a vSwitch or bridge exists.
    pub bridge_capability: bool,
    /// Send Management Address TLVs.
    pub management_address: bool,
}

impl Default for Advertise {
    fn default() -> Self {
        Self {
            port_description: true,
            adapter_description: true,
            system_name: true,
            system_name_fqdn: true,
            system_description: true,
            os_version: true,
            hardware: false,
            system_capabilities: true,
            bridge_capability: false,
            management_address: true,
        }
    }
}

/// Management address selection.
#[allow(clippy::struct_excessive_bools)] // each is an independent user-facing switch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ManagementAddresses {
    /// Advertise IPv4.
    pub ipv4: bool,
    /// Advertise IPv6.
    pub ipv6: bool,
    /// Allow RFC 8981 temporary IPv6 addresses.
    pub allow_temporary_ipv6: bool,
    /// Allow link-local addresses (IPv6 fe80::/10, IPv4 169.254/16).
    pub allow_link_local: bool,
    /// Maximum addresses per interface. 0 disables.
    pub max_per_interface: usize,
    /// Addresses to advertise instead of the automatic selection, as text.
    pub pinned: Vec<String>,
}

impl Default for ManagementAddresses {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            allow_temporary_ipv6: false,
            allow_link_local: false,
            max_per_interface: 2,
            pinned: Vec::new(),
        }
    }
}

/// Interface administrative mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceMode {
    /// Neither.
    Disabled,
    /// Receive only.
    RxOnly,
    /// Transmit only.
    TxOnly,
    /// Both.
    #[default]
    RxTx,
}

impl From<InterfaceMode> for AdminStatus {
    fn from(m: InterfaceMode) -> Self {
        match m {
            InterfaceMode::Disabled => Self::Disabled,
            InterfaceMode::RxOnly => Self::RxOnly,
            InterfaceMode::TxOnly => Self::TxOnly,
            InterfaceMode::RxTx => Self::RxTx,
        }
    }
}

/// Interface selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Interfaces {
    /// Mode for physical Ethernet adapters.
    pub default_mode: InterfaceMode,
    /// Mode for Wi-Fi adapters.
    pub wifi: InterfaceMode,
    /// Mode for virtual adapters (Hyper-V, bridges, teams).
    pub r#virtual: InterfaceMode,
    /// Alias globs that are always disabled. Case-insensitive; `*` and
    /// `?` wildcards.
    pub exclude: Vec<String>,
    /// Per-interface overrides, first match wins.
    pub overrides: Vec<InterfaceOverride>,
}

impl Default for Interfaces {
    fn default() -> Self {
        Self {
            default_mode: InterfaceMode::RxTx,
            wifi: InterfaceMode::Disabled,
            r#virtual: InterfaceMode::Disabled,
            exclude: vec!["vEthernet*".into(), "VPN*".into(), "Loopback*".into()],
            overrides: Vec::new(),
        }
    }
}

/// One interface override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceOverride {
    /// Alias glob, or `guid:{...}` to match the adapter GUID exactly.
    pub r#match: String,
    /// Mode for matching interfaces.
    #[serde(default)]
    pub mode: Option<InterfaceMode>,
    /// Administrator-defined Port Description.
    #[serde(default)]
    pub port_description: Option<String>,
}

/// Logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Logging {
    /// Minimum level: `error`, `warn`, `info`, `debug`, `trace`.
    pub level: LogLevel,
    /// Write to the Windows Event Log.
    pub windows_event_log: bool,
    /// Maximum Event Log entries per minute before suppression.
    pub event_rate_limit_per_minute: u32,
}

impl Default for Logging {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            windows_event_log: true,
            event_rate_limit_per_minute: 60,
        }
    }
}

/// Log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Normal operation.
    #[default]
    Info,
    /// Verbose.
    Debug,
    /// Everything.
    Trace,
}

/// Local IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ipc {
    /// Serve the named pipe.
    pub enabled: bool,
    /// Windows group granted read-only access, as a name or SID string.
    pub read_group: String,
}

impl Default for Ipc {
    fn default() -> Self {
        Self {
            enabled: true,
            read_group: "S-1-5-11".into(),
        } // Authenticated Users
    }
}

/// Windows integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Windows {
    /// Unbind the Microsoft LLDP driver on adapters where this agent
    /// transmits, and restore it when it stops.
    pub manage_mslldp_binding: bool,
}

impl Default for Windows {
    fn default() -> Self {
        Self {
            manage_mslldp_binding: true,
        }
    }
}

/// Registry policy values that override the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyOverrides {
    /// `agent.enabled`.
    pub enabled: Option<bool>,
    /// `interfaces.default_mode`.
    pub default_mode: Option<InterfaceMode>,
    /// `lldp.advertise.system_name_fqdn`.
    pub advertise_fqdn: Option<bool>,
    /// `lldp.advertise.os_version`.
    pub advertise_os_version: Option<bool>,
    /// `lldp.advertise.hardware`.
    pub advertise_hardware: Option<bool>,
    /// `lldp.advertise.management_address`.
    pub advertise_management_address: Option<bool>,
}
