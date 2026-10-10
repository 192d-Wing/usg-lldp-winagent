//! Turns configuration plus system facts into what the agent advertises:
//! the [`Resolver`] implementation used by the service.

use std::net::IpAddr;

use lldp_codec::{ChassisId, ManagementAddress, NetworkAddress, PortId, SystemCapabilities};
use lldp_core::agent::Decision;
use lldp_core::{
    AdminStatus, InterfaceInfo, LocalPort, LocalSystem, PortConfig, Resolver, TimerParams,
    UnicastAddress,
};

use crate::{ChassisIdSource, Config, PortIdSource};

/// Facts about the local system, supplied by the platform crate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemFacts {
    /// Short host name.
    pub hostname: String,
    /// Fully qualified name, equal to `hostname` when not domain-joined.
    pub fqdn: String,
    /// Operating system description without version, for example
    /// "Microsoft Windows 11 Enterprise".
    pub os_name: String,
    /// Version and build text, for example "24H2 (build 26100) x64".
    pub os_version: String,
    /// Manufacturer and model, if known.
    pub hardware: Option<String>,
    /// SMBIOS system UUID, if known.
    pub smbios_uuid: Option<String>,
    /// A virtual switch or bridge exists on this host.
    pub has_bridge: bool,
}

/// Resolver backed by a configuration and system facts. Replace the whole
/// value on reload.
#[derive(Debug, Clone)]
pub struct ConfigResolver {
    config: Config,
    facts: SystemFacts,
    system: LocalSystem,
}

impl ConfigResolver {
    /// Builds the resolver and precomputes the system-wide content.
    pub fn new(config: Config, facts: SystemFacts) -> Self {
        let system = build_system(&config, &facts);
        Self {
            config,
            facts,
            system,
        }
    }

    /// The configuration in effect.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// The facts in effect.
    pub const fn facts(&self) -> &SystemFacts {
        &self.facts
    }

    /// Chassis ID in effect.
    pub fn chassis_id(&self) -> &ChassisId {
        &self.system.chassis_id
    }
}

fn truncate_bytes(s: &str, max: usize) -> Vec<u8> {
    let mut end = s.len().min(max);
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default().as_bytes().to_vec()
}

fn build_system(cfg: &Config, facts: &SystemFacts) -> LocalSystem {
    let lldp = &cfg.lldp;
    let hostname_id = || {
        let h = if facts.hostname.is_empty() {
            "windows-host"
        } else {
            facts.hostname.as_str()
        };
        ChassisId::locally_assigned(&String::from_utf8_lossy(&truncate_bytes(h, 255)))
    };
    let chassis_id = match lldp.chassis_id.source {
        // MAC-based chassis IDs are per port and substituted by the agent
        // at transmit time; the system view falls back to the hostname.
        ChassisIdSource::Hostname | ChassisIdSource::Mac => hostname_id(),
        ChassisIdSource::SmbiosUuid => facts
            .smbios_uuid
            .as_deref()
            .and_then(ChassisId::locally_assigned)
            .or_else(hostname_id),
        ChassisIdSource::Custom => lldp
            .chassis_id
            .value
            .as_deref()
            .and_then(ChassisId::locally_assigned)
            .or_else(hostname_id),
    }
    .unwrap_or_else(|| ChassisId {
        subtype: lldp_codec::ChassisIdSubtype::LocallyAssigned,
        value: b"windows-host".to_vec(),
    });

    let system_name = lldp.advertise.system_name.then(|| {
        if let Some(o) = &lldp.system_name_override {
            return truncate_bytes(o, 255);
        }
        let name = if lldp.advertise.system_name_fqdn && !facts.fqdn.is_empty() {
            &facts.fqdn
        } else {
            &facts.hostname
        };
        truncate_bytes(name, 255)
    });

    let system_description = lldp.advertise.system_description.then(|| {
        if let Some(o) = &lldp.system_description_override {
            return truncate_bytes(o, 255);
        }
        let mut s = if facts.os_name.is_empty() {
            "Microsoft Windows".to_owned()
        } else {
            facts.os_name.clone()
        };
        if lldp.advertise.os_version && !facts.os_version.is_empty() {
            s.push(' ');
            s.push_str(&facts.os_version);
        }
        if lldp.advertise.hardware
            && let Some(h) = &facts.hardware
        {
            s.push_str(" on ");
            s.push_str(h);
        }
        truncate_bytes(&s, 255)
    });

    let capabilities = lldp.advertise.system_capabilities.then(|| {
        // Station Only is for a system with no other capability (802.1AB
        // Table 8-4, footnote), so a bridge advertises Bridge alone.
        if lldp.advertise.bridge_capability && facts.has_bridge {
            let bridge = lldp_codec::Capability::Bridge.bit();
            SystemCapabilities {
                supported: bridge,
                enabled: bridge,
            }
        } else {
            SystemCapabilities::STATION_ONLY
        }
    });

    LocalSystem {
        chassis_id,
        system_name,
        system_description,
        capabilities,
        org_tlvs: Vec::new(),
    }
}

/// Selects management addresses for an interface per the configured
/// rules: pinned addresses win; otherwise IPv6 global, then IPv6 unique
/// local, then IPv4, skipping temporary, link-local, and non-preferred
/// addresses unless allowed, up to `max_per_interface`. When the limit is
/// two or more, each family with a usable address keeps at least one slot.
/// When no address qualifies, the interface's MAC address is advertised
/// instead, as 802.1AB-2016 8.5.9.4 b) and 8.5.9.9 a) recommend.
pub fn select_management_addresses(cfg: &Config, iface: &InterfaceInfo) -> Vec<ManagementAddress> {
    let m = &cfg.lldp.management_addresses;
    if !cfg.lldp.advertise.management_address || m.max_per_interface == 0 {
        return Vec::new();
    }
    let picked = select_ip_addresses(cfg, iface);
    if picked.is_empty()
        && let Some(mac) = iface.mac
    {
        return vec![ManagementAddress::with_if_index(
            NetworkAddress::mac(mac),
            iface.if_index,
        )];
    }
    picked
}

fn select_ip_addresses(cfg: &Config, iface: &InterfaceInfo) -> Vec<ManagementAddress> {
    let m = &cfg.lldp.management_addresses;
    let mk =
        |addr: IpAddr| ManagementAddress::with_if_index(NetworkAddress::from(addr), iface.if_index);
    if !m.pinned.is_empty() {
        return m
            .pinned
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(mk)
            .take(m.max_per_interface)
            .collect();
    }
    let rank = |u: &UnicastAddress| -> Option<u8> {
        if !u.preferred {
            return None;
        }
        match u.addr {
            IpAddr::V6(v6) => {
                if !m.ipv6 {
                    return None;
                }
                if u.temporary && !m.allow_temporary_ipv6 {
                    return None;
                }
                let seg0 = v6.segments()[0];
                let link_local = seg0 & 0xffc0 == 0xfe80;
                let unique_local = seg0 & 0xfe00 == 0xfc00;
                if v6.is_loopback() || v6.is_unspecified() {
                    return None;
                }
                if link_local {
                    return m.allow_link_local.then_some(3);
                }
                Some(u8::from(unique_local))
            }
            IpAddr::V4(v4) => {
                if !m.ipv4 || v4.is_loopback() || v4.is_unspecified() {
                    return None;
                }
                if v4.is_link_local() {
                    return m.allow_link_local.then_some(4);
                }
                Some(2)
            }
        }
    };
    let mut ranked: Vec<(u8, IpAddr)> = iface
        .addresses
        .iter()
        .filter_map(|u| rank(u).map(|r| (r, u.addr)))
        .collect();
    ranked.sort();
    ranked.dedup();
    let mut picked: Vec<(u8, IpAddr)> = ranked.iter().copied().take(m.max_per_interface).collect();
    // With room for two or more, each address family that has a candidate
    // gets at least one slot, so several IPv6 addresses do not crowd out
    // the IPv4 address (or the reverse).
    if m.max_per_interface >= 2 {
        for v4 in [false, true] {
            if picked.iter().any(|(_, a)| a.is_ipv4() == v4) {
                continue;
            }
            if let Some(best) = ranked.iter().find(|(_, a)| a.is_ipv4() == v4) {
                picked.pop();
                picked.push(*best);
            }
        }
        picked.sort();
    }
    picked.into_iter().map(|(_, a)| mk(a)).collect()
}

impl Resolver for ConfigResolver {
    fn system(&self) -> LocalSystem {
        self.system.clone()
    }

    fn decide(&self, iface: &InterfaceInfo) -> Decision {
        let resolved = self
            .config
            .resolve_interface(&iface.alias, &iface.guid, iface.kind);
        let admin_status = AdminStatus::from(resolved.mode);
        let port_id = match (self.config.lldp.port_id, iface.mac) {
            (PortIdSource::Mac, Some(mac)) => PortId::mac(mac),
            (PortIdSource::InterfaceName, _) | (PortIdSource::Mac, None) => {
                PortId::interface_name(&iface.alias)
                    .or_else(|| PortId::locally_assigned(&iface.guid))
                    .unwrap_or_else(|| PortId {
                        subtype: lldp_codec::PortIdSubtype::LocallyAssigned,
                        value: b"port".to_vec(),
                    })
            }
        };
        let adv = &self.config.lldp.advertise;
        let port_description = adv.port_description.then(|| {
            if let Some(o) = &resolved.port_description {
                return truncate_bytes(o, 255);
            }
            let s = if adv.adapter_description
                && !iface.description.is_empty()
                && iface.description != iface.alias
            {
                format!("{} ({})", iface.alias, iface.description)
            } else {
                iface.alias.clone()
            };
            truncate_bytes(&s, 255)
        });
        let local = LocalPort {
            port_id,
            port_description,
            management_addresses: select_management_addresses(&self.config, iface),
            org_tlvs: Vec::new(),
        };
        Decision {
            admin_status,
            local,
        }
    }

    fn timers(&self) -> TimerParams {
        self.config.lldp.timer_params()
    }

    fn port_config(&self, admin_status: AdminStatus) -> PortConfig {
        PortConfig {
            admin_status,
            destination: lldp_codec::LldpDestination::NearestBridge,
            max_neighbors: self.config.lldp.max_neighbors_per_interface,
            max_lldpdu_len: 1500,
            tx_stagger: std::time::Duration::ZERO,
        }
    }
}
