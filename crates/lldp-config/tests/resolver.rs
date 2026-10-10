//! Advertisement resolution tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::IpAddr;

use lldp_codec::{Capability, ChassisIdSubtype, MacAddr, PortIdSubtype};
use lldp_config::{ChassisIdSource, Config, ConfigResolver, PortIdSource, SystemFacts};
use lldp_core::{AdminStatus, InterfaceInfo, InterfaceKind, Resolver, UnicastAddress};

const MAC: MacAddr = MacAddr([0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]);

fn facts() -> SystemFacts {
    SystemFacts {
        hostname: "WS-12345".into(),
        fqdn: "WS-12345.example.mil".into(),
        os_name: "Microsoft Windows 11 Enterprise".into(),
        os_version: "24H2 (build 26100) x64".into(),
        hardware: Some("Dell Inc. Latitude 5550".into()),
        smbios_uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()),
        has_bridge: true,
    }
}

fn addr(s: &str, temporary: bool, preferred: bool) -> UnicastAddress {
    UnicastAddress {
        addr: s.parse::<IpAddr>().unwrap(),
        temporary,
        preferred,
        prefix_len: 64,
    }
}

fn iface() -> InterfaceInfo {
    InterfaceInfo {
        guid: "{AAAAAAAA-0000-0000-0000-000000000001}".into(),
        luid: 1,
        if_index: 12,
        alias: "Ethernet".into(),
        description: "Intel(R) Ethernet Controller I225-LM".into(),
        mac: Some(MAC),
        connected: true,
        link_speed: 1_000_000_000,
        kind: InterfaceKind::PhysicalEthernet,
        addresses: vec![
            addr("fe80::1", false, true),
            addr("2001:db8:10::5", false, true),
            addr("2001:db8:10:0:1234:5678:9abc:def0", true, true),
            addr("fd00::5", false, true),
            addr("10.10.10.50", false, true),
            addr("169.254.1.1", false, true),
            addr("2001:db8:10::9", false, false),
        ],
    }
}

#[test]
fn defaults_advertise_fqdn_os_and_station_only() {
    let r = ConfigResolver::new(Config::default(), facts());
    let s = r.system();
    assert_eq!(s.chassis_id.subtype, ChassisIdSubtype::LocallyAssigned);
    assert_eq!(s.chassis_id.to_string(), "WS-12345");
    assert_eq!(s.system_name.as_deref(), Some(&b"WS-12345.example.mil"[..]));
    assert_eq!(
        s.system_description.as_deref(),
        Some(&b"Microsoft Windows 11 Enterprise 24H2 (build 26100) x64"[..])
    );
    let caps = s.capabilities.unwrap();
    assert!(caps.is_enabled(Capability::StationOnly));
    assert!(
        !caps.supports(Capability::Bridge),
        "bridge is off by default even when a vSwitch exists"
    );

    let d = r.decide(&iface());
    assert_eq!(d.admin_status, AdminStatus::RxTx);
    assert_eq!(d.local.port_id.subtype, PortIdSubtype::MacAddress);
    assert_eq!(d.local.port_id.to_string(), "00:1b:21:aa:bb:cc");
    assert_eq!(
        d.local.port_description.as_deref(),
        Some(&b"Ethernet (Intel(R) Ethernet Controller I225-LM)"[..])
    );
    let addrs: Vec<String> = d
        .local
        .management_addresses
        .iter()
        .map(|m| m.address.to_string())
        .collect();
    assert_eq!(
        addrs,
        ["2001:db8:10::5", "10.10.10.50"],
        "GUA first, one slot per family, max 2; temporary, link-local, and tentative skipped"
    );
    assert_eq!(d.local.management_addresses[0].interface_number, 12);
}

#[test]
fn privacy_switches_and_overrides() {
    let mut c = Config::default();
    c.lldp.advertise.system_name_fqdn = false;
    c.lldp.advertise.os_version = false;
    c.lldp.advertise.hardware = true;
    c.lldp.advertise.bridge_capability = true;
    c.lldp.advertise.adapter_description = false;
    c.lldp.advertise.management_address = false;
    c.lldp.chassis_id.source = ChassisIdSource::SmbiosUuid;
    c.lldp.port_id = PortIdSource::InterfaceName;
    let r = ConfigResolver::new(c, facts());
    let s = r.system();
    assert_eq!(
        s.chassis_id.to_string(),
        "00112233-4455-6677-8899-aabbccddeeff"
    );
    assert_eq!(s.system_name.as_deref(), Some(&b"WS-12345"[..]));
    assert_eq!(
        s.system_description.as_deref(),
        Some(&b"Microsoft Windows 11 Enterprise on Dell Inc. Latitude 5550"[..])
    );
    assert!(s.capabilities.unwrap().is_enabled(Capability::Bridge));
    let d = r.decide(&iface());
    assert_eq!(d.local.port_id.subtype, PortIdSubtype::InterfaceName);
    assert_eq!(d.local.port_id.to_string(), "Ethernet");
    assert_eq!(d.local.port_description.as_deref(), Some(&b"Ethernet"[..]));
    assert_eq!(d.local.management_addresses, vec![]);

    let mut c = Config::default();
    c.lldp.system_name_override = Some("kiosk-7".into());
    c.lldp.system_description_override = Some("Managed kiosk".into());
    c.lldp.chassis_id.source = ChassisIdSource::Custom;
    c.lldp.chassis_id.value = Some("ASSET-0042".into());
    c.lldp.advertise.system_capabilities = false;
    let r = ConfigResolver::new(c, facts());
    let s = r.system();
    assert_eq!(s.chassis_id.to_string(), "ASSET-0042");
    assert_eq!(s.system_name.as_deref(), Some(&b"kiosk-7"[..]));
    assert_eq!(s.system_description.as_deref(), Some(&b"Managed kiosk"[..]));
    assert!(s.capabilities.is_none());
}

#[test]
fn management_address_rules() {
    let mut c = Config::default();
    c.lldp.management_addresses.allow_temporary_ipv6 = true;
    c.lldp.management_addresses.allow_link_local = true;
    c.lldp.management_addresses.max_per_interface = 8;
    let addrs: Vec<String> = lldp_config::select_management_addresses(&c, &iface())
        .iter()
        .map(|m| m.address.to_string())
        .collect();
    assert_eq!(
        addrs,
        [
            "2001:db8:10::5",
            "2001:db8:10:0:1234:5678:9abc:def0",
            "fd00::5",
            "10.10.10.50",
            "fe80::1",
            "169.254.1.1"
        ]
    );

    let mut c = Config::default();
    c.lldp.management_addresses.ipv6 = false;
    let addrs: Vec<String> = lldp_config::select_management_addresses(&c, &iface())
        .iter()
        .map(|m| m.address.to_string())
        .collect();
    assert_eq!(addrs, ["10.10.10.50"]);

    // Default limit of two: one slot per family rather than two IPv6.
    let select = |max: usize| -> Vec<String> {
        let mut c = Config::default();
        c.lldp.management_addresses.max_per_interface = max;
        lldp_config::select_management_addresses(&c, &iface())
            .iter()
            .map(|m| m.address.to_string())
            .collect()
    };
    assert_eq!(select(2), ["2001:db8:10::5", "10.10.10.50"]);
    assert_eq!(select(3), ["2001:db8:10::5", "fd00::5", "10.10.10.50"]);
    assert_eq!(select(1), ["2001:db8:10::5"]);

    let mut c = Config::default();
    c.lldp.management_addresses.pinned =
        vec!["192.0.2.1".into(), "not-an-ip".into(), "2001:db8::1".into()];
    let addrs: Vec<String> = lldp_config::select_management_addresses(&c, &iface())
        .iter()
        .map(|m| m.address.to_string())
        .collect();
    assert_eq!(addrs, ["192.0.2.1", "2001:db8::1"]);
}

#[test]
fn interface_without_mac_falls_back_to_name() {
    let r = ConfigResolver::new(Config::default(), facts());
    let mut i = iface();
    i.mac = None;
    let d = r.decide(&i);
    assert_eq!(d.local.port_id.subtype, PortIdSubtype::InterfaceName);
    let mut c = Config::default();
    c.interfaces.default_mode = lldp_config::InterfaceMode::Disabled;
    let r = ConfigResolver::new(c, facts());
    assert_eq!(r.decide(&iface()).admin_status, AdminStatus::Disabled);
    assert_eq!(r.port_config(AdminStatus::RxTx).max_neighbors, 8);
    assert_eq!(r.timers().ttl(), 121);
}

#[test]
fn long_values_are_truncated_on_char_boundaries() {
    let mut f = facts();
    f.fqdn = format!("{}.example", "é".repeat(200)); // 400+ bytes
    let r = ConfigResolver::new(Config::default(), f);
    let name = r.system().system_name.unwrap();
    assert!(name.len() <= 255);
    assert!(std::str::from_utf8(&name).is_ok());
}
