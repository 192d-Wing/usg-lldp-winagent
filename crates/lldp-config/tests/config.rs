//! Configuration parsing, validation, and resolution tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use lldp_config::{
    Config, ConfigError, InterfaceKind, InterfaceMode, PolicyOverrides, SCHEMA_VERSION,
};
use lldp_core::AdminStatus;

#[test]
fn minimal_file_is_default() {
    let c = Config::from_yaml("version: 1\n").unwrap();
    assert_eq!(c, Config::default());
    assert_eq!(c.lldp.timer_params().ttl(), 121);
}

#[test]
fn example_file_equals_defaults() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/config.yaml"
    ))
    .unwrap();
    let c = Config::from_yaml(&text).unwrap();
    assert_eq!(
        c,
        Config::default(),
        "examples/config.yaml must document the defaults"
    );
}

#[test]
fn yaml_roundtrip() {
    let c = Config::default();
    let text = c.to_yaml().unwrap();
    assert_eq!(Config::from_yaml(&text).unwrap(), c);
}

#[test]
fn unknown_field_is_an_error() {
    let e = Config::from_yaml("version: 1\nlldp:\n  transmit_intervall: 30\n").unwrap_err();
    assert!(
        matches!(e, ConfigError::Parse(ref m) if m.contains("transmit_intervall")),
        "{e}"
    );
}

#[test]
fn wrong_version_rejected() {
    assert_eq!(
        Config::from_yaml("version: 2\n").unwrap_err(),
        ConfigError::UnsupportedVersion {
            found: 2,
            supported: SCHEMA_VERSION
        }
    );
    assert!(matches!(
        Config::from_yaml("agent: {}\n").unwrap_err(),
        ConfigError::Parse(_)
    ));
}

#[test]
fn range_violations_are_collected_with_paths() {
    let text = "version: 1\nlldp:\n  transmit_interval: 0\n  max_neighbors_per_interface: 100\n  chassis_id:\n    source: custom\nlogging:\n  event_rate_limit_per_minute: 0\n";
    let ConfigError::Invalid(v) = Config::from_yaml(text).unwrap_err() else {
        panic!()
    };
    let paths: Vec<&str> = v.iter().map(|x| x.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "lldp.transmit_interval",
            "lldp.max_neighbors_per_interface",
            "lldp.chassis_id.value",
            "logging.event_rate_limit_per_minute"
        ]
    );
    assert!(v[0].message.contains("1 to 3600"));
}

#[test]
fn custom_chassis_value_rules() {
    assert!(
        Config::from_yaml("version: 1\nlldp:\n  chassis_id: {source: custom, value: WS-1}\n")
            .is_ok()
    );
    assert!(
        Config::from_yaml("version: 1\nlldp:\n  chassis_id: {source: hostname, value: WS-1}\n")
            .is_err()
    );
    assert!(
        Config::from_yaml("version: 1\nlldp:\n  chassis_id: {source: custom, value: ''}\n")
            .is_err()
    );
}

#[test]
fn interface_resolution() {
    let text = r#"
version: 1
interfaces:
  default_mode: rx_tx
  wifi: rx_only
  exclude: ["vEthernet*"]
  overrides:
    - match: "Ethernet 2"
      mode: tx_only
      port_description: "Bench"
    - match: "guid:{AAAAAAAA-0000-0000-0000-000000000000}"
      mode: disabled
    - match: "Dock*"
      port_description: "Dock port"
"#;
    let c = Config::from_yaml(text).unwrap();
    let r = c.resolve_interface("Ethernet", "{1}", InterfaceKind::PhysicalEthernet);
    assert_eq!(r.mode, InterfaceMode::RxTx);
    assert_eq!(r.matched_override, None);
    let r = c.resolve_interface("Ethernet 2", "{1}", InterfaceKind::PhysicalEthernet);
    assert_eq!(
        (r.mode, r.port_description.as_deref(), r.matched_override),
        (InterfaceMode::TxOnly, Some("Bench"), Some(0))
    );
    let r = c.resolve_interface(
        "Whatever",
        "aaaaaaaa-0000-0000-0000-000000000000",
        InterfaceKind::PhysicalEthernet,
    );
    assert_eq!(r.mode, InterfaceMode::Disabled);
    assert_eq!(r.matched_override, Some(1));
    let r = c.resolve_interface("Dock Ethernet", "{2}", InterfaceKind::PhysicalEthernet);
    assert_eq!(
        (r.mode, r.port_description.as_deref()),
        (InterfaceMode::RxTx, Some("Dock port"))
    );
    assert_eq!(
        c.resolve_interface("vEthernet (WSL)", "{3}", InterfaceKind::Virtual)
            .mode,
        InterfaceMode::Disabled
    );
    assert_eq!(
        c.resolve_interface("Wi-Fi", "{4}", InterfaceKind::Wifi)
            .mode,
        InterfaceMode::RxOnly
    );
    assert_eq!(
        c.resolve_interface("Tunnel", "{5}", InterfaceKind::Other)
            .mode,
        InterfaceMode::Disabled
    );
    assert_eq!(
        AdminStatus::from(InterfaceMode::TxOnly),
        AdminStatus::TxOnly
    );
}

#[test]
fn policy_wins() {
    let mut c = Config::default();
    c.apply_policy(&PolicyOverrides {
        enabled: Some(false),
        default_mode: Some(InterfaceMode::RxOnly),
        advertise_fqdn: Some(false),
        advertise_os_version: None,
        advertise_hardware: Some(true),
        advertise_management_address: Some(false),
    });
    assert!(!c.agent.enabled);
    assert_eq!(c.interfaces.default_mode, InterfaceMode::RxOnly);
    assert!(!c.lldp.advertise.system_name_fqdn);
    assert!(c.lldp.advertise.os_version);
    assert!(c.lldp.advertise.hardware);
    assert!(!c.lldp.advertise.management_address);
    // Disabled agent forces every interface off regardless of matching.
    assert_eq!(
        c.resolve_interface("Ethernet", "{1}", InterfaceKind::PhysicalEthernet)
            .mode,
        InterfaceMode::Disabled
    );
}

#[test]
fn ipc_read_group_must_be_a_sid_or_sddl_alias() {
    for ok in [
        "S-1-5-11",
        "S-1-5-32-545",
        "AU",
        "BU",
        "S-1-5-21-1-2-3-513",
        "",
    ] {
        let text = format!("version: 1\nipc:\n  read_group: \"{ok}\"\n");
        assert!(Config::from_yaml(&text).is_ok(), "{ok}");
    }
    for bad in [
        "Authenticated Users",
        "S-1-5-",
        "S-1",
        "AU)(A;;GA;;;WD",
        "au",
        "S-1-5-11;",
    ] {
        let text = format!("version: 1\nipc:\n  read_group: \"{bad}\"\n");
        let ConfigError::Invalid(v) = Config::from_yaml(&text).unwrap_err() else {
            panic!("{bad}")
        };
        assert_eq!(v[0].path, "ipc.read_group", "{bad}");
    }
}

#[test]
fn pinned_management_addresses_must_parse() {
    let text = "version: 1\nlldp:\n  management_addresses:\n    pinned: [\"10.0.0.1\", \"fd00::1\", \"not-an-address\"]\n";
    let ConfigError::Invalid(v) = Config::from_yaml(text).unwrap_err() else {
        panic!()
    };
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].path, "lldp.management_addresses.pinned[2]");
}
