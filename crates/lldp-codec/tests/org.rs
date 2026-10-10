//! Organizationally specific TLV decoder tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use lldp_codec::org::ieee8021::{Ieee8021Tlv, LinkAggregation};
use lldp_codec::org::ieee8023::{Ieee8023Tlv, MacPhyConfigStatus, PowerDll, PowerViaMdi};
use lldp_codec::org::med::{MedDeviceType, MedLocation, MedTlv, capability};
use lldp_codec::org::oui;
use lldp_codec::{DecodedOrgTlv, OrgTlv};

fn org(o: [u8; 3], st: u8, d: &[u8]) -> OrgTlv {
    OrgTlv {
        oui: o,
        subtype: st,
        data: d.to_vec(),
    }
}

#[test]
fn ieee8021_decode_and_roundtrip() {
    let cases = vec![
        Ieee8021Tlv::PortVlanId(100),
        Ieee8021Tlv::PortAndProtocolVlanId {
            supported: true,
            enabled: false,
            ppvid: 200,
        },
        Ieee8021Tlv::VlanName {
            vid: 100,
            name: b"Workstations".to_vec(),
        },
        Ieee8021Tlv::VlanName {
            vid: 1,
            name: vec![],
        },
        Ieee8021Tlv::ProtocolIdentity(vec![0x88, 0x8e, 0x01]),
        Ieee8021Tlv::VidUsageDigest(0xdead_beef),
        Ieee8021Tlv::ManagementVid(99),
        Ieee8021Tlv::LinkAggregation(LinkAggregation {
            capable: true,
            aggregated: true,
            aggregated_port_id: 5001,
        }),
    ];
    for c in cases {
        let raw = c.to_org_tlv().unwrap();
        assert_eq!(raw.oui, oui::IEEE_802_1);
        assert_eq!(raw.decode(), DecodedOrgTlv::Ieee8021(c.clone()), "{c:?}");
    }
    // Wire example: PVID 100 as sent by a switch.
    let raw = org(oui::IEEE_802_1, 1, &[0x00, 0x64]);
    assert_eq!(
        raw.decode(),
        DecodedOrgTlv::Ieee8021(Ieee8021Tlv::PortVlanId(100))
    );
}

#[test]
fn ieee8021_malformed_is_unrecognized() {
    let bad = [
        org(oui::IEEE_802_1, 1, &[0x00]),
        org(oui::IEEE_802_1, 1, &[0, 0, 0]),
        org(oui::IEEE_802_1, 2, &[0, 0]),
        org(oui::IEEE_802_1, 3, &[0, 1, 5, b'a']),
        org(oui::IEEE_802_1, 3, &[0, 1, 33, b'a']),
        org(oui::IEEE_802_1, 4, &[2, 1]),
        // 802.1Q-2022 D.2.2.3: enabled but not supported, and PPVID > 4094.
        org(oui::IEEE_802_1, 2, &[0x04, 0, 5]),
        org(oui::IEEE_802_1, 2, &[0x06, 0x0f, 0xff]),
        org(oui::IEEE_802_1, 5, &[1, 2, 3]),
        org(oui::IEEE_802_1, 7, &[1, 0, 0, 0]),
        org(oui::IEEE_802_1, 99, &[]),
    ];
    for b in &bad {
        assert!(
            matches!(b.decode(), DecodedOrgTlv::Unrecognized(_)),
            "{b:?}"
        );
    }
    assert!(
        Ieee8021Tlv::VlanName {
            vid: 1,
            name: vec![b'x'; 33]
        }
        .to_org_tlv()
        .is_none()
    );
    assert!(Ieee8021Tlv::ProtocolIdentity(vec![]).to_org_tlv().is_none());
    // PPVID 4094 with both flags is the largest valid value.
    assert_eq!(
        Ieee8021Tlv::decode(2, &[0x06, 0x0f, 0xfe]),
        Some(Ieee8021Tlv::PortAndProtocolVlanId {
            supported: true,
            enabled: true,
            ppvid: 4094
        })
    );
}

#[test]
fn power_via_mdi_type_source_priority_bits() {
    // 802.3-2022 Table 79-7: type in bits 7:6, source in 5:4, bit 3
    // reserved, PD 4PID in bit 2, priority in 1:0.
    let p = PowerViaMdi::parse(&[0x00, 1, 5, 0b0101_0110, 0, 130, 0, 125]).unwrap();
    let d = p.dll.unwrap();
    assert_eq!((d.power_type, d.power_source, d.power_priority), (1, 1, 2));
    assert!(d.pd_4pid);
    assert_eq!((d.pd_requested_power, d.pse_allocated_power), (130, 125));
    let mut out = Vec::new();
    p.write(&mut out);
    assert_eq!(out, [0x00, 1, 5, 0b0101_0110, 0, 130, 0, 125]);
    // The reserved bit is ignored on receive.
    let d = PowerViaMdi::parse(&[0x0f, 1, 5, 0b0001_1011, 0, 0, 1, 44]).unwrap();
    assert_eq!(d.dll.unwrap().power_priority, 3);
    assert!(!d.dll.unwrap().pd_4pid);
    // A Type 3 or Type 4 TLV (29-octet string, 25 here) keeps its extension raw.
    let mut long = vec![0x0f, 1, 5, 0b0001_0011, 0, 0, 1, 44];
    long.extend_from_slice(&[0xab; 17]);
    assert_eq!(PowerViaMdi::parse(&long).unwrap().extension, vec![0xab; 17]);
}

#[test]
fn ieee8023_decode_and_roundtrip() {
    let cases = vec![
        Ieee8023Tlv::MacPhyConfigStatus(MacPhyConfigStatus {
            autoneg_supported: true,
            autoneg_enabled: true,
            pmd_autoneg_advertised: 0x6c01,
            operational_mau_type: 30,
        }),
        Ieee8023Tlv::PowerViaMdi(PowerViaMdi {
            port_class_pse: true,
            pse_mdi_power_supported: true,
            pse_mdi_power_enabled: true,
            pse_pairs_controllable: false,
            pse_power_pair: 1,
            power_class: 1,
            dll: None,
            extension: vec![],
        }),
        Ieee8023Tlv::PowerViaMdi(PowerViaMdi {
            port_class_pse: true,
            pse_mdi_power_supported: true,
            pse_mdi_power_enabled: true,
            pse_pairs_controllable: false,
            pse_power_pair: 1,
            power_class: 4,
            dll: Some(PowerDll {
                power_type: 0,
                power_source: 1,
                power_priority: 3,
                pd_4pid: false,
                pd_requested_power: 130,
                pse_allocated_power: 130,
            }),
            extension: vec![1, 2, 3],
        }),
        Ieee8023Tlv::LinkAggregation(LinkAggregation {
            capable: true,
            aggregated: false,
            aggregated_port_id: 0,
        }),
        Ieee8023Tlv::MaximumFrameSize(9216),
        Ieee8023Tlv::Eee {
            transmit_tw: 17,
            receive_tw: 17,
            fallback_tw: 0,
            echo_transmit_tw: 17,
            echo_receive_tw: 17,
        },
    ];
    for c in cases {
        let raw = c.to_org_tlv();
        assert_eq!(raw.oui, oui::IEEE_802_3);
        assert_eq!(raw.decode(), DecodedOrgTlv::Ieee8023(c.clone()), "{c:?}");
    }
    // Wire example: MAC/PHY from a gigabit switch port, 1000BASE-T FD (MAU 30).
    let raw = org(oui::IEEE_802_3, 1, &[0x03, 0x6c, 0x01, 0x00, 0x1e]);
    match raw.decode() {
        DecodedOrgTlv::Ieee8023(Ieee8023Tlv::MacPhyConfigStatus(m)) => {
            assert!(m.autoneg_enabled);
            assert_eq!(m.operational_mau_type, 30);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn ieee8023_malformed_is_unrecognized() {
    let bad = [
        org(oui::IEEE_802_3, 1, &[3, 0, 0, 0]),
        org(oui::IEEE_802_3, 2, &[1, 1]),
        org(oui::IEEE_802_3, 2, &[1, 1, 1, 0]),
        org(oui::IEEE_802_3, 3, &[1]),
        org(oui::IEEE_802_3, 4, &[0x24]),
        org(oui::IEEE_802_3, 5, &[0; 9]),
        org(oui::IEEE_802_3, 6, &[0; 9]),
    ];
    for b in &bad {
        assert!(
            matches!(b.decode(), DecodedOrgTlv::Unrecognized(_)),
            "{b:?}"
        );
    }
}

#[test]
fn med_decode_and_roundtrip() {
    let cases = vec![
        MedTlv::Capabilities {
            capabilities: capability::CAPABILITIES
                | capability::NETWORK_POLICY
                | capability::INVENTORY,
            device_type: MedDeviceType::NetworkConnectivity,
        },
        MedTlv::NetworkPolicy {
            application_type: 1,
            unknown: false,
            tagged: true,
            vlan_id: 4094,
            l2_priority: 5,
            dscp: 46,
        },
        MedTlv::NetworkPolicy {
            application_type: 2,
            unknown: true,
            tagged: false,
            vlan_id: 0,
            l2_priority: 0,
            dscp: 0,
        },
        MedTlv::Location(MedLocation::Elin(b"5551234567".to_vec())),
        MedTlv::Location(MedLocation::Civic(vec![0x11; 20])),
        MedTlv::Location(MedLocation::Other {
            format: 9,
            data: vec![1],
        }),
        MedTlv::ExtendedPower {
            power_type: 0,
            power_source: 1,
            power_priority: 2,
            power_value: 130,
        },
        MedTlv::HardwareRevision(b"V01".to_vec()),
        MedTlv::FirmwareRevision(b"1.0".to_vec()),
        MedTlv::SoftwareRevision(b"17.9.4a".to_vec()),
        MedTlv::SerialNumber(b"FOC1234ABCD".to_vec()),
        MedTlv::ManufacturerName(b"Cisco".to_vec()),
        MedTlv::ModelName(b"C9300-48P".to_vec()),
        MedTlv::AssetId(vec![]),
    ];
    for c in cases {
        let raw = c.to_org_tlv().unwrap();
        assert_eq!(raw.oui, oui::TIA_MED);
        assert_eq!(raw.decode(), DecodedOrgTlv::Med(c.clone()), "{c:?}");
    }
    // Wire example: voice policy, tagged, VLAN 100, priority 5, DSCP 46.
    // b1 = T(0x40) | vlan>>7 (0) ; b2 = (100 & 0x7f)<<1 | prio>>2 = 0xc8 | 1 ; b3 = (5&3)<<6 | 46 = 0x40|0x2e
    let raw = org(oui::TIA_MED, 2, &[1, 0x40, 0xc9, 0x6e]);
    assert_eq!(
        raw.decode(),
        DecodedOrgTlv::Med(MedTlv::NetworkPolicy {
            application_type: 1,
            unknown: false,
            tagged: true,
            vlan_id: 100,
            l2_priority: 5,
            dscp: 46
        })
    );
}

#[test]
fn med_malformed_is_unrecognized() {
    let bad = [
        org(oui::TIA_MED, 1, &[0, 1]),
        org(oui::TIA_MED, 2, &[1, 0, 0]),
        org(oui::TIA_MED, 3, &[]),
        org(oui::TIA_MED, 4, &[0, 0]),
        org(oui::TIA_MED, 8, &[b'x'; 33]),
        org(oui::TIA_MED, 12, &[]),
    ];
    for b in &bad {
        assert!(
            matches!(b.decode(), DecodedOrgTlv::Unrecognized(_)),
            "{b:?}"
        );
    }
    assert!(
        MedTlv::NetworkPolicy {
            application_type: 1,
            unknown: false,
            tagged: false,
            vlan_id: 4096,
            l2_priority: 0,
            dscp: 0
        }
        .to_org_tlv()
        .is_none()
    );
    assert!(MedTlv::SerialNumber(vec![0; 33]).to_org_tlv().is_none());
}

#[test]
fn unknown_oui_is_preserved() {
    let cisco = org([0x00, 0x00, 0x0c], 1, &[0x01]);
    assert_eq!(cisco.decode(), DecodedOrgTlv::Unknown(&cisco));
}
