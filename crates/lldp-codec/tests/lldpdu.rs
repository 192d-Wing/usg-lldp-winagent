//! Positive and negative LLDPDU tests (PLAN.MD Sections 3.4 and 17).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::{Ipv4Addr, Ipv6Addr};

use lldp_codec::ethernet::{parse_ethernet, parse_lldp_frame, write_lldp_frame};
use lldp_codec::tlv::{TlvIter, tlv_type, write_tlv};
use lldp_codec::{
    Capability, ChassisId, ChassisIdSubtype, DecodeError, DecodeWarning, EncodeError,
    LldpDestination, Lldpdu, MacAddr, ManagementAddress, NetworkAddress, OrgTlv, PortId,
    PortIdSubtype, SystemCapabilities, Tlv,
};

const SRC: MacAddr = MacAddr([0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]);

fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_tlv(&mut out, t, v).unwrap();
    out
}

fn chassis_mac() -> Vec<u8> {
    tlv(1, &[4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
}
fn port_name() -> Vec<u8> {
    tlv(2, &[5, b'G', b'i', b'1', b'/', b'0', b'/', b'2', b'4'])
}
fn ttl(v: u16) -> Vec<u8> {
    tlv(3, &v.to_be_bytes())
}
fn end() -> Vec<u8> {
    tlv(0, &[])
}

fn minimal() -> Vec<u8> {
    [chassis_mac(), port_name(), ttl(120), end()].concat()
}

fn switch_like() -> Lldpdu {
    let mut pdu = Lldpdu::new(
        ChassisId::mac(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
        PortId::interface_name("GigabitEthernet1/0/24").unwrap(),
        120,
    );
    pdu.optional
        .push(Tlv::PortDescription(b"Workstation Access Port".to_vec()));
    pdu.optional.push(Tlv::SystemName(b"SW-ACCESS-01".to_vec()));
    pdu.optional
        .push(Tlv::SystemDescription(b"Cisco IOS-XE 17.9".to_vec()));
    pdu.optional
        .push(Tlv::SystemCapabilities(SystemCapabilities {
            supported: Capability::Bridge.bit() | Capability::Router.bit(),
            enabled: Capability::Bridge.bit(),
        }));
    pdu.optional
        .push(Tlv::ManagementAddress(ManagementAddress::with_if_index(
            Ipv4Addr::new(10, 10, 10, 1).into(),
            1,
        )));
    pdu.optional
        .push(Tlv::ManagementAddress(ManagementAddress::with_if_index(
            "2001:db8:10::1".parse::<Ipv6Addr>().unwrap().into(),
            1,
        )));
    pdu.optional.push(Tlv::Organizational(OrgTlv {
        oui: lldp_codec::org::oui::IEEE_802_1,
        subtype: 1,
        data: vec![0x00, 0x64],
    }));
    pdu
}

#[test]
fn minimal_lldpdu_decodes() {
    let d = Lldpdu::decode(&minimal()).unwrap();
    assert_eq!(d.lldpdu.chassis_id.subtype, ChassisIdSubtype::MacAddress);
    assert_eq!(d.lldpdu.chassis_id.to_string(), "aa:bb:cc:dd:ee:ff");
    assert_eq!(d.lldpdu.port_id.subtype, PortIdSubtype::InterfaceName);
    assert_eq!(d.lldpdu.port_id.to_string(), "Gi1/0/24");
    assert_eq!(d.lldpdu.ttl, 120);
    assert_eq!(d.lldpdu.optional, vec![]);
    assert_eq!(d.report.warnings, vec![]);
}

#[test]
fn full_roundtrip() {
    let pdu = switch_like();
    let bytes = pdu.encode(1500).unwrap();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu, pdu);
    assert_eq!(d.report.warnings, vec![]);
    assert_eq!(d.lldpdu.system_name(), Some(&b"SW-ACCESS-01"[..]));
    assert_eq!(d.lldpdu.management_addresses().count(), 2);
    let caps = d.lldpdu.system_capabilities().unwrap();
    assert!(caps.is_enabled(Capability::Bridge));
    assert!(!caps.is_enabled(Capability::Router));
    assert!(caps.supports(Capability::Router));
}

#[test]
fn ethernet_frame_roundtrip() {
    let pdu = switch_like().encode(1500).unwrap();
    let mut frame = Vec::new();
    write_lldp_frame(&mut frame, LldpDestination::NearestBridge, SRC, &pdu);
    let (hdr, payload) = parse_lldp_frame(&frame).unwrap();
    assert_eq!(hdr.dst, LldpDestination::NearestBridge.mac());
    assert_eq!(
        LldpDestination::from_mac(hdr.dst),
        Some(LldpDestination::NearestBridge)
    );
    assert_eq!(hdr.src, SRC);
    assert_eq!(hdr.vlan_id, None);
    assert_eq!(payload, &pdu[..]);
}

#[test]
fn vlan_tagged_frame_is_accepted() {
    let pdu = minimal();
    let mut frame = Vec::new();
    frame.extend_from_slice(&LldpDestination::NearestBridge.mac().0);
    frame.extend_from_slice(&SRC.0);
    frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x64, 0x88, 0xcc]);
    frame.extend_from_slice(&pdu);
    let (hdr, payload) = parse_lldp_frame(&frame).unwrap();
    assert_eq!(hdr.vlan_id, Some(100));
    assert_eq!(payload, &pdu[..]);
}

#[test]
fn wrong_ethertype_rejected() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xff; 12]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&minimal());
    assert_eq!(
        parse_lldp_frame(&frame),
        Err(DecodeError::WrongEtherType { ethertype: 0x0800 })
    );
}

#[test]
fn truncated_frames_rejected() {
    for len in 0..14 {
        let frame = vec![0u8; len];
        assert!(
            matches!(
                parse_ethernet(&frame),
                Err(DecodeError::TruncatedFrame { .. })
            ),
            "len {len}"
        );
    }
    // Tagged header cut inside the tag.
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x81, 0x00, 0x00]);
    assert!(matches!(
        parse_ethernet(&frame),
        Err(DecodeError::TruncatedFrame { .. })
    ));
}

#[test]
fn padding_after_end_is_reported_not_fatal() {
    let mut bytes = minimal();
    bytes.extend_from_slice(&[0u8; 20]);
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(
        d.report.warnings,
        vec![DecodeWarning::TrailingData { len: 20 }]
    );
}

#[test]
fn missing_end_tlv_is_warning() {
    let bytes = [chassis_mac(), port_name(), ttl(120)].concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.report.warnings, vec![DecodeWarning::MissingEndTlv]);
}

#[test]
fn end_tlv_with_length_is_warning() {
    let bytes = [chassis_mac(), port_name(), ttl(120), tlv(0, &[1, 2])].concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert!(
        d.report
            .warnings
            .contains(&DecodeWarning::EndTlvNonZeroLength { len: 2 })
    );
}

#[test]
fn empty_lldpdu_rejected() {
    assert_eq!(Lldpdu::decode(&[]), Err(DecodeError::Empty));
}

#[test]
fn missing_mandatory_tlvs_rejected() {
    assert_eq!(
        Lldpdu::decode(&end()),
        Err(DecodeError::MissingMandatoryTlv { expected: 1 })
    );
    assert_eq!(
        Lldpdu::decode(&[chassis_mac(), end()].concat()),
        Err(DecodeError::MissingMandatoryTlv { expected: 2 })
    );
    assert_eq!(
        Lldpdu::decode(&[chassis_mac(), port_name()].concat()),
        Err(DecodeError::MissingMandatoryTlv { expected: 3 })
    );
}

#[test]
fn wrong_mandatory_order_rejected() {
    assert_eq!(
        Lldpdu::decode(&[port_name(), chassis_mac(), ttl(1), end()].concat()),
        Err(DecodeError::MandatoryTlvOrder {
            position: 0,
            found: 2
        })
    );
    assert_eq!(
        Lldpdu::decode(&[chassis_mac(), ttl(1), port_name(), end()].concat()),
        Err(DecodeError::MandatoryTlvOrder {
            position: 1,
            found: 3
        })
    );
    assert_eq!(
        Lldpdu::decode(&[chassis_mac(), port_name(), tlv(5, b"x"), ttl(1), end()].concat()),
        Err(DecodeError::MandatoryTlvOrder {
            position: 2,
            found: 5
        })
    );
}

#[test]
fn duplicate_mandatory_rejected() {
    for dup in [chassis_mac(), port_name(), ttl(5)] {
        let t = dup[0] >> 1;
        let bytes = [chassis_mac(), port_name(), ttl(120), dup, end()].concat();
        assert_eq!(
            Lldpdu::decode(&bytes),
            Err(DecodeError::DuplicateMandatoryTlv { tlv_type: t })
        );
    }
}

#[test]
fn bad_tlv_lengths_rejected() {
    // Declared length runs past the end.
    let mut bytes = [chassis_mac(), port_name(), ttl(120)].concat();
    bytes.extend_from_slice(&[(5 << 1), 0x10, b'a']);
    assert!(matches!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::TruncatedTlv {
            declared: 16,
            remaining: 1,
            ..
        })
    ));
    // Single trailing header octet.
    let mut bytes = [chassis_mac(), port_name(), ttl(120)].concat();
    bytes.push(0x0a);
    assert!(matches!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::TruncatedTlvHeader { .. })
    ));
    // Chassis ID with only a subtype.
    let bytes = [tlv(1, &[4]), port_name(), ttl(1), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidMandatoryTlvLength {
            tlv_type: 1,
            len: 1
        })
    );
    // Chassis ID empty.
    let bytes = [tlv(1, &[]), port_name(), ttl(1), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidMandatoryTlvLength {
            tlv_type: 1,
            len: 0
        })
    );
    // Chassis ID longer than 256 (subtype + 255).
    let big = [vec![7u8], vec![b'a'; 256]].concat();
    let bytes = [tlv(1, &big), port_name(), ttl(1), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidIdentifier {
            tlv_type: 1,
            subtype: 7,
            len: 256
        })
    );
    // TTL wrong length.
    let bytes = [chassis_mac(), port_name(), tlv(3, &[1]), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidMandatoryTlvLength {
            tlv_type: 3,
            len: 1
        })
    );
    let bytes = [chassis_mac(), port_name(), tlv(3, &[0, 0, 0]), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidMandatoryTlvLength {
            tlv_type: 3,
            len: 3
        })
    );
}

#[test]
fn invalid_identifiers_rejected() {
    // MAC subtype with 5 octets.
    let bytes = [tlv(1, &[4, 1, 2, 3, 4, 5]), port_name(), ttl(1), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidIdentifier {
            tlv_type: 1,
            subtype: 4,
            len: 5
        })
    );
    // Port ID MAC subtype with 7 octets.
    let bytes = [
        chassis_mac(),
        tlv(2, &[3, 1, 2, 3, 4, 5, 6, 7]),
        ttl(1),
        end(),
    ]
    .concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidIdentifier {
            tlv_type: 2,
            subtype: 3,
            len: 7
        })
    );
    // Network address subtype with IPv4 family but 3 octets.
    let bytes = [tlv(1, &[5, 1, 10, 0, 0]), port_name(), ttl(1), end()].concat();
    assert_eq!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::InvalidIdentifier {
            tlv_type: 1,
            subtype: 5,
            len: 4
        })
    );
    // Reserved subtype with a value is accepted (not our business to reject).
    let bytes = [tlv(1, &[200, 1, 2]), port_name(), ttl(1), end()].concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.chassis_id.subtype, ChassisIdSubtype::Reserved(200));
}

#[test]
fn zero_ttl_and_max_ttl_decode() {
    let d = Lldpdu::decode(&[chassis_mac(), port_name(), ttl(0), end()].concat()).unwrap();
    assert_eq!(d.lldpdu.ttl, 0);
    let d = Lldpdu::decode(&[chassis_mac(), port_name(), ttl(65535), end()].concat()).unwrap();
    assert_eq!(d.lldpdu.ttl, 65535);
}

#[test]
fn unknown_tlvs_preserved_and_counted() {
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(42, &[1, 2, 3]),
        tlv(126, &[]),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.report.tlvs_unrecognized, 2);
    assert_eq!(
        d.lldpdu.optional[0],
        Tlv::Unknown {
            tlv_type: 42,
            value: vec![1, 2, 3]
        }
    );
    assert_eq!(
        d.lldpdu.optional[1],
        Tlv::Unknown {
            tlv_type: 126,
            value: vec![]
        }
    );
    // And they survive re-encoding.
    assert_eq!(d.lldpdu.encode(1500).unwrap(), bytes);
}

#[test]
fn duplicate_optional_keeps_first() {
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(5, b"first"),
        tlv(5, b"second"),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.system_name(), Some(&b"first"[..]));
    assert_eq!(d.report.tlvs_discarded, 1);
    assert!(matches!(
        d.report.warnings[0],
        DecodeWarning::DuplicateOptionalTlv { tlv_type: 5, .. }
    ));
}

#[test]
fn overlong_string_tlv_discarded() {
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(6, &[b'x'; 300]),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.system_description(), None);
    assert_eq!(d.report.tlvs_discarded, 1);
}

#[test]
fn invalid_capabilities_discarded() {
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(7, &[0, 4, 0]),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.system_capabilities(), None);
    assert_eq!(d.report.tlvs_discarded, 1);
}

#[test]
fn management_address_edge_cases() {
    // Valid IPv6 with ifIndex and empty OID.
    let good = ManagementAddress::with_if_index("fe80::1".parse::<Ipv6Addr>().unwrap().into(), 12);
    let mut v = Vec::new();
    good.write(&mut v).unwrap();
    assert_eq!(ManagementAddress::parse(&v).unwrap(), good);
    // Address length field says 5 but only 4 follow -> invalid.
    assert!(ManagementAddress::parse(&[5, 1, 10, 0, 0]).is_none());
    // Address length 0 -> invalid.
    assert!(ManagementAddress::parse(&[0, 2, 0, 0, 0, 0, 0, 0]).is_none());
    // IPv4 family with IPv6 length -> invalid.
    let mut bad = vec![17, 1];
    bad.extend_from_slice(&[0; 16]);
    bad.extend_from_slice(&[2, 0, 0, 0, 1, 0]);
    assert!(ManagementAddress::parse(&bad).is_none());
    // OID length mismatch -> invalid.
    assert!(ManagementAddress::parse(&[5, 1, 10, 0, 0, 1, 2, 0, 0, 0, 1, 3, 1]).is_none());
    // Other family, 2 octets, accepted and displayed as hex.
    let other = ManagementAddress::parse(&[3, 6, 0xab, 0xcd, 1, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        other.address,
        NetworkAddress::Other {
            family: 6,
            octets: vec![0xab, 0xcd]
        }
    );
    assert_eq!(other.address.to_string(), "afn6:abcd");
    // In an LLDPDU, a bad management address is discarded but the PDU survives.
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(8, &[5, 1, 10, 0, 0]),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.management_addresses().count(), 0);
    assert_eq!(d.report.tlvs_discarded, 1);
}

#[test]
fn org_tlv_too_short_discarded() {
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(127, &[0, 0x80, 0xc2]),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.organizational().count(), 0);
    assert_eq!(d.report.tlvs_discarded, 1);
    // Exactly 4 octets (no data) is valid.
    let bytes = [
        chassis_mac(),
        port_name(),
        ttl(1),
        tlv(127, &[0, 0x80, 0xc2, 9]),
        end(),
    ]
    .concat();
    let d = Lldpdu::decode(&bytes).unwrap();
    assert_eq!(d.lldpdu.organizational().next().unwrap().subtype, 9);
}

#[test]
fn max_length_tlv_roundtrips() {
    let big = OrgTlv {
        oui: [1, 2, 3],
        subtype: 4,
        data: vec![0xaa; 507],
    };
    let mut pdu = switch_like();
    pdu.optional.push(Tlv::Organizational(big));
    let bytes = pdu.encode(9216).unwrap();
    assert_eq!(Lldpdu::decode(&bytes).unwrap().lldpdu, pdu);
    // 508 octets of data cannot be represented.
    let too_big = OrgTlv {
        oui: [1, 2, 3],
        subtype: 4,
        data: vec![0; 508],
    };
    let mut pdu = switch_like();
    pdu.optional.push(Tlv::Organizational(too_big));
    assert!(matches!(
        pdu.encode(9216),
        Err(EncodeError::ValueTooLong {
            tlv_type: 127,
            len: 512
        })
    ));
}

#[test]
fn encode_respects_limit() {
    let pdu = switch_like();
    let len = pdu.encode(1500).unwrap().len();
    assert!(matches!(
        pdu.encode(len - 1),
        Err(EncodeError::LldpduTooLarge { .. })
    ));
    assert!(pdu.encode(len).is_ok());
}

#[test]
fn encode_rejects_invalid_values() {
    let pdu = Lldpdu::new(
        ChassisId {
            subtype: ChassisIdSubtype::LocallyAssigned,
            value: vec![],
        },
        PortId::mac(SRC),
        1,
    );
    assert!(matches!(
        pdu.encode(1500),
        Err(EncodeError::InvalidValue(_))
    ));
    assert!(ChassisId::locally_assigned("").is_none());
    assert!(ChassisId::locally_assigned(&"a".repeat(256)).is_none());
    assert!(ChassisId::locally_assigned(&"a".repeat(255)).is_some());
    let mut pdu = Lldpdu::new(ChassisId::mac(SRC), PortId::mac(SRC), 1);
    pdu.optional.push(Tlv::SystemName(vec![b'n'; 256]));
    assert!(matches!(
        pdu.encode(1500),
        Err(EncodeError::ValueTooLong {
            tlv_type: 5,
            len: 256
        })
    ));
}

#[test]
fn oversized_lldpdu_rejected() {
    let bytes = vec![0u8; lldp_codec::MAX_LLDPDU_LEN + 1];
    assert!(matches!(
        Lldpdu::decode(&bytes),
        Err(DecodeError::LldpduTooLarge { .. })
    ));
}

#[test]
fn tlv_iter_stops_after_error() {
    let mut it = TlvIter::new(&[0x0a, 0x05, 1, 2]);
    assert!(it.next().unwrap().is_err());
    assert!(it.next().is_none());
}

#[test]
fn tlv_type_constants_match_wire() {
    assert_eq!(tlv_type::END, 0);
    assert_eq!(tlv_type::ORGANIZATIONAL, 127);
    assert_eq!(tlv(127, &[])[0], 0xfe);
}

#[test]
fn capabilities_short_names() {
    let caps = SystemCapabilities {
        supported: 0xffff,
        enabled: Capability::Bridge.bit() | Capability::StationOnly.bit(),
    };
    let names: String = caps.enabled_iter().map(Capability::short_name).collect();
    assert_eq!(names, "BS");
    assert_eq!(SystemCapabilities::STATION_ONLY.enabled_iter().count(), 1);
}

#[test]
fn lossy_text_rendering() {
    assert_eq!(lldp_codec::types::lossy_text(b"Gi1/0/1"), "Gi1/0/1");
    assert_eq!(lldp_codec::types::lossy_text(&[0x00, 0xff]), "00:ff");
    assert_eq!(lldp_codec::types::lossy_text(b"a\x01b"), "61:01:62");
}
