//! Protocol, framing, and dispatch tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::Ipv4Addr;

use lldp_codec::{ChassisId, Lldpdu, MacAddr, ManagementAddress, PortId, SystemCapabilities, Tlv};
use lldp_ipc::{
    Caller, ErrorCode, Handler, HandlerFuture, InterfaceModeView, LldpduView, MAX_MESSAGE_LEN,
    Request, RequestEnvelope, Response, call, dispatch, read_message, serve_connection,
    write_message,
};
use serde_json::{Value, json};

struct Echo;

impl Handler for Echo {
    fn handle(&self, request: Request, caller: Caller) -> HandlerFuture<'_> {
        Box::pin(async move { Ok(json!({"op": request.name(), "admin": caller.is_admin})) })
    }
}

#[test]
fn request_wire_shape() {
    let env = RequestEnvelope::new(Request::ListNeighbors {
        interface: Some("Ethernet".into()),
    });
    let v: Value = serde_json::to_value(&env).unwrap();
    assert_eq!(
        v,
        json!({"v": 1, "op": "ListNeighbors", "params": {"interface": "Ethernet"}})
    );
    let env2: RequestEnvelope = serde_json::from_str(r#"{"v":1,"op":"GetServiceStatus"}"#).unwrap();
    assert_eq!(env2.request, Request::GetServiceStatus);
    let env3: RequestEnvelope = serde_json::from_str(
        r#"{"v":1,"op":"SetInterfaceMode","params":{"interface":"Ethernet","mode":"rx_only"}}"#,
    )
    .unwrap();
    assert_eq!(
        env3.request,
        Request::SetInterfaceMode {
            interface: "Ethernet".into(),
            mode: InterfaceModeView::RxOnly
        }
    );
    assert!(serde_json::from_str::<RequestEnvelope>(r#"{"v":1,"op":"Nope"}"#).is_err());
    assert!(
        serde_json::from_str::<RequestEnvelope>(r#"{"v":1,"op":"GetServiceStatus","extra":1}"#)
            .is_err()
    );
}

#[test]
fn response_wire_shape() {
    let ok = Response::ok(&json!({"a": 1}));
    assert_eq!(
        serde_json::to_value(&ok).unwrap(),
        json!({"v": 1, "ok": true, "result": {"a": 1}})
    );
    let err = Response::err(lldp_ipc::IpcError::new(ErrorCode::Forbidden, "no"));
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({"v": 1, "ok": false, "error": {"code": "forbidden", "message": "no"}})
    );
    let r: Result<Value, _> = err.into_result();
    assert_eq!(r.unwrap_err().code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn dispatch_enforces_version_and_admin() {
    let h = Echo;
    let user = Caller { is_admin: false };
    let admin = Caller { is_admin: true };
    let r = dispatch(&h, br#"{"v":1,"op":"GetServiceStatus"}"#, user).await;
    assert!(r.ok);
    assert_eq!(r.result.unwrap()["admin"], json!(false));
    let r = dispatch(&h, br#"{"v":2,"op":"GetServiceStatus"}"#, user).await;
    assert_eq!(r.error.unwrap().code, ErrorCode::UnsupportedVersion);
    let r = dispatch(&h, br#"{"v":1,"op":"ReloadConfiguration"}"#, user).await;
    assert_eq!(r.error.unwrap().code, ErrorCode::Forbidden);
    let r = dispatch(&h, br#"{"v":1,"op":"ReloadConfiguration"}"#, admin).await;
    assert!(r.ok);
    let r = dispatch(&h, b"not json", user).await;
    assert_eq!(r.error.unwrap().code, ErrorCode::BadRequest);
}

#[tokio::test]
async fn framing_roundtrip_and_limits() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    write_message(&mut a, b"hello").await.unwrap();
    assert_eq!(read_message(&mut b).await.unwrap().unwrap(), b"hello");
    drop(a);
    assert!(read_message(&mut b).await.unwrap().is_none());

    let (mut a, mut b) = tokio::io::duplex(4096);
    assert!(write_message(&mut a, &[]).await.is_err());
    assert!(
        write_message(&mut a, &vec![0u8; MAX_MESSAGE_LEN + 1])
            .await
            .is_err()
    );
    // A hostile length prefix is rejected without allocating.
    tokio::io::AsyncWriteExt::write_all(&mut a, &[0xff, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    let e = read_message(&mut b).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn serve_and_call_over_duplex() {
    let (server, mut client) = tokio::io::duplex(65536);
    let task =
        tokio::spawn(
            async move { serve_connection(server, &Echo, Caller { is_admin: false }).await },
        );
    let r = call(&mut client, Request::ListInterfaces).await.unwrap();
    assert_eq!(r.result.unwrap()["op"], json!("ListInterfaces"));
    let r = call(&mut client, Request::ReloadConfiguration)
        .await
        .unwrap();
    assert_eq!(r.error.unwrap().code, ErrorCode::Forbidden);
    drop(client);
    task.await.unwrap().unwrap();
}

#[test]
fn lldpdu_view_covers_all_tlvs() {
    let mut pdu = Lldpdu::new(
        ChassisId::mac(MacAddr([1, 2, 3, 4, 5, 6])),
        PortId::interface_name("Gi1/0/1").unwrap(),
        120,
    );
    pdu.optional.push(Tlv::SystemName(b"SW".to_vec()));
    pdu.optional
        .push(Tlv::SystemCapabilities(SystemCapabilities {
            supported: lldp_codec::Capability::Bridge.bit() | lldp_codec::Capability::Router.bit(),
            enabled: lldp_codec::Capability::Bridge.bit(),
        }));
    pdu.optional
        .push(Tlv::ManagementAddress(ManagementAddress::with_if_index(
            Ipv4Addr::new(10, 0, 0, 1).into(),
            3,
        )));
    pdu.optional.push(Tlv::Organizational(lldp_codec::OrgTlv {
        oui: [0, 0x80, 0xc2],
        subtype: 1,
        data: vec![0, 100],
    }));
    pdu.optional.push(Tlv::Organizational(lldp_codec::OrgTlv {
        oui: [0, 0, 0x0c],
        subtype: 9,
        data: vec![1],
    }));
    pdu.optional.push(Tlv::Unknown {
        tlv_type: 42,
        value: vec![0xab],
    });
    let v = LldpduView::from_lldpdu(&pdu);
    assert_eq!(v.chassis_id.value, "01:02:03:04:05:06");
    assert_eq!(v.chassis_id.subtype_name, "macaddress");
    assert_eq!(v.port_id.value, "Gi1/0/1");
    assert_eq!(v.system_name.as_deref(), Some("SW"));
    let caps = v.capabilities.clone().unwrap();
    assert_eq!(caps.short, "B");
    assert_eq!(caps.supported, ["bridge", "router"]);
    assert_eq!(v.management_addresses[0].address, "10.0.0.1");
    assert_eq!(v.management_addresses[0].family, "ipv4");
    assert_eq!(v.org_tlvs[0].decoded.as_ref().unwrap()["pvid"], json!(100));
    assert_eq!(v.org_tlvs[0].organization.as_deref(), Some("IEEE 802.1"));
    assert_eq!(v.org_tlvs[1].organization.as_deref(), Some("Cisco"));
    assert!(v.org_tlvs[1].decoded.is_none());
    assert_eq!(v.unknown_tlvs[0].value_hex, "ab");
    // The view serializes and round-trips.
    let s = serde_json::to_string(&v).unwrap();
    let back: LldpduView = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}
