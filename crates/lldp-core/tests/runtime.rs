//! Driver tests with a mock channel and paused time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;

use lldp_codec::ethernet::{parse_lldp_frame, write_lldp_frame};
use lldp_codec::{ChassisId, LldpDestination, Lldpdu, MacAddr, PortId};
use lldp_core::packet_io::MockChannel;
use lldp_core::runtime::{Exit, PortCommand, run_port};
use lldp_core::{AdminStatus, LocalPort, LocalSystem, Port, PortConfig, PortEvent, TimerParams};
use tokio::sync::{broadcast, mpsc, oneshot};

const OUR_MAC: MacAddr = MacAddr([0x00, 0x1b, 0x21, 0x00, 0x00, 0x01]);
const SW_MAC: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);

fn switch_frame(ttl: u16) -> Vec<u8> {
    let pdu = Lldpdu::new(
        ChassisId::mac(SW_MAC),
        PortId::interface_name("Gi1/0/1").unwrap(),
        ttl,
    );
    let mut frame = Vec::new();
    write_lldp_frame(
        &mut frame,
        LldpDestination::NearestBridge,
        SW_MAC,
        &pdu.encode(1500).unwrap(),
    );
    frame
}

#[tokio::test(start_paused = true)]
async fn driver_transmits_receives_and_shuts_down() {
    let now = tokio::time::Instant::now().into_std();
    let port = Port::new(
        PortConfig::default(),
        TimerParams::DEFAULT,
        LocalSystem::minimal(ChassisId::locally_assigned("WS").unwrap()),
        LocalPort::minimal(PortId::mac(OUR_MAC)),
        OUR_MAC,
        now,
    );
    let (chan, handle) = MockChannel::new(OUR_MAC);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (ev_tx, mut ev_rx) = broadcast::channel(64);
    let task = tokio::spawn(run_port(port, Box::new(chan), cmd_rx, ev_tx));

    cmd_tx.send(PortCommand::LinkUp).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(handle.sent_count(), 1, "immediate transmission on link up");

    // Fast start: 4 frames within the first 3 seconds, then nothing until 33 s.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(handle.sent_count(), 4);
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert_eq!(handle.sent_count(), 4);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(handle.sent_count(), 5);

    // A neighbor arrives, is reported, and expires on time.
    handle.inject(switch_frame(5)).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(matches!(
        ev_rx.try_recv().unwrap(),
        PortEvent::NeighborAdded(_)
    ));
    let (snap_tx, snap_rx) = oneshot::channel();
    cmd_tx.send(PortCommand::Snapshot(snap_tx)).await.unwrap();
    let snap = snap_rx.await.unwrap();
    assert_eq!(snap.neighbors.len(), 1);
    assert!(snap.link_up);
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(matches!(
        ev_rx.try_recv().unwrap(),
        PortEvent::NeighborExpired(_)
    ));

    // Shutdown sends TTL 0 and the task exits.
    let before = handle.sent_count();
    cmd_tx.send(PortCommand::Shutdown).await.unwrap();
    assert_eq!(task.await.unwrap(), Exit::Shutdown);
    let sent = handle.take_sent();
    assert_eq!(sent.len(), before + 1);
    let (_, pdu) = parse_lldp_frame(sent.last().unwrap()).unwrap();
    assert_eq!(Lldpdu::decode(pdu).unwrap().lldpdu.ttl, 0);
}

#[tokio::test(start_paused = true)]
async fn driver_exits_when_channel_closes() {
    let now = tokio::time::Instant::now().into_std();
    let port = Port::new(
        PortConfig {
            admin_status: AdminStatus::RxOnly,
            ..PortConfig::default()
        },
        TimerParams::DEFAULT,
        LocalSystem::minimal(ChassisId::mac(OUR_MAC)),
        LocalPort::minimal(PortId::mac(OUR_MAC)),
        OUR_MAC,
        now,
    );
    let (chan, handle) = MockChannel::new(OUR_MAC);
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (ev_tx, _ev_rx) = broadcast::channel(8);
    let task = tokio::spawn(run_port(port, Box::new(chan), cmd_rx, ev_tx));
    drop(handle);
    assert!(matches!(task.await.unwrap(), Exit::ChannelError(_)));
}
