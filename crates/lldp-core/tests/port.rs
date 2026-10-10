//! Deterministic state machine tests for `Port` (no runtime).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::{Duration, Instant};

use lldp_codec::ethernet::{parse_lldp_frame, write_lldp_frame};
use lldp_codec::{ChassisId, LldpDestination, Lldpdu, MacAddr, PortId, SystemCapabilities, Tlv};
use lldp_core::port::{PortEvent, RemoveReason};
use lldp_core::{Action, AdminStatus, LocalPort, LocalSystem, Port, PortConfig, TimerParams};

const OUR_MAC: MacAddr = MacAddr([0x00, 0x1b, 0x21, 0x00, 0x00, 0x01]);
const SW_MAC: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);

fn system() -> LocalSystem {
    let mut s = LocalSystem::minimal(ChassisId::locally_assigned("WS-12345").unwrap());
    s.system_name = Some(b"WS-12345.example.mil".to_vec());
    s.capabilities = Some(SystemCapabilities::STATION_ONLY);
    s
}

fn local() -> LocalPort {
    let mut p = LocalPort::minimal(PortId::mac(OUR_MAC));
    p.port_description = Some(b"Ethernet".to_vec());
    p
}

fn port(status: AdminStatus, now: Instant) -> Port {
    let cfg = PortConfig {
        admin_status: status,
        ..PortConfig::default()
    };
    Port::new(cfg, TimerParams::DEFAULT, system(), local(), OUR_MAC, now)
}

fn switch_frame(port_name: &str, ttl: u16, src: MacAddr) -> Vec<u8> {
    let mut pdu = Lldpdu::new(
        ChassisId::mac(SW_MAC),
        PortId::interface_name(port_name).unwrap(),
        ttl,
    );
    pdu.optional.push(Tlv::SystemName(b"SW-ACCESS-01".to_vec()));
    let bytes = pdu.encode(1500).unwrap();
    let mut frame = Vec::new();
    write_lldp_frame(&mut frame, LldpDestination::NearestBridge, src, &bytes);
    frame
}

fn transmits(actions: &[Action]) -> Vec<&Vec<u8>> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Transmit(f) => Some(f),
            Action::Event(_) => None,
        })
        .collect()
}

fn events(actions: &[Action]) -> Vec<&PortEvent> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Event(e) => Some(e),
            Action::Transmit(_) => None,
        })
        .collect()
}

fn ttl_of(frame: &[u8]) -> u16 {
    let (_, pdu) = parse_lldp_frame(frame).unwrap();
    Lldpdu::decode(pdu).unwrap().lldpdu.ttl
}

#[test]
fn readvertise_restarts_the_fast_period_with_unchanged_content() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    assert!(
        transmits(&p.readvertise(t0)).is_empty(),
        "nothing while the link is down"
    );
    p.link_up(t0);
    for s in 1..=3 {
        p.tick(t0 + Duration::from_secs(s));
    }
    // In the normal interval now; an unchanged update sends nothing.
    let t = t0 + Duration::from_secs(10);
    assert_eq!(
        transmits(&p.update_local(system(), local(), t)),
        Vec::<&Vec<u8>>::new()
    );
    let a = p.readvertise(t);
    assert_eq!(transmits(&a).len(), 1);
    assert_eq!(ttl_of(transmits(&a)[0]), 121);
    for s in 1..=3 {
        assert_eq!(p.next_deadline(), Some(t + Duration::from_secs(s)));
        assert_eq!(transmits(&p.tick(t + Duration::from_secs(s))).len(), 1);
    }
    assert_eq!(p.next_deadline(), Some(t + Duration::from_secs(33)));
}

#[test]
fn link_up_starts_fast_transmission_then_normal_interval() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    let a = p.link_up(t0);
    let tx = transmits(&a);
    assert_eq!(tx.len(), 1, "first frame goes out immediately");
    let (hdr, pdu) = parse_lldp_frame(tx[0]).unwrap();
    assert_eq!(hdr.dst, LldpDestination::NearestBridge.mac());
    assert_eq!(hdr.src, OUR_MAC);
    let d = Lldpdu::decode(pdu).unwrap().lldpdu;
    assert_eq!(d.ttl, 121);
    assert_eq!(
        d.chassis_id,
        ChassisId::locally_assigned("WS-12345").unwrap()
    );
    assert_eq!(d.system_name(), Some(&b"WS-12345.example.mil"[..]));

    // txFastInit = 4 frames at msgFastTx = 1 s: frames at t0, t0+1, t0+2, t0+3.
    let mut sent = 1;
    for s in 1..=3 {
        assert_eq!(p.next_deadline(), Some(t0 + Duration::from_secs(s)));
        assert_eq!(transmits(&p.tick(t0 + Duration::from_secs(s))).len(), 1);
        sent += 1;
    }
    assert_eq!(sent, 4);
    // Then the normal interval: next at t0 + 3 + 30.
    assert_eq!(p.next_deadline(), Some(t0 + Duration::from_secs(33)));
    assert_eq!(
        transmits(&p.tick(t0 + Duration::from_secs(32))),
        Vec::<&Vec<u8>>::new()
    );
    assert_eq!(transmits(&p.tick(t0 + Duration::from_secs(33))).len(), 1);
    assert_eq!(p.stats().tx_frames_total, 5);
}

#[test]
fn credit_limits_bursts_of_local_changes() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::TxOnly, t0);
    p.link_up(t0); // uses 1 credit of 5
    let mut sent = 0;
    for _ in 0..10 {
        sent += transmits(&p.local_change(t0)).len();
    }
    assert_eq!(sent, 4, "only the remaining credit may be spent at once");
    // A pending txNow waits for the next credit increment at t0 + 1 s.
    assert_eq!(p.next_deadline(), Some(t0 + Duration::from_secs(1)));
    assert_eq!(transmits(&p.tick(t0 + Duration::from_secs(1))).len(), 1);
    // Credit refills one per second and never exceeds txCreditMax.
    let later = t0 + Duration::from_secs(600);
    p.tick(later);
    let mut burst = 0;
    for _ in 0..10 {
        burst += transmits(&p.local_change(later)).len();
    }
    assert!(burst <= 5, "burst {burst} exceeded txCreditMax");
}

#[test]
fn receive_adds_updates_and_expires_neighbors() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxOnly, t0);
    p.link_up(t0);
    let a = p.handle_frame(&switch_frame("Gi1/0/24", 10, SW_MAC), t0);
    assert!(matches!(events(&a)[0], PortEvent::NeighborAdded(n) if n.ttl == 10));
    assert_eq!(p.neighbors().len(), 1);
    assert_eq!(p.stats().rx_frames_total, 1);
    assert_eq!(p.stats().rem_inserts, 1);

    // Same content again: refresh, no event, expiry pushed out.
    let a = p.handle_frame(
        &switch_frame("Gi1/0/24", 10, SW_MAC),
        t0 + Duration::from_secs(5),
    );
    assert_eq!(events(&a), Vec::<&PortEvent>::new());
    assert_eq!(p.next_deadline(), Some(t0 + Duration::from_secs(15)));

    // Changed content: update event.
    let mut changed = Lldpdu::new(
        ChassisId::mac(SW_MAC),
        PortId::interface_name("Gi1/0/24").unwrap(),
        10,
    );
    changed
        .optional
        .push(Tlv::SystemName(b"SW-ACCESS-02".to_vec()));
    let mut frame = Vec::new();
    write_lldp_frame(
        &mut frame,
        LldpDestination::NearestBridge,
        SW_MAC,
        &changed.encode(1500).unwrap(),
    );
    let a = p.handle_frame(&frame, t0 + Duration::from_secs(6));
    assert!(
        matches!(events(&a)[0], PortEvent::NeighborUpdated(n) if n.lldpdu.system_name() == Some(&b"SW-ACCESS-02"[..]))
    );

    // Expiry exactly at last_seen + TTL.
    assert_eq!(
        events(&p.tick(t0 + Duration::from_secs(15))),
        Vec::<&PortEvent>::new()
    );
    let a = p.tick(t0 + Duration::from_secs(16));
    assert!(matches!(events(&a)[0], PortEvent::NeighborExpired(_)));
    assert_eq!(p.neighbors().len(), 0);
    assert_eq!(p.stats().rx_ageouts_total, 1);
}

#[test]
fn ttl_zero_removes_immediately() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxOnly, t0);
    p.link_up(t0);
    p.handle_frame(&switch_frame("Gi1/0/24", 120, SW_MAC), t0);
    let a = p.handle_frame(&switch_frame("Gi1/0/24", 0, SW_MAC), t0);
    assert!(matches!(
        events(&a)[0],
        PortEvent::NeighborRemoved {
            reason: RemoveReason::ShutdownReceived,
            ..
        }
    ));
    assert_eq!(p.neighbors().len(), 0);
    assert_eq!(p.stats().rem_deletes, 1);
    // TTL 0 for an unknown neighbor is a no-op.
    let a = p.handle_frame(&switch_frame("Gi1/0/25", 0, SW_MAC), t0);
    assert_eq!(events(&a), Vec::<&PortEvent>::new());
}

#[test]
fn too_many_neighbors_drops_newest() {
    let t0 = Instant::now();
    let cfg = PortConfig {
        admin_status: AdminStatus::RxOnly,
        max_neighbors: 2,
        ..PortConfig::default()
    };
    let mut p = Port::new(cfg, TimerParams::DEFAULT, system(), local(), OUR_MAC, t0);
    p.link_up(t0);
    p.handle_frame(&switch_frame("p1", 60, SW_MAC), t0);
    p.handle_frame(&switch_frame("p2", 60, SW_MAC), t0);
    let a = p.handle_frame(&switch_frame("p3", 60, SW_MAC), t0);
    assert!(matches!(events(&a)[0], PortEvent::TooManyNeighbors { .. }));
    assert_eq!(p.neighbors().len(), 2);
    assert_eq!(p.stats().rem_drops, 1);
    assert_eq!(p.stats().rx_frames_discarded_total, 1);
    // Existing neighbors can still refresh.
    assert_eq!(
        events(&p.handle_frame(&switch_frame("p1", 60, SW_MAC), t0)),
        Vec::<&PortEvent>::new()
    );
}

#[test]
fn malformed_frames_are_counted_not_fatal() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    p.link_up(t0);
    let a = p.handle_frame(&[0u8; 10], t0);
    assert!(matches!(events(&a)[0], PortEvent::FrameDiscarded(_)));
    let mut bad = switch_frame("p1", 60, SW_MAC);
    bad.truncate(30);
    p.handle_frame(&bad, t0);
    assert_eq!(p.stats().rx_frames_errors, 2);
    assert_eq!(p.stats().rx_frames_discarded_total, 2);
    assert_eq!(p.stats().rx_frames_total, 0);
}

#[test]
fn own_echo_and_non_lldp_destinations_are_ignored() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    p.link_up(t0);
    let a = p.handle_frame(&switch_frame("p1", 60, OUR_MAC), t0);
    assert_eq!(a, Vec::<Action>::new());
    assert_eq!(p.neighbors().len(), 0);
    let mut unicast = switch_frame("p1", 60, SW_MAC);
    unicast[..6].copy_from_slice(&OUR_MAC.0);
    p.handle_frame(&unicast, t0);
    assert_eq!(p.neighbors().len(), 0);
    assert_eq!(p.stats().rx_frames_discarded_total, 1);
}

#[test]
fn rx_only_never_transmits_and_tx_only_never_receives() {
    let t0 = Instant::now();
    let mut rx = port(AdminStatus::RxOnly, t0);
    assert_eq!(transmits(&rx.link_up(t0)), Vec::<&Vec<u8>>::new());
    assert_eq!(
        transmits(&rx.tick(t0 + Duration::from_secs(100))),
        Vec::<&Vec<u8>>::new()
    );
    let mut tx = port(AdminStatus::TxOnly, t0);
    tx.link_up(t0);
    tx.handle_frame(&switch_frame("p1", 60, SW_MAC), t0);
    assert_eq!(tx.neighbors().len(), 0);
    assert_eq!(tx.stats().rx_frames_total, 0);
}

#[test]
fn new_neighbor_triggers_fast_start() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    p.link_up(t0);
    // Burn through the initial fast period.
    for s in 1..=3 {
        p.tick(t0 + Duration::from_secs(s));
    }
    let quiet = t0 + Duration::from_secs(20);
    p.tick(quiet);
    let a = p.handle_frame(&switch_frame("p1", 60, SW_MAC), quiet);
    assert_eq!(
        transmits(&a).len(),
        1,
        "new neighbor causes an immediate transmission"
    );
    assert_eq!(
        p.next_deadline().unwrap(),
        quiet + Duration::from_secs(1),
        "and a fast period follows"
    );
}

#[test]
fn admin_disable_sends_shutdown_and_waits_reinit_delay() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    p.link_up(t0);
    p.handle_frame(&switch_frame("p1", 60, SW_MAC), t0);
    let a = p.set_admin_status(AdminStatus::Disabled, t0);
    let tx = transmits(&a);
    assert_eq!(tx.len(), 1);
    assert_eq!(ttl_of(tx[0]), 0);
    let (_, pdu) = parse_lldp_frame(tx[0]).unwrap();
    assert!(
        Lldpdu::decode(pdu).unwrap().lldpdu.optional.is_empty(),
        "shutdown LLDPDU carries mandatory TLVs only"
    );
    assert!(matches!(
        events(&a)[0],
        PortEvent::NeighborRemoved {
            reason: RemoveReason::AdminDisabled,
            ..
        }
    ));
    assert_eq!(
        transmits(&p.tick(t0 + Duration::from_millis(500))),
        Vec::<&Vec<u8>>::new()
    );

    // Re-enable within reinitDelay: nothing until the delay elapses.
    let t1 = t0 + Duration::from_secs(1);
    assert_eq!(
        transmits(&p.set_admin_status(AdminStatus::RxTx, t1)),
        Vec::<&Vec<u8>>::new()
    );
    assert_eq!(p.next_deadline(), Some(t0 + Duration::from_secs(2)));
    assert_eq!(transmits(&p.tick(t0 + Duration::from_secs(2))).len(), 1);
}

#[test]
fn rx_to_rxtx_transition_starts_transmitting() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxOnly, t0);
    p.link_up(t0);
    let a = p.set_admin_status(AdminStatus::RxTx, t0 + Duration::from_secs(5));
    assert_eq!(transmits(&a).len(), 1);
}

#[test]
fn link_down_drops_neighbors_and_stops_tx() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    p.link_up(t0);
    p.handle_frame(&switch_frame("p1", 60, SW_MAC), t0);
    let a = p.link_down(t0 + Duration::from_secs(1));
    assert!(transmits(&a).is_empty(), "no shutdown frame on a down link");
    assert!(matches!(
        events(&a)[0],
        PortEvent::NeighborRemoved {
            reason: RemoveReason::LinkDown,
            ..
        }
    ));
    assert_eq!(p.next_deadline(), None);
    assert_eq!(
        transmits(&p.tick(t0 + Duration::from_secs(60))),
        Vec::<&Vec<u8>>::new()
    );
    // Link up again: fast start from scratch.
    let a = p.link_up(t0 + Duration::from_secs(61));
    assert_eq!(transmits(&a).len(), 1);
}

#[test]
fn agent_shutdown_sends_ttl_zero_and_clears() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::RxTx, t0);
    p.link_up(t0);
    p.handle_frame(&switch_frame("p1", 60, SW_MAC), t0);
    let a = p.shutdown(t0);
    assert_eq!(ttl_of(transmits(&a)[0]), 0);
    assert!(matches!(
        events(&a)[0],
        PortEvent::NeighborRemoved {
            reason: RemoveReason::AgentShutdown,
            ..
        }
    ));
    assert_eq!(p.next_deadline(), None);
}

#[test]
fn update_local_transmits_only_on_change() {
    let t0 = Instant::now();
    let mut p = port(AdminStatus::TxOnly, t0);
    p.link_up(t0);
    assert_eq!(
        transmits(&p.update_local(system(), local(), t0)),
        Vec::<&Vec<u8>>::new()
    );
    let mut s = system();
    s.system_name = Some(b"renamed".to_vec());
    let a = p.update_local(s, local(), t0);
    assert_eq!(transmits(&a).len(), 1);
    let (_, pdu) = parse_lldp_frame(transmits(&a)[0]).unwrap();
    assert_eq!(
        Lldpdu::decode(pdu).unwrap().lldpdu.system_name(),
        Some(&b"renamed"[..])
    );
}

#[test]
fn timer_params_validation_and_ttl() {
    assert!(TimerParams::DEFAULT.validate().is_ok());
    assert_eq!(TimerParams::DEFAULT.ttl(), 121);
    let big = TimerParams {
        msg_tx_interval: 3600,
        msg_tx_hold: 100,
        ..TimerParams::DEFAULT
    };
    assert_eq!(big.ttl(), 65535);
    let bad = TimerParams {
        msg_tx_interval: 0,
        ..TimerParams::DEFAULT
    };
    let e = bad.validate().unwrap_err();
    assert_eq!(e.name, "msgTxInterval");
    assert!(
        TimerParams {
            tx_fast_init: 9,
            ..TimerParams::DEFAULT
        }
        .validate()
        .is_err()
    );
    assert!(
        TimerParams {
            reinit_delay: 11,
            ..TimerParams::DEFAULT
        }
        .validate()
        .is_err()
    );
}
