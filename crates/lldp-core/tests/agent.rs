//! Agent orchestration tests with a mock backend and paused time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lldp_codec::{ChassisId, MacAddr, PortId};
use lldp_core::agent::{Decision, NoHooks};
use lldp_core::packet_io::{
    AdapterId, MockChannel, MockHandle, PacketChannel, PacketIo, PacketIoError,
};
use lldp_core::{
    AdminStatus, Agent, AgentEvent, InterfaceChange, InterfaceInfo, InterfaceKind, LocalPort,
    LocalSystem, PortConfig, PortEvent, PortHooks, Resolver, TimerParams,
};
use tokio::sync::broadcast;

const MAC: MacAddr = MacAddr([0x00, 0x1b, 0x21, 0x00, 0x00, 0x01]);

#[derive(Default)]
struct MockBackend {
    handles: Mutex<Vec<(String, MockHandle)>>,
    fail: Mutex<Vec<String>>,
}

impl PacketIo for MockBackend {
    fn open(&self, adapter: &AdapterId) -> Result<Box<dyn PacketChannel>, PacketIoError> {
        if self.fail.lock().unwrap().contains(&adapter.0) {
            return Err(PacketIoError::OpenFailed {
                adapter: adapter.clone(),
                reason: "mock".into(),
            });
        }
        let (chan, handle) = MockChannel::new(MAC);
        self.handles
            .lock()
            .unwrap()
            .push((adapter.0.clone(), handle));
        Ok(Box::new(chan))
    }
}

struct FixedResolver {
    mode: Mutex<AdminStatus>,
}

impl Resolver for FixedResolver {
    fn system(&self) -> LocalSystem {
        LocalSystem::minimal(ChassisId::locally_assigned("WS").unwrap())
    }
    fn decide(&self, iface: &InterfaceInfo) -> Decision {
        let mode = if iface.kind == InterfaceKind::PhysicalEthernet {
            *self.mode.lock().unwrap()
        } else {
            AdminStatus::Disabled
        };
        Decision {
            admin_status: mode,
            local: LocalPort::minimal(PortId::mac(iface.mac.unwrap_or(MAC))),
        }
    }
    fn timers(&self) -> TimerParams {
        TimerParams::DEFAULT
    }
    fn port_config(&self, admin_status: AdminStatus) -> PortConfig {
        PortConfig {
            admin_status,
            ..PortConfig::default()
        }
    }
}

#[derive(Default)]
struct RecordingHooks {
    log: Mutex<Vec<String>>,
}

impl PortHooks for RecordingHooks {
    fn tx_started(&self, i: &InterfaceInfo) {
        self.log.lock().unwrap().push(format!("start {}", i.alias));
    }
    fn tx_stopped(&self, i: &InterfaceInfo) {
        self.log.lock().unwrap().push(format!("stop {}", i.alias));
    }
}

fn iface(guid: &str, alias: &str, kind: InterfaceKind, connected: bool) -> InterfaceInfo {
    InterfaceInfo {
        guid: guid.into(),
        luid: 1,
        if_index: 7,
        alias: alias.into(),
        description: "Mock NIC".into(),
        mac: Some(MAC),
        connected,
        link_speed: 1_000_000_000,
        kind,
        addresses: vec![],
    }
}

fn drain(rx: &mut broadcast::Receiver<AgentEvent>) -> Vec<AgentEvent> {
    let mut v = Vec::new();
    while let Ok(e) = rx.try_recv() {
        v.push(e);
    }
    v
}

#[tokio::test(start_paused = true)]
async fn agent_manages_ports_through_interface_lifecycle() {
    let backend = Arc::new(MockBackend::default());
    let resolver = Arc::new(FixedResolver {
        mode: Mutex::new(AdminStatus::RxTx),
    });
    let hooks = Arc::new(RecordingHooks::default());
    let (ev_tx, mut ev_rx) = broadcast::channel(256);
    let mut agent = Agent::new(backend.clone(), resolver.clone(), hooks.clone(), ev_tx);

    // Physical adapter, link up: port starts and transmits immediately.
    agent
        .handle(InterfaceChange::Added(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            true,
        )))
        .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let first = drain(&mut ev_rx);
    assert!(matches!(
        first[0],
        AgentEvent::PortStarted {
            admin_status: AdminStatus::RxTx,
            ..
        }
    ));
    let handle = backend.handles.lock().unwrap()[0].1.clone();
    assert_eq!(handle.sent_count(), 1);
    assert_eq!(hooks.log.lock().unwrap().as_slice(), ["start Ethernet"]);

    // Wi-Fi is disabled by the resolver: no port.
    agent
        .handle(InterfaceChange::Added(iface(
            "{B}",
            "Wi-Fi",
            InterfaceKind::Wifi,
            true,
        )))
        .await;
    assert_eq!(backend.handles.lock().unwrap().len(), 1);
    assert_eq!(agent.admin_status("{B}"), AdminStatus::Disabled);
    assert_eq!(agent.interfaces().count(), 2);

    // Link down stops transmission and drops neighbors; link up restarts fast.
    agent
        .handle(InterfaceChange::LinkDown(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            false,
        )))
        .await;
    tokio::time::sleep(Duration::from_secs(40)).await;
    assert_eq!(
        handle.sent_count(),
        1,
        "nothing is sent while the link is down"
    );
    agent
        .handle(InterfaceChange::LinkUp(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            true,
        )))
        .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        handle.sent_count(),
        2,
        "link up restarts transmission at once"
    );

    // Reload with rx-only: shutdown LLDPDU, hook fires.
    *resolver.mode.lock().unwrap() = AdminStatus::RxOnly;
    agent.reload().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        handle.sent_count(),
        3,
        "shutdown LLDPDU on transition to rx-only"
    );
    assert_eq!(
        hooks.log.lock().unwrap().as_slice(),
        ["start Ethernet", "stop Ethernet"]
    );
    assert_eq!(agent.admin_status("{A}"), AdminStatus::RxOnly);

    // Runtime mode change back to rx_tx after reinitDelay: transmits again.
    assert!(agent.set_admin_status("{A}", AdminStatus::RxTx).await);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        handle.sent_count() >= 4,
        "transmission resumes after reinitDelay"
    );
    assert!(!agent.set_admin_status("{Z}", AdminStatus::RxTx).await);

    // Snapshot works; removal stops the task with a shutdown frame.
    let snap = agent.snapshot("{A}").await.unwrap();
    assert!(snap.link_up);
    let before = handle.sent_count();
    agent
        .handle(InterfaceChange::Removed(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            true,
        )))
        .await;
    assert_eq!(handle.sent_count(), before + 1);
    assert!(
        drain(&mut ev_rx)
            .iter()
            .any(|e| matches!(e, AgentEvent::PortStopped { .. }))
    );
    assert!(agent.snapshot("{A}").await.is_none());
    assert_eq!(agent.interfaces().count(), 1);
}

#[tokio::test(start_paused = true)]
async fn open_failure_is_reported_and_retried_on_next_change() {
    let backend = Arc::new(MockBackend::default());
    backend.fail.lock().unwrap().push("{A}".into());
    let resolver = Arc::new(FixedResolver {
        mode: Mutex::new(AdminStatus::RxTx),
    });
    let (ev_tx, mut ev_rx) = broadcast::channel(64);
    let mut agent = Agent::new(backend.clone(), resolver, Arc::new(NoHooks), ev_tx);
    agent
        .handle(InterfaceChange::Added(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            true,
        )))
        .await;
    assert!(matches!(
        drain(&mut ev_rx)[0],
        AgentEvent::PortOpenFailed { .. }
    ));
    backend.fail.lock().unwrap().clear();
    agent
        .handle(InterfaceChange::Changed(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            true,
        )))
        .await;
    assert!(matches!(
        drain(&mut ev_rx)[0],
        AgentEvent::PortStarted { .. }
    ));
    agent.shutdown().await;
    assert_eq!(agent.snapshot_all().await.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn port_events_are_forwarded_with_interface_identity() {
    let backend = Arc::new(MockBackend::default());
    let resolver = Arc::new(FixedResolver {
        mode: Mutex::new(AdminStatus::RxOnly),
    });
    let (ev_tx, mut ev_rx) = broadcast::channel(64);
    let mut agent = Agent::new(backend.clone(), resolver, Arc::new(NoHooks), ev_tx);
    agent
        .handle(InterfaceChange::Added(iface(
            "{A}",
            "Ethernet",
            InterfaceKind::PhysicalEthernet,
            true,
        )))
        .await;
    let handle = backend.handles.lock().unwrap()[0].1.clone();
    let pdu = lldp_codec::Lldpdu::new(
        ChassisId::mac(MacAddr([1, 2, 3, 4, 5, 6])),
        PortId::interface_name("Gi1").unwrap(),
        60,
    );
    let mut frame = Vec::new();
    lldp_codec::ethernet::write_lldp_frame(
        &mut frame,
        lldp_codec::LldpDestination::NearestBridge,
        MacAddr([1, 2, 3, 4, 5, 6]),
        &pdu.encode(1500).unwrap(),
    );
    handle.inject(frame).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let evs = drain(&mut ev_rx);
    assert!(evs.iter().any(|e| matches!(e, AgentEvent::Port { alias, event: PortEvent::NeighborAdded(_), .. } if alias == "Ethernet")));
    assert_eq!(agent.snapshot("{A}").await.unwrap().neighbors.len(), 1);
    agent.shutdown().await;
}

#[tokio::test]
async fn mock_channel_shares_state() {
    let (mut chan, handle) = MockChannel::new(MAC);
    chan.send(&[1, 2, 3]).unwrap();
    assert_eq!(handle.sent_count(), 1);
    let b: Box<dyn PacketChannel> = Box::new(chan);
    let mut b = b;
    b.send(&[4]).unwrap();
    assert_eq!(handle.sent_count(), 2);
}
