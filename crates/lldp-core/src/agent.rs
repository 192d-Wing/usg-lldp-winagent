//! The agent: owns one port task per managed interface and reacts to
//! interface changes and configuration reloads.
//!
//! Policy decisions (which interfaces to manage, what to advertise) are
//! supplied by a [`Resolver`] so this module stays free of configuration
//! and platform types.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::interface::{InterfaceChange, InterfaceInfo};
use crate::local::{LocalPort, LocalSystem};
use crate::packet_io::{AdapterId, PacketIo, PacketIoError};
use crate::port::{AdminStatus, Port, PortConfig, PortEvent};
use crate::runtime::{PortCommand, PortSnapshot, run_port};
use crate::timers::TimerParams;

/// Decides, for one interface, whether and how it is managed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Administrative status. `Disabled` means no port task.
    pub admin_status: AdminStatus,
    /// What the port advertises.
    pub local: LocalPort,
}

/// Supplies policy: system-wide advertisement content and per-interface
/// decisions. Implemented by the service from configuration and system
/// facts.
pub trait Resolver: Send + Sync {
    /// System-wide advertisement content.
    fn system(&self) -> LocalSystem;
    /// Decision for an interface.
    fn decide(&self, iface: &InterfaceInfo) -> Decision;
    /// Timer parameters.
    fn timers(&self) -> TimerParams;
    /// Per-port limits.
    fn port_config(&self, admin_status: AdminStatus) -> PortConfig;
}

/// Hooks for platform side effects when a port starts or stops
/// transmitting (used for MsLldp binding control).
pub trait PortHooks: Send + Sync {
    /// A port on `iface` is now transmitting.
    fn tx_started(&self, iface: &InterfaceInfo);
    /// A port on `iface` stopped transmitting (or was removed).
    fn tx_stopped(&self, iface: &InterfaceInfo);
}

/// No-op hooks.
#[derive(Debug, Default)]
pub struct NoHooks;

impl PortHooks for NoHooks {
    fn tx_started(&self, _: &InterfaceInfo) {}
    fn tx_stopped(&self, _: &InterfaceInfo) {}
}

/// Something that happened at agent level.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentEvent {
    /// A port task was started for the interface.
    PortStarted {
        /// Interface.
        iface: InterfaceInfo,
        /// Mode.
        admin_status: AdminStatus,
    },
    /// A port task was stopped.
    PortStopped {
        /// Interface.
        iface: InterfaceInfo,
    },
    /// Opening the packet channel failed; the interface stays unmanaged
    /// until the next change.
    PortOpenFailed {
        /// Interface.
        iface: InterfaceInfo,
        /// Error.
        error: PacketIoError,
    },
    /// A port task ended on its own (packet channel error).
    PortFailed {
        /// Interface GUID.
        guid: String,
        /// Error.
        error: PacketIoError,
    },
    /// An event from a port.
    Port {
        /// Interface GUID.
        guid: String,
        /// Interface alias at the time.
        alias: String,
        /// The event.
        event: PortEvent,
    },
}

struct ManagedPort {
    info: InterfaceInfo,
    admin_status: AdminStatus,
    cmds: mpsc::Sender<PortCommand>,
    task: JoinHandle<crate::runtime::Exit>,
    _forwarder: JoinHandle<()>,
}

/// The agent.
pub struct Agent {
    backend: Arc<dyn PacketIo>,
    resolver: Arc<dyn Resolver>,
    hooks: Arc<dyn PortHooks>,
    events: broadcast::Sender<AgentEvent>,
    ports: BTreeMap<String, ManagedPort>,
    known: BTreeMap<String, InterfaceInfo>,
}

impl Agent {
    /// Creates an agent. `events` receives everything the agent and its
    /// ports observe.
    pub fn new(
        backend: Arc<dyn PacketIo>,
        resolver: Arc<dyn Resolver>,
        hooks: Arc<dyn PortHooks>,
        events: broadcast::Sender<AgentEvent>,
    ) -> Self {
        Self {
            backend,
            resolver,
            hooks,
            events,
            ports: BTreeMap::new(),
            known: BTreeMap::new(),
        }
    }

    /// Interfaces currently known, managed or not.
    pub fn interfaces(&self) -> impl Iterator<Item = &InterfaceInfo> {
        self.known.values()
    }

    /// Administrative status of a managed interface, `Disabled` if not managed.
    pub fn admin_status(&self, guid: &str) -> AdminStatus {
        self.ports
            .get(guid)
            .map_or(AdminStatus::Disabled, |p| p.admin_status)
    }

    /// Applies an interface change.
    pub async fn handle(&mut self, change: InterfaceChange) {
        match change {
            InterfaceChange::Added(info) | InterfaceChange::Changed(info) => {
                self.known.insert(info.guid.clone(), info.clone());
                self.reconcile(&info).await;
            }
            InterfaceChange::LinkUp(info) => {
                self.known.insert(info.guid.clone(), info.clone());
                self.reconcile(&info).await;
                if let Some(p) = self.ports.get(&info.guid) {
                    let _ = p.cmds.send(PortCommand::LinkUp).await;
                }
            }
            InterfaceChange::LinkDown(info) => {
                self.known.insert(info.guid.clone(), info.clone());
                if let Some(p) = self.ports.get(&info.guid) {
                    let _ = p.cmds.send(PortCommand::LinkDown).await;
                }
            }
            InterfaceChange::Removed(info) => {
                self.known.remove(&info.guid);
                self.stop_port(&info.guid).await;
            }
        }
    }

    /// Re-evaluates every known interface against the resolver, for
    /// configuration reloads.
    pub async fn reload(&mut self) {
        let infos: Vec<InterfaceInfo> = self.known.values().cloned().collect();
        for info in infos {
            self.reconcile(&info).await;
        }
    }

    /// Changes the administrative status of one interface at runtime
    /// (CLI `interface mode`). Returns false if the interface is unknown.
    pub async fn set_admin_status(&mut self, guid: &str, status: AdminStatus) -> bool {
        let Some(info) = self.known.get(guid).cloned() else {
            return false;
        };
        if status == AdminStatus::Disabled {
            self.stop_port(guid).await;
            return true;
        }
        let decision = Decision {
            admin_status: status,
            local: self.resolver.decide(&info).local,
        };
        self.apply(&info, decision).await;
        true
    }

    async fn reconcile(&mut self, info: &InterfaceInfo) {
        let decision = self.resolver.decide(info);
        if decision.admin_status == AdminStatus::Disabled {
            self.stop_port(&info.guid).await;
            return;
        }
        self.apply(info, decision).await;
    }

    async fn apply(&mut self, info: &InterfaceInfo, decision: Decision) {
        if let Some(p) = self.ports.get_mut(&info.guid) {
            let was_tx = p.admin_status.tx();
            if p.admin_status != decision.admin_status {
                p.admin_status = decision.admin_status;
                let _ = p
                    .cmds
                    .send(PortCommand::SetAdminStatus(decision.admin_status))
                    .await;
            }
            p.info = info.clone();
            let _ = p
                .cmds
                .send(PortCommand::UpdateLocal(Box::new((
                    self.resolver.system(),
                    decision.local,
                ))))
                .await;
            match (was_tx, decision.admin_status.tx()) {
                (false, true) => self.hooks.tx_started(info),
                (true, false) => self.hooks.tx_stopped(info),
                _ => {}
            }
            return;
        }
        self.start_port(info, decision).await;
    }

    async fn start_port(&mut self, info: &InterfaceInfo, decision: Decision) {
        let chan = match self.backend.open(&AdapterId(info.guid.clone())) {
            Ok(c) => c,
            Err(error) => {
                let _ = self.events.send(AgentEvent::PortOpenFailed {
                    iface: info.clone(),
                    error,
                });
                return;
            }
        };
        let now = tokio::time::Instant::now().into_std();
        let cfg = self.resolver.port_config(decision.admin_status);
        let port = Port::new(
            cfg,
            self.resolver.timers(),
            self.resolver.system(),
            decision.local,
            chan.mac(),
            now,
        );
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (ev_tx, mut ev_rx) = broadcast::channel::<PortEvent>(64);
        let task = tokio::spawn(run_port(port, chan, cmd_rx, ev_tx));
        if info.connected {
            let _ = cmd_tx.send(PortCommand::LinkUp).await;
        }
        let forwarder = {
            let events = self.events.clone();
            let guid = info.guid.clone();
            let alias = info.alias.clone();
            tokio::spawn(async move {
                loop {
                    match ev_rx.recv().await {
                        Ok(event) => {
                            let _ = events.send(AgentEvent::Port {
                                guid: guid.clone(),
                                alias: alias.clone(),
                                event,
                            });
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        };
        if decision.admin_status.tx() {
            self.hooks.tx_started(info);
        }
        let _ = self.events.send(AgentEvent::PortStarted {
            iface: info.clone(),
            admin_status: decision.admin_status,
        });
        self.ports.insert(
            info.guid.clone(),
            ManagedPort {
                info: info.clone(),
                admin_status: decision.admin_status,
                cmds: cmd_tx,
                task,
                _forwarder: forwarder,
            },
        );
    }

    async fn stop_port(&mut self, guid: &str) {
        let Some(p) = self.ports.remove(guid) else {
            return;
        };
        let _ = p.cmds.send(PortCommand::Shutdown).await;
        if let Ok(crate::runtime::Exit::ChannelError(error)) = p.task.await {
            let _ = self.events.send(AgentEvent::PortFailed {
                guid: guid.to_owned(),
                error,
            });
        }
        if p.admin_status.tx() {
            self.hooks.tx_stopped(&p.info);
        }
        let _ = self.events.send(AgentEvent::PortStopped { iface: p.info });
    }

    /// Snapshot of one managed port.
    pub async fn snapshot(&self, guid: &str) -> Option<PortSnapshot> {
        let p = self.ports.get(guid)?;
        let (tx, rx) = oneshot::channel();
        p.cmds.send(PortCommand::Snapshot(tx)).await.ok()?;
        rx.await.ok()
    }

    /// Snapshots of every managed port, keyed by GUID.
    pub async fn snapshot_all(&self) -> BTreeMap<String, PortSnapshot> {
        let mut out = BTreeMap::new();
        for guid in self.ports.keys() {
            if let Some(s) = self.snapshot(guid).await {
                out.insert(guid.clone(), s);
            }
        }
        out
    }

    /// Triggers an immediate transmission on every transmitting port
    /// (local change such as a hostname update).
    pub async fn local_change(&self) {
        for p in self.ports.values() {
            let local = self.resolver.decide(&p.info).local;
            let _ = p
                .cmds
                .send(PortCommand::UpdateLocal(Box::new((
                    self.resolver.system(),
                    local,
                ))))
                .await;
        }
    }

    /// Starts a new fast transmission period on one port, or on every port
    /// when `guid` is `None`, without any change in content.
    pub async fn readvertise(&self, guid: Option<&str>) {
        for (g, p) in &self.ports {
            if guid.is_none_or(|want| want == g) {
                let _ = p.cmds.send(PortCommand::Readvertise).await;
            }
        }
    }

    /// Stops every port, sending shutdown LLDPDUs.
    pub async fn shutdown(&mut self) {
        let guids: Vec<String> = self.ports.keys().cloned().collect();
        for g in guids {
            self.stop_port(&g).await;
        }
    }
}
