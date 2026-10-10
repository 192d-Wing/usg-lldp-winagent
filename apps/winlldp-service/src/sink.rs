//! Routes agent and service events to the Windows Event Log and, in
//! console mode, to stderr.

use lldp_core::AgentEvent;
use lldp_core::port::PortEvent;
use lldp_windows::eventlog::{EventLog, Level, id};
use tokio::sync::{broadcast, mpsc};

/// Service-level events that are not agent events.
#[derive(Debug)]
pub enum SinkEvent {
    /// Service started.
    Started {
        /// Version.
        version: String,
    },
    /// Service stopping.
    Stopped,
    /// Configuration loaded.
    ConfigLoaded {
        /// Path.
        path: String,
        /// Policy overrides were applied.
        policy_applied: bool,
    },
    /// Configuration failed to load.
    ConfigError(String),
    /// The process token holds privileges beyond the declared set; the
    /// service is stopping.
    PrivilegesUnexpected(String),
    /// The service executable can be modified by a non-administrator.
    BinaryInsecure(String),
    /// Npcap load outcome.
    Npcap {
        /// Version if loaded.
        version: Option<String>,
        /// Error if not.
        error: Option<String>,
    },
    /// MsLldp binding change outcome.
    MsLldp {
        /// Interface alias.
        alias: String,
        /// Binding state after the operation.
        enabled: bool,
        /// Error if the operation failed.
        error: Option<String>,
    },
    /// Interface monitor failure.
    MonitorError(String),
    /// IPC server started.
    IpcStarted(String),
    /// IPC server error.
    IpcError(String),
}

/// The sink task.
pub struct Sink {
    console: bool,
    log: Option<EventLog>,
    service_rx: mpsc::UnboundedReceiver<SinkEvent>,
    agent_rx: broadcast::Receiver<AgentEvent>,
}

impl Sink {
    /// Creates the sink. Event Log failures fall back to console only.
    pub fn new(
        console: bool,
        per_minute: u32,
        service_rx: mpsc::UnboundedReceiver<SinkEvent>,
        agent_rx: broadcast::Receiver<AgentEvent>,
    ) -> Self {
        let log = match EventLog::open(per_minute) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("event log unavailable: {e}");
                None
            }
        };
        Self {
            console,
            log,
            service_rx,
            agent_rx,
        }
    }

    fn emit(&self, level: Level, event_id: u32, message: &str) {
        if self.console {
            let tag = match level {
                Level::Info => "INFO ",
                Level::Warning => "WARN ",
                Level::Error => "ERROR",
            };
            eprintln!("{tag} [{event_id}] {message}");
        }
        if let Some(l) = &self.log {
            l.report(level, event_id, message);
        }
    }

    /// Runs until both channels close.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                s = self.service_rx.recv() => match s {
                    Some(e) => self.service_event(&e),
                    None => break,
                },
                a = self.agent_rx.recv() => match a {
                    Ok(e) => self.agent_event(&e),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        self.emit(Level::Warning, id::EVENTS_SUPPRESSED, &format!("{n} agent events dropped (sink lagging)"));
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    }

    fn service_event(&self, e: &SinkEvent) {
        match e {
            SinkEvent::Started { version } => self.emit(Level::Info, id::SERVICE_STARTED, &format!("WinLLDP {version} started")),
            SinkEvent::Stopped => self.emit(Level::Info, id::SERVICE_STOPPED, "WinLLDP stopped"),
            SinkEvent::ConfigLoaded { path, policy_applied } => {
                self.emit(Level::Info, id::CONFIG_LOADED, &format!("configuration loaded from {path}"));
                if *policy_applied {
                    self.emit(Level::Info, id::POLICY_APPLIED, "registry policy overrides applied (HKLM\\SOFTWARE\\Policies\\WinLLDP)");
                }
            }
            SinkEvent::ConfigError(m) if m.starts_with(crate::app::INSECURE_CONFIG_PREFIX) => {
                self.emit(Level::Error, id::CONFIG_INSECURE, m);
            }
            SinkEvent::ConfigError(m) => self.emit(Level::Error, id::CONFIG_ERROR, m),
            SinkEvent::PrivilegesUnexpected(m) => self.emit(
                Level::Error,
                id::PRIVILEGES_UNEXPECTED,
                &format!("the service token holds privileges WinLLDP does not declare and is stopping: {m}. Re-run the installer or `winlldp-service.exe harden`"),
            ),
            SinkEvent::BinaryInsecure(m) => self.emit(
                Level::Error,
                id::BINARY_INSECURE,
                &format!("the service executable can be modified by a non-administrator: {m}. Install under %ProgramFiles% with the MSI"),
            ),
            SinkEvent::Npcap { version: Some(v), .. } => self.emit(Level::Info, id::NPCAP_VERSION, &format!("packet backend: {v}")),
            SinkEvent::Npcap { error, .. } => self.emit(
                Level::Error,
                id::NPCAP_UNAVAILABLE,
                &format!("Npcap is not available; LLDP transmit and receive are disabled until it is installed: {}", error.as_deref().unwrap_or("unknown")),
            ),
            SinkEvent::MsLldp { alias, enabled, error: None } => self.emit(
                Level::Info,
                id::MSLLDP_BINDING_CHANGED,
                &format!("Microsoft LLDP driver binding on '{alias}' {}", if *enabled { "restored" } else { "disabled while WinLLDP transmits" }),
            ),
            SinkEvent::MsLldp { alias, error: Some(err), .. } => {
                self.emit(Level::Warning, id::MSLLDP_BINDING_ERROR, &format!("could not change Microsoft LLDP driver binding on '{alias}': {err}"));
            }
            SinkEvent::MonitorError(m) => self.emit(Level::Error, id::PORT_FAILED, &format!("interface monitor: {m}")),
            SinkEvent::IpcStarted(n) => self.emit(Level::Info, id::IPC_STARTED, &format!("IPC listening on {n}")),
            SinkEvent::IpcError(m) => self.emit(Level::Error, id::IPC_ERROR, m),
        }
    }

    fn agent_event(&self, e: &AgentEvent) {
        match e {
            AgentEvent::PortStarted {
                iface,
                admin_status,
            } => self.emit(
                Level::Info,
                id::INTERFACE_MANAGED,
                &format!(
                    "managing '{}' ({}) in mode {admin_status:?}",
                    iface.alias, iface.description
                ),
            ),
            AgentEvent::PortStopped { iface } => self.emit(
                Level::Info,
                id::INTERFACE_UNMANAGED,
                &format!("stopped managing '{}'", iface.alias),
            ),
            AgentEvent::PortOpenFailed { iface, error } => {
                self.emit(
                    Level::Error,
                    id::PORT_OPEN_FAILED,
                    &format!("cannot open packet channel on '{}': {error}", iface.alias),
                );
            }
            AgentEvent::PortFailed { guid, error } => self.emit(
                Level::Error,
                id::PORT_FAILED,
                &format!("port {guid} failed: {error}"),
            ),
            AgentEvent::Port { alias, event, .. } => match event {
                PortEvent::NeighborAdded(n) => self.emit(
                    Level::Info,
                    id::NEIGHBOR_ADDED,
                    &format!(
                        "neighbor discovered on '{alias}': {} port {} ({})",
                        n.lldpdu.system_name().map_or_else(
                            || n.msap.chassis_id.to_string(),
                            lldp_codec::types::lossy_text
                        ),
                        n.msap.port_id,
                        n.msap.chassis_id
                    ),
                ),
                PortEvent::NeighborUpdated(n) => {
                    self.emit(
                        Level::Info,
                        id::NEIGHBOR_UPDATED,
                        &format!(
                            "neighbor updated on '{alias}': {} port {}",
                            n.msap.chassis_id, n.msap.port_id
                        ),
                    );
                }
                PortEvent::NeighborExpired(n) => {
                    self.emit(
                        Level::Warning,
                        id::NEIGHBOR_EXPIRED,
                        &format!(
                            "neighbor expired on '{alias}': {} port {}",
                            n.msap.chassis_id, n.msap.port_id
                        ),
                    );
                }
                PortEvent::NeighborRemoved { neighbor, reason } => self.emit(
                    Level::Info,
                    id::NEIGHBOR_REMOVED,
                    &format!(
                        "neighbor removed on '{alias}' ({reason:?}): {} port {}",
                        neighbor.msap.chassis_id, neighbor.msap.port_id
                    ),
                ),
                PortEvent::TooManyNeighbors { msap } => {
                    self.emit(
                        Level::Warning,
                        id::TOO_MANY_NEIGHBORS,
                        &format!(
                            "neighbor table full on '{alias}'; dropped {} port {}",
                            msap.chassis_id, msap.port_id
                        ),
                    );
                }
                PortEvent::FrameDiscarded(err) => self.emit(
                    Level::Warning,
                    id::FRAME_DISCARDED,
                    &format!("malformed LLDP frame on '{alias}': {err}"),
                ),
                PortEvent::TransmitError(m) => self.emit(
                    Level::Error,
                    id::TRANSMIT_FAILED,
                    &format!("cannot build LLDPDU for '{alias}': {m}"),
                ),
                _ => {}
            },
            _ => {}
        }
    }
}
