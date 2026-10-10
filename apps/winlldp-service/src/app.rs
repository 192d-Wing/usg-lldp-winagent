//! The service's main loop: configuration, backend, agent, interface
//! monitor, IPC server, event sink, reload, and shutdown.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lldp_config::{Config, ConfigResolver, PolicyOverrides, SystemFacts};
use lldp_core::agent::{Decision, PortHooks};
use lldp_core::packet_io::{AdapterId, PacketChannel, PacketIo, PacketIoError};
use lldp_core::{
    Agent, AgentEvent, InterfaceInfo, InterfaceKind, LocalSystem, PortConfig, Resolver, TimerParams,
};
use lldp_windows::npcap::NpcapBackend;
use lldp_windows::sysinfo::SystemInfo;
use tokio::sync::{Mutex, Notify, broadcast, mpsc, watch};

use crate::handler::IpcHandler;
use crate::sink::{Sink, SinkEvent};

/// SCM user control code that triggers a configuration reload.
pub const RELOAD_CONTROL_CODE: u32 = 128;

/// Resolver that can be swapped on reload.
#[derive(Clone)]
pub struct SharedResolver(pub Arc<RwLock<ConfigResolver>>);

impl SharedResolver {
    fn read(&self) -> ConfigResolver {
        self.0
            .read()
            .map_or_else(|p| p.into_inner().clone(), |r| r.clone())
    }

    /// Current chassis ID as text.
    pub fn chassis_id(&self) -> String {
        self.read().chassis_id().to_string()
    }
}

impl Resolver for SharedResolver {
    fn system(&self) -> LocalSystem {
        self.read().system()
    }
    fn decide(&self, iface: &InterfaceInfo) -> Decision {
        self.read().decide(iface)
    }
    fn timers(&self) -> TimerParams {
        self.read().timers()
    }
    fn port_config(&self, admin_status: lldp_core::AdminStatus) -> PortConfig {
        self.read().port_config(admin_status)
    }
}

/// Backend used when Npcap is not available: every open fails with a
/// clear error, so the service keeps running and reporting status.
struct UnavailableBackend(String);

impl PacketIo for UnavailableBackend {
    fn open(&self, _: &AdapterId) -> Result<Box<dyn PacketChannel>, PacketIoError> {
        Err(PacketIoError::BackendUnavailable(self.0.clone()))
    }
}

/// MsLldp binding control hooks. PowerShell runs on the blocking pool so
/// the agent is never stalled.
struct MsLldpHooks {
    enabled: bool,
    sink: mpsc::UnboundedSender<SinkEvent>,
    /// GUIDs of interfaces whose binding was just disabled. MsLldp sends a
    /// shutdown LLDPDU with the same chassis and port ID as ours when it is
    /// unbound, so the port must advertise again afterwards.
    readvertise: mpsc::UnboundedSender<String>,
    /// Binding changes still running, awaited at shutdown so the restore
    /// is logged before the service reports stopped.
    pending: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl MsLldpHooks {
    fn track(&self, task: tokio::task::JoinHandle<()>) {
        if let Ok(mut p) = self.pending.lock() {
            p.retain(|t| !t.is_finished());
            p.push(task);
        }
    }

    async fn drain(&self) {
        let tasks = self
            .pending
            .lock()
            .map_or_else(|_| Vec::new(), |mut p| std::mem::take(&mut *p));
        for t in tasks {
            let _ = t.await;
        }
    }
}

impl PortHooks for MsLldpHooks {
    fn tx_started(&self, iface: &InterfaceInfo) {
        if !self.enabled {
            return;
        }
        let guid = iface.guid.clone();
        let alias = iface.alias.clone();
        let sink = self.sink.clone();
        let readvertise = self.readvertise.clone();
        self.track(tokio::task::spawn_blocking(move || {
            let _ = sink.send(match lldp_windows::mslldp::disable_and_record(&guid) {
                Ok(()) => {
                    let _ = readvertise.send(guid);
                    SinkEvent::MsLldp {
                        alias,
                        enabled: false,
                        error: None,
                    }
                }
                Err(e) => SinkEvent::MsLldp {
                    alias,
                    enabled: false,
                    error: Some(e.to_string()),
                },
            });
        }));
    }

    fn tx_stopped(&self, iface: &InterfaceInfo) {
        if !self.enabled {
            return;
        }
        let guid = iface.guid.clone();
        let alias = iface.alias.clone();
        let sink = self.sink.clone();
        self.track(tokio::task::spawn_blocking(move || {
            let _ = sink.send(match lldp_windows::mslldp::restore(&guid) {
                Ok(()) => SinkEvent::MsLldp {
                    alias,
                    enabled: true,
                    error: None,
                },
                Err(e) => SinkEvent::MsLldp {
                    alias,
                    enabled: true,
                    error: Some(e.to_string()),
                },
            });
        }));
    }
}

/// Shared service state visible to the IPC handler.
pub struct ServiceState {
    /// The agent.
    pub agent: Mutex<Agent>,
    /// Policy resolver.
    pub resolver: SharedResolver,
    /// Startup instant.
    pub started: Instant,
    /// Npcap version, if loaded.
    pub npcap_version: Option<String>,
    /// Backend description.
    pub backend_status: String,
    /// Configuration path.
    pub config_path: PathBuf,
    /// Unix time of last successful configuration load.
    pub config_loaded_unix: std::sync::atomic::AtomicU64,
    /// Policy overrides were present at last load.
    pub policy_applied: std::sync::atomic::AtomicBool,
    /// Requests a reload (from IPC).
    pub reload: Arc<Notify>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn load_config(path: &std::path::Path) -> Result<(Config, bool), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut cfg = Config::from_yaml(&text).map_err(|e| e.to_string())?;
    let policy = lldp_windows::policy::read();
    let applied = policy != PolicyOverrides::default();
    cfg.apply_policy(&policy);
    cfg.validate().map_err(|e| e.to_string())?;
    Ok((cfg, applied))
}

fn facts_from(info: &SystemInfo, interfaces: &[InterfaceInfo]) -> SystemFacts {
    let os_name = if info.product_name.is_empty() {
        "Microsoft Windows".to_owned()
    } else {
        format!("Microsoft {}", info.product_name)
    };
    let mut os_version = String::new();
    if !info.display_version.is_empty() {
        os_version.push_str(&info.display_version);
    }
    if !info.build.is_empty() {
        if !os_version.is_empty() {
            os_version.push(' ');
        }
        os_version.push_str("(build ");
        os_version.push_str(&info.build);
        os_version.push(')');
    }
    if !os_version.is_empty() {
        os_version.push(' ');
    }
    os_version.push_str(info.architecture);
    let hardware = match (&info.manufacturer, &info.model) {
        (Some(m), Some(p)) => Some(format!("{} {}", m.trim(), p.trim())),
        (Some(m), None) => Some(m.trim().to_owned()),
        (None, Some(p)) => Some(p.trim().to_owned()),
        (None, None) => None,
    };
    let has_bridge = interfaces.iter().any(|i| {
        i.kind == InterfaceKind::Virtual
            && (i.description.contains("Hyper-V Virtual Ethernet")
                || i.description.contains("Network Bridge"))
    });
    SystemFacts {
        hostname: info.hostname.clone(),
        fqdn: if info.fqdn.is_empty() {
            info.hostname.clone()
        } else {
            info.fqdn.clone()
        },
        os_name,
        os_version: os_version.trim().to_owned(),
        hardware,
        smbios_uuid: info.smbios_uuid.clone(),
        has_bridge,
    }
}

/// Runs in the foreground until Ctrl+C.
pub fn run_console(config_path: PathBuf) -> Result<(), String> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reload = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });
    rt.block_on(run(config_path, shutdown_rx, reload, resume, true))
}

/// Runs under the SCM until `shutdown` becomes true.
pub fn run_service(
    config_path: PathBuf,
    shutdown: watch::Receiver<bool>,
    reload: Arc<Notify>,
    resume: Arc<Notify>,
) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(run(config_path, shutdown, reload, resume, false))
}

#[allow(clippy::too_many_lines)]
async fn run(
    config_path: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    reload: Arc<Notify>,
    resume: Arc<Notify>,
    console: bool,
) -> Result<(), String> {
    let (sink_tx, sink_rx) = mpsc::unbounded_channel::<SinkEvent>();
    let (agent_ev_tx, agent_ev_rx) = broadcast::channel::<AgentEvent>(1024);

    // Configuration first, so the event rate limit is known.
    let loaded = load_config(&config_path);
    let (config, policy_applied) = loaded.clone().unwrap_or_else(|_| {
        // A missing or invalid file must not stop the service, and must not
        // fall back to advertising defaults the file may have turned off.
        // Stay up with every interface disabled: `winlldp status` and
        // `diagnostics` work, and a reload picks up the corrected file.
        let mut cfg = Config::default();
        cfg.agent.enabled = false;
        (cfg, false)
    });
    let sink = Sink::new(
        console,
        config.logging.event_rate_limit_per_minute,
        sink_rx,
        agent_ev_rx,
    );
    tokio::spawn(sink.run());
    let _ = sink_tx.send(match &loaded {
        Ok(_) => SinkEvent::ConfigLoaded {
            path: config_path.display().to_string(),
            policy_applied,
        },
        Err(e) => SinkEvent::ConfigError(format!(
            "{e}; LLDP is disabled on every interface until the configuration is corrected and reloaded"
        )),
    });

    let sysinfo = SystemInfo::collect();
    let initial = lldp_windows::adapters::enumerate().unwrap_or_default();
    let facts = facts_from(&sysinfo, &initial);
    let resolver = SharedResolver(Arc::new(RwLock::new(ConfigResolver::new(
        config.clone(),
        facts,
    ))));

    let (backend, npcap_version, backend_status): (Arc<dyn PacketIo>, Option<String>, String) =
        match NpcapBackend::load() {
            Ok(b) => {
                let v = b.version().to_owned();
                let _ = sink_tx.send(SinkEvent::Npcap {
                    version: Some(v.clone()),
                    error: None,
                });
                (Arc::new(b), Some(v), "npcap".into())
            }
            Err(e) => {
                let _ = sink_tx.send(SinkEvent::Npcap {
                    version: None,
                    error: Some(e.to_string()),
                });
                (
                    Arc::new(UnavailableBackend(e.to_string())),
                    None,
                    format!("unavailable: {e}"),
                )
            }
        };

    let (readvertise_tx, mut readvertise_rx) = mpsc::unbounded_channel::<String>();
    let hooks = Arc::new(MsLldpHooks {
        enabled: config.windows.manage_mslldp_binding,
        sink: sink_tx.clone(),
        readvertise: readvertise_tx,
        pending: std::sync::Mutex::new(Vec::new()),
    });
    let agent = Agent::new(
        backend,
        Arc::new(resolver.clone()),
        Arc::clone(&hooks) as Arc<dyn PortHooks>,
        agent_ev_tx,
    );
    let state = Arc::new(ServiceState {
        agent: Mutex::new(agent),
        resolver: resolver.clone(),
        started: Instant::now(),
        npcap_version,
        backend_status,
        config_path: config_path.clone(),
        config_loaded_unix: std::sync::atomic::AtomicU64::new(if loaded.is_ok() {
            unix_now()
        } else {
            0
        }),
        policy_applied: std::sync::atomic::AtomicBool::new(policy_applied),
        reload: Arc::clone(&reload),
    });

    // Interface monitor.
    let (if_tx, mut if_rx) = mpsc::channel(64);
    let sub = lldp_windows::monitor::Subscription::subscribe().map_err(|e| e.to_string())?;
    let monitor_sink = sink_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = lldp_windows::monitor::run(sub, Duration::from_millis(500), if_tx).await {
            let _ = monitor_sink.send(SinkEvent::MonitorError(e.to_string()));
        }
    });

    // Suspend detection. Modern Standby (S0 low power idle) sends services
    // no resume power event, so also treat a wall-clock jump across a
    // short timer sleep as a resume.
    let resume_watch = Arc::clone(&resume);
    tokio::spawn(async move {
        loop {
            let before = SystemTime::now();
            tokio::time::sleep(Duration::from_secs(5)).await;
            if before.elapsed().is_ok_and(|d| d > Duration::from_secs(20)) {
                resume_watch.notify_one();
            }
        }
    });

    // IPC server.
    let ipc_stop = Arc::new(Notify::new());
    if config.ipc.enabled {
        let handler: Arc<dyn lldp_ipc::Handler> = Arc::new(IpcHandler {
            state: Arc::clone(&state),
        });
        let read_group = config.ipc.read_group.clone();
        let stop = Arc::clone(&ipc_stop);
        let ipc_sink = sink_tx.clone();
        tokio::spawn(async move {
            let _ = ipc_sink.send(SinkEvent::IpcStarted(lldp_ipc::PIPE_NAME.into()));
            if let Err(e) = lldp_windows::pipe::serve(
                lldp_ipc::PIPE_NAME,
                &read_group,
                handler,
                stop.notified(),
            )
            .await
            {
                let _ = ipc_sink.send(SinkEvent::IpcError(e.to_string()));
            }
        });
    }

    let _ = sink_tx.send(SinkEvent::Started {
        version: env!("CARGO_PKG_VERSION").into(),
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            () = reload.notified() => {
                match load_config(&config_path) {
                    Ok((cfg, applied)) => {
                        let sysinfo = SystemInfo::collect();
                        let ifaces: Vec<InterfaceInfo> = state.agent.lock().await.interfaces().cloned().collect();
                        let facts = facts_from(&sysinfo, &ifaces);
                        if let Ok(mut w) = resolver.0.write() {
                            *w = ConfigResolver::new(cfg, facts);
                        }
                        state.config_loaded_unix.store(unix_now(), std::sync::atomic::Ordering::Relaxed);
                        state.policy_applied.store(applied, std::sync::atomic::Ordering::Relaxed);
                        state.agent.lock().await.reload().await;
                        let _ = sink_tx.send(SinkEvent::ConfigLoaded { path: config_path.display().to_string(), policy_applied: applied });
                    }
                    Err(e) => {
                        let _ = sink_tx.send(SinkEvent::ConfigError(e));
                    }
                }
            }
            () = resume.notified() => {
                // The neighbor has aged us out during sleep: start a fast
                // period on every port; link and address changes arrive
                // through the monitor.
                state.agent.lock().await.readvertise(None).await;
            }
            Some(guid) = readvertise_rx.recv() => {
                state.agent.lock().await.readvertise(Some(&guid)).await;
            }
            change = if_rx.recv() => {
                match change {
                    Some(c) => state.agent.lock().await.handle(c).await,
                    None => {
                        let _ = sink_tx.send(SinkEvent::MonitorError("interface monitor stopped".into()));
                    }
                }
            }
        }
    }

    ipc_stop.notify_waiters();
    state.agent.lock().await.shutdown().await;
    hooks.drain().await;
    let _ = sink_tx.send(SinkEvent::Stopped);
    tokio::time::sleep(Duration::from_millis(200)).await; // let the sink flush
    Ok(())
}
