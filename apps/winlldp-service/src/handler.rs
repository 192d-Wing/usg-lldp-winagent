//! IPC request handling.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lldp_codec::ethernet::write_lldp_frame;
use lldp_core::{AdminStatus, InterfaceInfo, InterfaceKind, Resolver as _};
use lldp_ipc::{
    Caller, ErrorCode, Handler, HandlerFuture, InterfaceModeView, InterfaceView, IpcError,
    LldpduView, LocalAdvertisementView, NeighborView, Request, ServiceStatusView, StatisticsView,
};
use serde_json::{Value, json};

use crate::app::ServiceState;

/// Serves requests from the shared state.
pub struct IpcHandler {
    /// Service state.
    pub state: Arc<ServiceState>,
}

fn kind_name(k: InterfaceKind) -> &'static str {
    match k {
        InterfaceKind::PhysicalEthernet => "physical_ethernet",
        InterfaceKind::Wifi => "wifi",
        InterfaceKind::Virtual => "virtual",
        InterfaceKind::Other => "other",
    }
}

fn matches(iface: &InterfaceInfo, name: &str) -> bool {
    let n = name.trim();
    iface.alias.eq_ignore_ascii_case(n)
        || iface
            .guid
            .trim_matches(|c| c == '{' || c == '}')
            .eq_ignore_ascii_case(n.trim_matches(|c| c == '{' || c == '}'))
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<Value, IpcError> {
    serde_json::to_value(v).map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
}

impl IpcHandler {
    async fn interfaces(&self, filter: Option<&str>) -> Result<Vec<InterfaceInfo>, IpcError> {
        let agent = self.state.agent.lock().await;
        let all: Vec<InterfaceInfo> = agent.interfaces().cloned().collect();
        match filter {
            None => Ok(all),
            Some(f) => {
                let found: Vec<InterfaceInfo> = all.into_iter().filter(|i| matches(i, f)).collect();
                if found.is_empty() {
                    Err(IpcError::new(
                        ErrorCode::InterfaceNotFound,
                        format!("no interface named '{f}'"),
                    ))
                } else {
                    Ok(found)
                }
            }
        }
    }

    async fn interface_views(&self, filter: Option<&str>) -> Result<Vec<InterfaceView>, IpcError> {
        let ifaces = self.interfaces(filter).await?;
        let agent = self.state.agent.lock().await;
        let mut out = Vec::new();
        for i in ifaces {
            let snap = agent.snapshot(&i.guid).await;
            let mode = agent.admin_status(&i.guid);
            out.push(InterfaceView {
                guid: i.guid.clone(),
                alias: i.alias.clone(),
                description: i.description.clone(),
                mac: i.mac.map(|m| m.to_string()),
                if_index: i.if_index,
                kind: kind_name(i.kind).into(),
                connected: i.connected,
                link_speed: i.link_speed,
                mode: InterfaceModeView::from(mode),
                managed: snap.is_some(),
                neighbors: snap.as_ref().map_or(0, |s| s.neighbors.len()),
                too_many_neighbors: snap.as_ref().is_some_and(|s| s.too_many_neighbors),
                addresses: i.addresses.iter().map(|a| a.addr.to_string()).collect(),
            });
        }
        Ok(out)
    }

    async fn neighbors(&self, filter: Option<&str>) -> Result<Vec<NeighborView>, IpcError> {
        let ifaces = self.interfaces(filter).await?;
        let agent = self.state.agent.lock().await;
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut out = Vec::new();
        for i in ifaces {
            if let Some(snap) = agent.snapshot(&i.guid).await {
                for n in &snap.neighbors {
                    out.push(NeighborView::from_neighbor(
                        &i.guid, &i.alias, n, now, now_unix,
                    ));
                }
            }
        }
        Ok(out)
    }

    async fn status(&self) -> Result<ServiceStatusView, IpcError> {
        let agent = self.state.agent.lock().await;
        let known = agent.interfaces().count();
        let snaps = agent.snapshot_all().await;
        let neighbors_total = snaps.values().map(|s| s.neighbors.len()).sum();
        let system = self.state.resolver.system();
        Ok(ServiceStatusView {
            version: env!("CARGO_PKG_VERSION").into(),
            uptime_secs: self.state.started.elapsed().as_secs(),
            npcap_version: self.state.npcap_version.clone(),
            backend_status: self.state.backend_status.clone(),
            config_path: self.state.config_path.display().to_string(),
            config_loaded_unix: self
                .state
                .config_loaded_unix
                .load(std::sync::atomic::Ordering::Relaxed),
            policy_applied: self
                .state
                .policy_applied
                .load(std::sync::atomic::Ordering::Relaxed),
            interfaces_known: known,
            interfaces_managed: snaps.len(),
            neighbors_total,
            system_name: system
                .system_name
                .as_deref()
                .map(lldp_codec::types::lossy_text)
                .unwrap_or_default(),
            chassis_id: self.state.resolver.chassis_id(),
        })
    }

    async fn local(&self, filter: Option<&str>) -> Result<Vec<LocalAdvertisementView>, IpcError> {
        let ifaces = self.interfaces(filter).await?;
        let agent = self.state.agent.lock().await;
        let mut out = Vec::new();
        for i in ifaces {
            let Some(snap) = agent.snapshot(&i.guid).await else {
                continue;
            };
            let bytes = snap.local_lldpdu.encode(1500).unwrap_or_default();
            let mut frame = Vec::new();
            write_lldp_frame(
                &mut frame,
                lldp_codec::LldpDestination::NearestBridge,
                snap.mac,
                &bytes,
            );
            out.push(LocalAdvertisementView {
                interface_guid: i.guid.clone(),
                interface_alias: i.alias.clone(),
                mode: InterfaceModeView::from(snap.admin_status),
                destination_mac: lldp_codec::LldpDestination::NearestBridge.mac().to_string(),
                source_mac: snap.mac.to_string(),
                lldpdu: LldpduView::from_lldpdu(&snap.local_lldpdu),
                lldpdu_hex: lldp_ipc::hex(&bytes),
            });
        }
        Ok(out)
    }

    async fn statistics(&self, filter: Option<&str>) -> Result<Vec<StatisticsView>, IpcError> {
        let ifaces = self.interfaces(filter).await?;
        let agent = self.state.agent.lock().await;
        let mut out = Vec::new();
        for i in ifaces {
            if let Some(snap) = agent.snapshot(&i.guid).await {
                out.push(StatisticsView::from_stats(&i.guid, &i.alias, &snap.stats));
            }
        }
        Ok(out)
    }

    async fn handle_inner(&self, request: Request) -> Result<Value, IpcError> {
        match request {
            Request::GetServiceStatus => to_json(&self.status().await?),
            Request::ListInterfaces => to_json(&self.interface_views(None).await?),
            Request::GetInterfaceStatus { interface } => {
                let v = self.interface_views(Some(&interface)).await?;
                to_json(&v.into_iter().next())
            }
            Request::ListNeighbors { interface } => {
                to_json(&self.neighbors(interface.as_deref()).await?)
            }
            Request::GetNeighborDetails {
                interface,
                chassis_id,
                port_id,
            } => {
                let all = self.neighbors(Some(&interface)).await?;
                let found = all.into_iter().find(|n| {
                    n.lldpdu.chassis_id.value == chassis_id && n.lldpdu.port_id.value == port_id
                });
                found.map_or_else(
                    || {
                        Err(IpcError::new(
                            ErrorCode::NeighborNotFound,
                            format!("no neighbor {chassis_id}/{port_id} on {interface}"),
                        ))
                    },
                    |n| to_json(&n),
                )
            }
            Request::GetLocalAdvertisement { interface } => {
                to_json(&self.local(interface.as_deref()).await?)
            }
            Request::GetStatistics { interface } => {
                to_json(&self.statistics(interface.as_deref()).await?)
            }
            Request::SetInterfaceMode { interface, mode } => {
                let ifaces = self.interfaces(Some(&interface)).await?;
                let mut agent = self.state.agent.lock().await;
                let mut changed = Vec::new();
                for i in ifaces {
                    if agent
                        .set_admin_status(&i.guid, AdminStatus::from(mode))
                        .await
                    {
                        changed.push(i.alias.clone());
                    }
                }
                Ok(json!({"changed": changed, "mode": mode}))
            }
            Request::ReloadConfiguration => {
                self.state.reload.notify_one();
                Ok(json!({"requested": true}))
            }
        }
    }
}

impl Handler for IpcHandler {
    fn handle(&self, request: Request, _caller: Caller) -> HandlerFuture<'_> {
        Box::pin(self.handle_inner(request))
    }
}
